package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const resourceServerFinalizerName = "hanko.sh/resource-server-cleanup"

// AuthorizationDriverFactory selects the provider adapter for one namespaced object.
type AuthorizationDriverFactory func(namespace string, labels map[string]string) authorization.Driver

// HankoResourceServerReconciler reconciles the complete protected API aggregate.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoresourceservers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoresourceservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoresourceservers/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms;hankoapplications;hankoroles;hankoserviceaccounts,verbs=get;list;watch
type HankoResourceServerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Pool          *keycloak.Pool
	DriverFactory AuthorizationDriverFactory
	Recorder      events.EventRecorder
}

func (r *HankoResourceServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var resourceServer hankoshv1alpha1.HankoResourceServer
	if err := r.Get(ctx, req.NamespacedName, &resourceServer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	driver := r.driverFor(&resourceServer)
	mode := resourceServer.Spec.Mode
	if mode == "" {
		mode = ModeManage
	}

	if !resourceServer.DeletionTimestamp.IsZero() {
		return r.reconcileResourceServerDeletion(ctx, &resourceServer, driver, mode)
	}
	return r.reconcileActiveResourceServer(ctx, &resourceServer, driver, mode)
}

func (r *HankoResourceServerReconciler) reconcileActiveResourceServer(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, mode string) (ctrl.Result, error) {
	if mode != ModeManage && mode != ModeObserve {
		return ctrl.Result{}, r.statusError(ctx, resourceServer, "UnsupportedMode", fmt.Errorf("unsupported mode %q", mode))
	}
	if isImported(resourceServer.Labels) {
		mode = ModeObserve
	}
	if mode == ModeObserve && controllerutil.ContainsFinalizer(resourceServer, resourceServerFinalizerName) {
		controllerutil.RemoveFinalizer(resourceServer, resourceServerFinalizerName)
		if err := r.Update(ctx, resourceServer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	model, err := r.resolveAuthorizationModel(ctx, resourceServer)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "InvalidReferences", err)
	}
	capabilities, err := driver.Capabilities(ctx, model.Realm)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "CapabilityLookupFailed", err)
	}
	if err := authorization.ValidateCapabilities(model, capabilities); err != nil {
		return ctrl.Result{}, r.statusCapabilityError(ctx, resourceServer, capabilities, err)
	}
	if mode == ModeObserve {
		return r.observeResourceServer(ctx, resourceServer, driver, model)
	}
	return r.manageResourceServer(ctx, resourceServer, driver, model)
}

func (r *HankoResourceServerReconciler) reconcileResourceServerDeletion(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, mode string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(resourceServer, resourceServerFinalizerName) {
		return ctrl.Result{}, nil
	}
	// Empty ownership proves that no provider object is a safe deletion target.
	if mode == ModeObserve || isImported(resourceServer.Labels) || resourceServer.Status.ProviderResourceServerID == "" {
		controllerutil.RemoveFinalizer(resourceServer, resourceServerFinalizerName)
		return ctrl.Result{}, r.Update(ctx, resourceServer)
	}
	model := authorization.Model{Name: resourceServer.Name, Realm: resourceServer.Spec.RealmRef}
	if err := driver.DeleteOwned(ctx, model, managedObjectsFromStatus(resourceServer.Status)); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "CleanupFailed", err)
	}
	controllerutil.RemoveFinalizer(resourceServer, resourceServerFinalizerName)
	if err := r.Update(ctx, resourceServer); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove resource-server finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *HankoResourceServerReconciler) observeResourceServer(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, model authorization.Model) (ctrl.Result, error) {
	state, err := driver.Observe(ctx, model)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "ObserveFailed", err)
	}
	return r.statusSuccess(ctx, resourceServer, state, "Observed", "provider authorization state observed without mutation")
}

func (r *HankoResourceServerReconciler) manageResourceServer(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, model authorization.Model) (ctrl.Result, error) {
	// Persist the cleanup boundary only after every reference and capability
	// check has succeeded, and immediately before the first provider mutation.
	if !controllerutil.ContainsFinalizer(resourceServer, resourceServerFinalizerName) {
		controllerutil.AddFinalizer(resourceServer, resourceServerFinalizerName)
		if err := r.Update(ctx, resourceServer); err != nil {
			return ctrl.Result{}, fmt.Errorf("add resource-server finalizer: %w", err)
		}
	}
	state, err := driver.Reconcile(ctx, model, managedObjectsFromStatus(resourceServer.Status))
	if err != nil {
		reason := "ReconcileFailed"
		if errors.Is(err, authorization.ErrOwnershipConflict) {
			reason = "OwnershipConflict"
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, reason, err)
	}
	return r.statusSuccess(ctx, resourceServer, state, "Reconciled", "authorization graph matches portable desired state")
}

func (r *HankoResourceServerReconciler) driverFor(resourceServer *hankoshv1alpha1.HankoResourceServer) authorization.Driver {
	if r.DriverFactory != nil {
		return r.DriverFactory(resourceServer.Namespace, resourceServer.Labels)
	}
	return authorization.NewKeycloakDriver(kcForObject(r.Pool, resourceServer.Namespace, resourceServer.Labels))
}

func (r *HankoResourceServerReconciler) resolveAuthorizationModel(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer) (authorization.Model, error) {
	if err := validatePortableAuthorizationSpec(resourceServer.Spec); err != nil {
		return authorization.Model{}, err
	}
	var realm hankoshv1alpha1.HankoRealm
	if err := r.Get(ctx, types.NamespacedName{Name: resourceServer.Spec.RealmRef, Namespace: resourceServer.Namespace}, &realm); err != nil {
		return authorization.Model{}, fmt.Errorf("realm %q: %w", resourceServer.Spec.RealmRef, err)
	}
	if isImported(realm.Labels) && resourceServer.Spec.Mode != ModeObserve && !isImported(resourceServer.Labels) {
		return authorization.Model{}, fmt.Errorf("realm %q is read-only; resource server must use Observe", resourceServer.Spec.RealmRef)
	}

	application, err := r.applicationInRealm(ctx, resourceServer.Namespace, resourceServer.Spec.ApplicationRef, resourceServer.Spec.RealmRef)
	if err != nil {
		return authorization.Model{}, err
	}
	model := authorization.Model{
		Name: resourceServer.Name, Realm: resourceServer.Spec.RealmRef,
		Audience: resourceServer.Spec.Audience, DisplayName: resourceServer.Spec.DisplayName,
		ApplicationRef: application.Spec.ClientID,
	}
	for _, scope := range resourceServer.Spec.Scopes {
		model.Scopes = append(model.Scopes, authorization.Scope{Name: scope.Name, Description: scope.Description})
	}
	for _, resource := range resourceServer.Spec.Resources {
		model.Resources = append(model.Resources, authorization.Resource{
			Name: resource.Name, DisplayName: resource.DisplayName, URIs: resource.URIs, Type: resource.Type, Scopes: resource.Scopes,
		})
	}
	for _, permission := range resourceServer.Spec.Permissions {
		converted, err := r.resolveAuthorizationPermission(ctx, resourceServer, &realm, permission)
		if err != nil {
			return authorization.Model{}, err
		}
		model.Permissions = append(model.Permissions, converted)
	}
	return model, nil
}

func (r *HankoResourceServerReconciler) resolveAuthorizationPermission(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, realm *hankoshv1alpha1.HankoRealm, permission hankoshv1alpha1.AuthorizationPermission) (authorization.Permission, error) {
	converted := authorization.Permission{Name: permission.Name, Resources: permission.Resources, Scopes: permission.Scopes}
	for _, principal := range permission.Principals {
		resolved, err := r.resolveAuthorizationPrincipal(ctx, resourceServer, realm, principal)
		if err != nil {
			return authorization.Permission{}, fmt.Errorf("permission %q principal %q: %w", permission.Name, principal.Ref, err)
		}
		converted.Principals = append(converted.Principals, resolved)
	}
	return converted, nil
}

func (r *HankoResourceServerReconciler) resolveAuthorizationPrincipal(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, realm *hankoshv1alpha1.HankoRealm, principal hankoshv1alpha1.AuthorizationPrincipal) (authorization.Principal, error) {
	resolvedRef := principal.Ref
	switch principal.Kind {
	case "realm_role":
		roleName, err := r.roleInRealm(ctx, resourceServer.Namespace, principal.Ref, resourceServer.Spec.RealmRef, realm)
		if err != nil {
			return authorization.Principal{}, err
		}
		resolvedRef = roleName
	case "application":
		application, err := r.applicationInRealm(ctx, resourceServer.Namespace, principal.Ref, resourceServer.Spec.RealmRef)
		if err != nil {
			return authorization.Principal{}, err
		}
		resolvedRef = application.Spec.ClientID
	case "service_account":
		var account hankoshv1alpha1.HankoServiceAccount
		if err := r.Get(ctx, types.NamespacedName{Name: principal.Ref, Namespace: resourceServer.Namespace}, &account); err != nil {
			return authorization.Principal{}, fmt.Errorf("service account %q: %w", principal.Ref, err)
		}
		if account.Spec.RealmRef != resourceServer.Spec.RealmRef {
			return authorization.Principal{}, fmt.Errorf("service account %q belongs to realm %q", principal.Ref, account.Spec.RealmRef)
		}
		resolvedRef = account.Spec.ClientID
	}
	return authorization.Principal{Kind: principal.Kind, Ref: resolvedRef}, nil
}

func (r *HankoResourceServerReconciler) applicationInRealm(ctx context.Context, namespace, name, realm string) (*hankoshv1alpha1.HankoApplication, error) {
	var application hankoshv1alpha1.HankoApplication
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &application); err != nil {
		return nil, fmt.Errorf("application %q: %w", name, err)
	}
	if application.Spec.RealmRef != realm {
		return nil, fmt.Errorf("application %q belongs to realm %q", name, application.Spec.RealmRef)
	}
	return &application, nil
}

func (r *HankoResourceServerReconciler) roleInRealm(ctx context.Context, namespace, name, realm string, realmObject *hankoshv1alpha1.HankoRealm) (string, error) {
	if slices.ContainsFunc(realmObject.Spec.Roles, func(role hankoshv1alpha1.RealmRole) bool { return role.Name == name }) {
		return name, nil
	}
	var role hankoshv1alpha1.HankoRole
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &role); err != nil {
		return "", fmt.Errorf("realm role %q: %w", name, err)
	}
	if role.Spec.RealmRef != realm {
		return "", fmt.Errorf("realm role %q belongs to realm %q", name, role.Spec.RealmRef)
	}
	return role.Spec.Name, nil
}

func validatePortableAuthorizationSpec(spec hankoshv1alpha1.HankoResourceServerSpec) error {
	if spec.Mode != "" && spec.Mode != ModeManage && spec.Mode != ModeObserve {
		return fmt.Errorf("unsupported mode %q", spec.Mode)
	}
	if strings.TrimSpace(spec.RealmRef) == "" || strings.TrimSpace(spec.Audience) == "" || strings.TrimSpace(spec.ApplicationRef) == "" {
		return errors.New("realmRef, audience and applicationRef are required")
	}
	scopes, err := validateAuthorizationScopes(spec.Scopes)
	if err != nil {
		return err
	}
	resources, err := validateAuthorizationResources(spec.Resources, scopes)
	if err != nil {
		return err
	}
	return validateAuthorizationPermissions(spec.Permissions, scopes, resources)
}

func validateAuthorizationScopes(scopes []hankoshv1alpha1.AuthorizationScope) (map[string]bool, error) {
	result := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope.Name == "" || result[scope.Name] {
			return nil, fmt.Errorf("duplicate or empty scope name %q", scope.Name)
		}
		result[scope.Name] = true
	}
	return result, nil
}

func validateAuthorizationResources(resources []hankoshv1alpha1.AuthorizationResource, scopes map[string]bool) (map[string]bool, error) {
	result := make(map[string]bool, len(resources))
	for _, resource := range resources {
		if resource.Name == "" || result[resource.Name] {
			return nil, fmt.Errorf("duplicate or empty resource name %q", resource.Name)
		}
		result[resource.Name] = true
		for _, scope := range resource.Scopes {
			if !scopes[scope] {
				return nil, fmt.Errorf("resource %q references unknown scope %q", resource.Name, scope)
			}
		}
	}
	return result, nil
}

func validateAuthorizationPermissions(desired []hankoshv1alpha1.AuthorizationPermission, scopes, resources map[string]bool) error {
	permissions := make(map[string]bool, len(desired))
	for _, permission := range desired {
		if err := validateAuthorizationPermission(permission, permissions, scopes, resources); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthorizationPermission(permission hankoshv1alpha1.AuthorizationPermission, permissions, scopes, resources map[string]bool) error {
	if permission.Name == "" || permissions[permission.Name] {
		return fmt.Errorf("duplicate or empty permission name %q", permission.Name)
	}
	permissions[permission.Name] = true
	if len(permission.Scopes) == 0 || len(permission.Principals) == 0 {
		return fmt.Errorf("permission %q requires at least one scope and principal", permission.Name)
	}
	if err := validateAuthorizationReferences(permission.Name, "scope", permission.Scopes, scopes); err != nil {
		return err
	}
	if err := validateAuthorizationReferences(permission.Name, "resource", permission.Resources, resources); err != nil {
		return err
	}
	return validateAuthorizationPrincipals(permission)
}

func validateAuthorizationReferences(permissionName, referenceType string, references []string, known map[string]bool) error {
	for _, reference := range references {
		if !known[reference] {
			return fmt.Errorf("permission %q references unknown %s %q", permissionName, referenceType, reference)
		}
	}
	return nil
}

func validateAuthorizationPrincipals(permission hankoshv1alpha1.AuthorizationPermission) error {
	principalKeys := make(map[string]bool, len(permission.Principals))
	for _, principal := range permission.Principals {
		key := principal.Kind + "\x00" + principal.Ref
		if principalKeys[key] {
			return fmt.Errorf("permission %q contains duplicate principal %s/%s", permission.Name, principal.Kind, principal.Ref)
		}
		principalKeys[key] = true
		if principal.Kind != "realm_role" && principal.Kind != "application" && principal.Kind != "service_account" {
			return fmt.Errorf("permission %q has unsupported principal kind %q", permission.Name, principal.Kind)
		}
	}
	return nil
}

func (r *HankoResourceServerReconciler) statusError(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, reason string, reconcileErr error) error {
	patch := client.MergeFrom(resourceServer.DeepCopy())
	resourceServer.Status.Phase = "Error"
	resourceServer.Status.ObservedGeneration = resourceServer.Generation
	setCondition(&resourceServer.Status.Conditions, "DriftFree", metav1.ConditionFalse, reason, reconcileErr.Error())
	setCondition(&resourceServer.Status.Conditions, "Synced", metav1.ConditionFalse, reason, reconcileErr.Error())
	if patchErr := r.Status().Patch(ctx, resourceServer, patch); patchErr != nil {
		return errors.Join(reconcileErr, patchErr)
	}
	return reconcileErr
}

func (r *HankoResourceServerReconciler) statusCapabilityError(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, capabilities authorization.Capabilities, reconcileErr error) error {
	patch := client.MergeFrom(resourceServer.DeepCopy())
	resourceServer.Status.Phase = "Error"
	resourceServer.Status.ObservedGeneration = resourceServer.Generation
	resourceServer.Status.Capabilities = capabilityStatus(capabilities)
	resourceServer.Status.Findings = []hankoshv1alpha1.AuthorizationFinding{{
		Classification: "unsupported", ObjectKind: "resource_server", ObjectName: resourceServer.Name,
		Code: "unsupported_capability", Message: reconcileErr.Error(),
	}}
	setCondition(&resourceServer.Status.Conditions, "CapabilitiesSatisfied", metav1.ConditionFalse, "UnsupportedCapability", reconcileErr.Error())
	setCondition(&resourceServer.Status.Conditions, "DriftFree", metav1.ConditionFalse, "UnsupportedCapability", reconcileErr.Error())
	setCondition(&resourceServer.Status.Conditions, "Synced", metav1.ConditionFalse, "UnsupportedCapability", reconcileErr.Error())
	if err := r.Status().Patch(ctx, resourceServer, patch); err != nil {
		return errors.Join(reconcileErr, err)
	}
	return reconcileErr
}

func (r *HankoResourceServerReconciler) statusSuccess(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, state authorization.State, reason, message string) (ctrl.Result, error) {
	patch := client.MergeFrom(resourceServer.DeepCopy())
	now := metav1.Now()
	resourceServer.Status.Phase = "Ready"
	resourceServer.Status.ObservedGeneration = resourceServer.Generation
	resourceServer.Status.AppliedPlanHash = resourceServer.Annotations["hanko.sh/authorization-plan-hash"]
	resourceServer.Status.BackendKind = "keycloak"
	resourceServer.Status.ProviderResourceServerID = state.ProviderResourceServerID
	resourceServer.Status.Capabilities = capabilityStatus(state.Capabilities)
	resourceServer.Status.Findings = findingsStatus(state.Findings)
	if reason == "Reconciled" {
		resourceServer.Status.ManagedObjects = managedObjectsStatus(state.ManagedObjects)
	}
	resourceServer.Status.LastReconciled = &now
	setCondition(&resourceServer.Status.Conditions, "CapabilitiesSatisfied", metav1.ConditionTrue, "Supported", "provider supports every requested authorization semantic")
	setCondition(&resourceServer.Status.Conditions, "DriftFree", metav1.ConditionTrue, reason, message)
	setCondition(&resourceServer.Status.Conditions, "Synced", metav1.ConditionTrue, reason, message)
	if err := r.Status().Patch(ctx, resourceServer, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoResourceServer synced", "name", resourceServer.Name, "realm", resourceServer.Spec.RealmRef, "mode", resourceServer.Spec.Mode)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func managedObjectsFromStatus(status hankoshv1alpha1.HankoResourceServerStatus) authorization.ManagedObjects {
	return authorization.ManagedObjects{
		ResourceServerID: status.ProviderResourceServerID,
		Scopes:           managedRefsFromStatus(status.ManagedObjects.Scopes),
		Resources:        managedRefsFromStatus(status.ManagedObjects.Resources),
		Policies:         managedRefsFromStatus(status.ManagedObjects.Policies),
		Permissions:      managedRefsFromStatus(status.ManagedObjects.Permissions),
	}
}

func managedObjectsStatus(objects authorization.ManagedObjects) hankoshv1alpha1.AuthorizationManagedObjects {
	return hankoshv1alpha1.AuthorizationManagedObjects{
		Scopes: managedRefsStatus(objects.Scopes), Resources: managedRefsStatus(objects.Resources),
		Policies: managedRefsStatus(objects.Policies), Permissions: managedRefsStatus(objects.Permissions),
	}
}

func managedRefsFromStatus(refs []hankoshv1alpha1.AuthorizationManagedReference) []authorization.ManagedReference {
	result := make([]authorization.ManagedReference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, authorization.ManagedReference{Name: ref.Name, ID: ref.ID})
	}
	return result
}

func managedRefsStatus(refs []authorization.ManagedReference) []hankoshv1alpha1.AuthorizationManagedReference {
	result := make([]hankoshv1alpha1.AuthorizationManagedReference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, hankoshv1alpha1.AuthorizationManagedReference{Name: ref.Name, ID: ref.ID})
	}
	return result
}

func capabilityStatus(value authorization.Capabilities) hankoshv1alpha1.AuthorizationCapabilitySnapshot {
	return hankoshv1alpha1.AuthorizationCapabilitySnapshot{
		ScopeGrants: value.ScopeGrants, RolePrincipals: value.RolePrincipals,
		ApplicationPrincipals: value.ApplicationPrincipals, ServiceAccountPrincipals: value.ServiceAccountPrincipals,
		ResourceObjects: value.ResourceObjects, ResourceURIMatching: value.ResourceURIMatching,
		UMARPT: value.UMARPT, NativePermissionClaim: value.NativePermissionClaim,
	}
}

func findingsStatus(findings []authorization.Finding) []hankoshv1alpha1.AuthorizationFinding {
	result := make([]hankoshv1alpha1.AuthorizationFinding, 0, len(findings))
	for _, finding := range findings {
		result = append(result, hankoshv1alpha1.AuthorizationFinding{
			Classification: finding.Classification, ObjectKind: finding.ObjectKind, ObjectName: finding.ObjectName,
			Code: finding.Code, Message: finding.Message, ReadOnly: finding.ReadOnly,
		})
	}
	return result
}

func (r *HankoResourceServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoResourceServer{}).
		Complete(r)
}
