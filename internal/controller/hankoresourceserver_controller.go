package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
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
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms;hankoapplications;hankoroles;hankoserviceaccounts;hankoorganizations,verbs=get;list;watch
type HankoResourceServerReconciler struct {
	client.Client
	APIReader            client.Reader
	organizationResolver *organizationGrantResolver
	Scheme               *runtime.Scheme
	Pool                 *keycloak.Pool
	DriverFactory        AuthorizationDriverFactory
	Recorder             events.EventRecorder
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
	plan, err := r.compileAuthorizationPlan(ctx, resourceServer, driver, mode)
	if err != nil {
		if errors.Is(err, authorization.ErrCapabilityUnsupported) {
			caps, _ := driver.Capabilities(ctx, resourceServer.Spec.RealmRef)
			return ctrl.Result{}, r.statusCapabilityError(ctx, resourceServer, caps, err)
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "PlanRejected", err)
	}
	if mode == ModeObserve {
		return r.observeResourceServer(ctx, resourceServer, driver, plan)
	}
	return r.manageResourceServer(ctx, resourceServer, driver, plan)
}

func authorizationIntent(resourceServer *hankoshv1alpha1.HankoResourceServer) authorization.Intent {
	s := resourceServer.Spec
	model := authorization.Model{Name: resourceServer.Name, Realm: s.RealmRef, Audience: s.Audience, DisplayName: s.DisplayName, ApplicationRef: s.ApplicationRef}
	for _, v := range s.Scopes {
		model.Scopes = append(model.Scopes, authorization.Scope{Name: v.Name, Description: v.Description})
	}
	for _, v := range s.Resources {
		model.Resources = append(model.Resources, authorization.Resource{Name: v.Name, DisplayName: v.DisplayName, URIs: v.URIs, Type: v.Type, Scopes: v.Scopes})
	}
	for _, v := range s.Permissions {
		p := authorization.Permission{Name: v.Name, Resources: v.Resources, Scopes: v.Scopes}
		for _, principal := range v.Principals {
			p.Principals = append(p.Principals, authorization.Principal{Kind: principal.Kind, Ref: principal.Ref, IncludeDescendants: principal.IncludeDescendants})
		}
		model.Permissions = append(model.Permissions, p)
	}
	return authorization.Normalize(model)
}
func (r *HankoResourceServerReconciler) compileAuthorizationPlan(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, mode string) (authorization.Plan, error) {
	reader := &contractReferenceReader{Client: r.Client, Reader: r.authorityReader()}
	resolver := *r
	resolver.Client = reader
	if groupReader, ok := driver.(authorization.OrganizationGroupReader); ok {
		resolver.organizationResolver = &organizationGrantResolver{reader: r.authorityReader(), provider: groupReader, namespace: obj.Namespace, realm: obj.Spec.RealmRef}
	}
	model, err := resolver.resolveAuthorizationModel(ctx, obj)
	if err != nil {
		return authorization.Plan{}, err
	}
	intent := authorizationIntent(obj)
	resolved, err := authorization.Resolve(intent, model)
	if err != nil {
		return authorization.Plan{}, err
	}
	caps, err := driver.Capabilities(ctx, model.Realm)
	if err != nil {
		return authorization.Plan{}, iamcontract.SafeError(err)
	}
	pre := executionPreconditions(obj, reader.digest(), mode)
	owned, _ := json.Marshal(managedObjectsFromStatus(obj.Status))
	pre.Ownership = iamcontract.Hash(iamcontract.Version, "authorization", "ownership", owned)
	plan, err := authorization.Compile(intent, resolved, authorization.KeycloakEvidence(caps), pre)
	if err != nil {
		return plan, iamEvaluationRejected{cause: err, identity: iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: intent.Identity()}, authorizationCaps: caps}
	}
	return plan, nil
}
func (r *HankoResourceServerReconciler) validateAuthorizationExecution(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, plan authorization.Plan) error {
	var current hankoshv1alpha1.HankoResourceServer
	if err := r.authorityReader().Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
		return err
	}
	mode := current.Spec.Mode
	if mode == "" {
		mode = ModeManage
	}
	if isImported(current.Labels) {
		mode = ModeObserve
	}
	if !current.DeletionTimestamp.IsZero() {
		return iamcontract.ErrStale
	}
	next, err := r.compileAuthorizationPlan(ctx, &current, driver, mode)
	if err != nil {
		return err
	}
	return plan.Validate(next)
}

func (r *HankoResourceServerReconciler) reconcileResourceServerDeletion(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, mode string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(resourceServer, resourceServerFinalizerName) {
		return ctrl.Result{}, nil
	}
	// Empty ownership proves that no provider object is a safe deletion target.
	if mode == ModeObserve || isImported(resourceServer.Labels) {
		controllerutil.RemoveFinalizer(resourceServer, resourceServerFinalizerName)
		return ctrl.Result{}, r.Update(ctx, resourceServer)
	}
	model := authorization.Model{Name: resourceServer.Name, Realm: resourceServer.Spec.RealmRef}
	if resourceServer.Status.ProviderResourceServerID == "" {
		application, err := r.applicationInRealm(ctx, resourceServer.Namespace, resourceServer.Spec.ApplicationRef, resourceServer.Spec.RealmRef)
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "CleanupFailed", err)
		}
		model.ApplicationRef = application.Spec.ClientID
	}
	if err := driver.DeleteOwned(ctx, model, managedObjectsFromStatus(resourceServer.Status), string(resourceServer.UID)); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, resourceServer, "CleanupFailed", err)
	}
	controllerutil.RemoveFinalizer(resourceServer, resourceServerFinalizerName)
	if err := r.Update(ctx, resourceServer); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove resource-server finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *HankoResourceServerReconciler) observeResourceServer(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, plan authorization.Plan) (ctrl.Result, error) {
	if err := r.validateAuthorizationExecution(ctx, resourceServer, driver, plan); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, "StalePlan", err, nil)
	}
	state, err := driver.Observe(ctx, plan)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, "ObserveFailed", err, nil)
	}
	if err := r.validateAuthorizationExecution(ctx, resourceServer, driver, plan); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, "StalePlan", err, nil)
	}
	return r.statusObservation(ctx, resourceServer, state, plan, true)
}

func (r *HankoResourceServerReconciler) manageResourceServer(ctx context.Context, resourceServer *hankoshv1alpha1.HankoResourceServer, driver authorization.Driver, plan authorization.Plan) (ctrl.Result, error) {
	// Persist the cleanup boundary only after every reference and capability
	// check has succeeded, and immediately before the first provider mutation.
	if !controllerutil.ContainsFinalizer(resourceServer, resourceServerFinalizerName) {
		controllerutil.AddFinalizer(resourceServer, resourceServerFinalizerName)
		if err := r.Update(ctx, resourceServer); err != nil {
			return ctrl.Result{}, fmt.Errorf("add resource-server finalizer: %w", err)
		}
	}
	if err := r.validateAuthorizationExecution(ctx, resourceServer, driver, plan); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, "StalePlan", err, nil)
	}
	state, err := driver.Reconcile(ctx, plan, managedObjectsFromStatus(resourceServer.Status))
	if err != nil {
		reason := "ReconcileFailed"
		if errors.Is(err, authorization.ErrOwnershipConflict) {
			reason = "OwnershipConflict"
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, reason, err, &state)
	}
	if err := r.validateAuthorizationExecution(ctx, resourceServer, driver, plan); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, resourceServer, &plan, "StalePlan", err, &state)
	}
	return r.statusObservation(ctx, resourceServer, state, plan, false)
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
	case "organization":
		if r.organizationResolver == nil {
			return authorization.Principal{}, authorization.OrganizationFailure("OrganizationPolicyUnsupported")
		}
		return r.organizationResolver.resolve(ctx, principal)
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
	return authorization.Principal{Kind: principal.Kind, Ref: resolvedRef, PortableRef: principal.Ref}, nil
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
		if principal.IncludeDescendants && principal.Kind != "organization" {
			return authorization.OrganizationFailure("OrganizationPolicyUnsupported")
		}
		if principal.Kind != "realm_role" && principal.Kind != "application" && principal.Kind != "service_account" && principal.Kind != "organization" {
			return fmt.Errorf("permission %q has unsupported principal kind %q", permission.Name, principal.Kind)
		}
	}
	return nil
}

func (r *HankoResourceServerReconciler) statusError(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, reason string, err error) error {
	return r.statusPlanError(ctx, obj, nil, reason, err, nil)
}
func (r *HankoResourceServerReconciler) statusPlanError(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, plan *authorization.Plan, reason string, err error, state *authorization.State) error {
	patch := client.MergeFrom(obj.DeepCopy())
	e := authorizationEvidence(&obj.Status)
	e.process(obj.Generation, obj.Spec.Mode == ModeObserve || isImported(obj.Labels))
	if plan != nil {
		e.evaluate(obj.Generation, plan.Identity())
		obj.Status.Capabilities = capabilityStatus(plan.Evidence().Supported)
	}
	var rejected iamEvaluationRejected
	if errors.As(err, &rejected) {
		e.evaluate(obj.Generation, rejected.identity)
		obj.Status.Capabilities = capabilityStatus(rejected.authorizationCaps)
		obj.Status.Findings = findingsStatus([]iamcontract.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "resource_server", Code: "unsupported_semantics", Message: "desired semantics cannot be represented by the selected adapter"}})
	}
	if state != nil {
		e.observe(obj.Generation, plan.Identity(), state.Observation)
		if state.ManagedObjects.ResourceServerID != "" && authorization.BoundedManagedObjects(state.ManagedObjects) {
			obj.Status.ProviderResourceServerID = state.ManagedObjects.ResourceServerID
			obj.Status.ManagedObjects = managedObjectsStatus(state.ManagedObjects)
		}
		obj.Status.Findings = findingsStatus(state.Findings)
	}
	historicalExplanation(obj, "Stale", metav1.ConditionFalse)
	obj.Status.Phase = "Error"
	iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionUnknown, "NotProven", "current attempt has no proven provider observation")
	if state != nil && iamcontract.ValidDigest(string(state.Observation.StateHash)) {
		iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionTrue, "Observed", "bounded provider observation succeeded")
	}
	reason = iamFailureReason(err, reason)
	var orgError authorization.OrganizationError
	if errors.As(err, &orgError) {
		reason = orgError.Code
		obj.Status.Findings = findingsStatus([]authorization.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "organization", Code: orgError.Code, Message: orgError.Error()}})
	}
	safe := iamcontract.SafeError(err)
	for _, kind := range []string{"Synced", "DriftFree"} {
		iamCondition(&obj.Status.Conditions, obj.Generation, kind, metav1.ConditionFalse, reason, safe.Error())
	}
	if patchErr := r.Status().Patch(ctx, obj, patch); patchErr != nil {
		return errors.Join(safe, patchErr)
	}
	return safe
}
func (r *HankoResourceServerReconciler) statusCapabilityError(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, caps authorization.Capabilities, err error) error {
	// Capability lookup and reference resolution have completed. The rejection
	// identity is carried by the compile error, never supplied by status.
	_ = caps
	return r.statusPlanError(ctx, obj, nil, "UnsupportedCapability", err, nil)
}
func (r *HankoResourceServerReconciler) statusObservation(ctx context.Context, obj *hankoshv1alpha1.HankoResourceServer, state authorization.State, plan authorization.Plan, observe bool) (ctrl.Result, error) {
	if !observe {
		if !authorization.BoundedManagedObjects(state.ManagedObjects) {
			return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, obj, &plan, "EvidenceBudgetExceeded", iamcontract.ErrObservationIncomplete, nil)
		}
		if err := observationError(state.Observation); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, r.statusPlanError(ctx, obj, &plan, "ReadBackFailed", err, &state)
		}
	}
	patch := client.MergeFrom(obj.DeepCopy())
	e := authorizationEvidence(&obj.Status)
	e.process(obj.Generation, observe)
	e.evaluate(obj.Generation, plan.Identity())
	e.observe(obj.Generation, plan.Identity(), state.Observation)
	if !observe {
		e.apply(obj.Generation, plan.Identity())
		obj.Status.ManagedObjects = managedObjectsStatus(state.ManagedObjects)
	}
	obj.Status.Phase = "Ready"
	if observationError(state.Observation) != nil {
		obj.Status.Phase = "Error"
	}
	now := metav1.Now()
	obj.Status.LastReconciled = &now
	obj.Status.ProviderResourceServerID = state.ProviderResourceServerID
	obj.Status.Capabilities = capabilityStatus(state.Capabilities)
	obj.Status.Findings = findingsStatus(state.Findings)
	reason, message := "Reconciled", "provider read-back matches the evaluated contract"
	if observe {
		obj.Status.AdoptionCandidate = refreshTargetCandidate(ctx, r.Client, r.APIReader, obj)
		reason, message = "Observed", "provider state observed without mutation"
	}
	status := metav1.ConditionTrue
	if err := observationError(state.Observation); err != nil {
		status = metav1.ConditionFalse
		reason = iamFailureReason(err, "ObservationIncomplete")
		message = "provider observation does not prove synchronized state"
	}
	for _, kind := range []string{"Synced", "DriftFree"} {
		iamCondition(&obj.Status.Conditions, obj.Generation, kind, status, reason, message)
	}
	iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionTrue, "Observed", "bounded provider observation succeeded")
	iamCondition(&obj.Status.Conditions, obj.Generation, "CapabilitiesSatisfied", metav1.ConditionTrue, "Supported", "adapter supports requested semantics")
	r.projectExplanation(ctx, obj, state, plan, !observe)
	if err := r.Status().Patch(ctx, obj, patch); err != nil {
		return ctrl.Result{}, err
	}
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
		ScopeGrants: value.ScopeGrants, RolePrincipals: value.RolePrincipals, OrganizationPrincipals: value.OrganizationPrincipals, OrganizationDescendants: value.OrganizationDescendants,
		ApplicationPrincipals: value.ApplicationPrincipals, ServiceAccountPrincipals: value.ServiceAccountPrincipals,
		ResourceObjects: value.ResourceObjects, ResourceURIMatching: value.ResourceURIMatching,
		UMARPT: value.UMARPT, NativePermissionClaim: value.NativePermissionClaim,
	}
}

func findingsStatus(findings []authorization.Finding) []hankoshv1alpha1.AuthorizationFinding {
	findings = iamcontract.Findings(findings)
	result := make([]hankoshv1alpha1.AuthorizationFinding, 0, len(findings))
	for _, finding := range findings {
		result = append(result, hankoshv1alpha1.AuthorizationFinding{
			Classification: string(finding.Classification), ObjectKind: finding.ObjectKind, ObjectName: finding.ObjectName,
			Code: finding.Code, Message: finding.Message, ReadOnly: finding.ReadOnly,
		})
	}
	return result
}

func (r *HankoResourceServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &hankoshv1alpha1.HankoResourceServer{}, organizationPrincipalIndex, authorizationProvenanceIndexValues); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoResourceServer{}, builder.WithPredicates(resourceServerAuthorityChanged())).
		Watches(&hankoshv1alpha1.HankoOrganization{}, handler.EnqueueRequestsFromMapFunc(r.organizationRequests)).
		Watches(&hankoshv1alpha1.HankoRole{}, handler.EnqueueRequestsFromMapFunc(r.organizationRequests)).
		Complete(r)
}
