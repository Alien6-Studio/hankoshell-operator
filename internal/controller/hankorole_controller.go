package controller

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

const roleFinalizerName = "hanko.sh/role-cleanup"

// HankoRoleReconciler reconciles HankoRole objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoroles/finalizers,verbs=update
type HankoRoleReconciler struct {
	APIReader client.Reader
	client.Client
	ProtectedRealm string
	Scheme         *runtime.Scheme
	Pool           *keycloak.Pool
	Recorder       events.EventRecorder
	DriverFactory  func(string, map[string]string) roles.Driver
}

func (r *HankoRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var role hankoshv1alpha1.HankoRole
	if err := r.Get(ctx, req.NamespacedName, &role); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err := validateStandaloneAuthorityRole(&role, r.ProtectedRealm); err != nil {
		if !role.DeletionTimestamp.IsZero() {
			return r.releaseInvalidRole(ctx, &role, err.Error())
		}
		patch := client.MergeFrom(role.DeepCopy())
		role.Status.Phase = "Error"
		roleEvidence(&role.Status).process(role.Generation, isImported(role.Labels))
		iamCondition(&role.Status.Conditions, role.Generation, "Synced", metav1.ConditionFalse, "ReservedAuthorityRole", err.Error())
		if patchErr := r.Status().Patch(ctx, &role, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}

	driver := r.roleDriver(&role)
	if err := r.validateRoleAuthority(ctx, &role, driver); err != nil {
		if !role.DeletionTimestamp.IsZero() {
			if isReservedAuthorityRoleViolation(err) {
				return r.releaseInvalidRole(ctx, &role, err.Error())
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify role authority before deletion: %w", err)
		}
		patch := client.MergeFrom(role.DeepCopy())
		role.Status.Phase = "Error"
		roleEvidence(&role.Status).process(role.Generation, isImported(role.Labels))
		reason := "AuthorityRoleLookupFailed"
		if isReservedAuthorityRoleViolation(err) {
			reason = "ReservedAuthorityRole"
		}
		iamCondition(&role.Status.Conditions, role.Generation, "Synced", metav1.ConditionFalse, reason, err.Error())
		if patchErr := r.Status().Patch(ctx, &role, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		if isReservedAuthorityRoleViolation(err) {
			return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify role authority: %w", err)
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !role.DeletionTimestamp.IsZero() {
		return r.reconcileRoleDeletion(ctx, &role, driver)
	}

	plan, err := r.compileRolePlan(ctx, &role, driver)
	if err != nil {
		return r.rolePlanError(ctx, &role, nil, "PlanRejected", err, nil)
	}
	if isImported(role.Labels) {
		if controllerutil.ContainsFinalizer(&role, roleFinalizerName) {
			controllerutil.RemoveFinalizer(&role, roleFinalizerName)
			if err := r.Update(ctx, &role); err != nil {
				return ctrl.Result{}, err
			}
		}
		if err := r.validateRoleExecution(ctx, &role, driver, plan); err != nil {
			return r.rolePlanError(ctx, &role, &plan, "StalePlan", err, nil)
		}
		state, err := driver.Observe(ctx, plan)
		if err != nil {
			return r.rolePlanError(ctx, &role, &plan, "ObserveFailed", err, nil)
		}
		if err := r.validateRoleAuthority(ctx, &role, driver); err != nil {
			return r.rolePlanError(ctx, &role, &plan, "ReservedAuthorityRole", err, &state)
		}
		return r.roleObservation(ctx, &role, plan, state, true)
	}
	if err := r.ensureRoleFinalizer(ctx, &role); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.validateRoleExecution(ctx, &role, driver, plan); err != nil {
		return r.rolePlanError(ctx, &role, &plan, "StalePlan", err, nil)
	}
	if err := r.validateRoleAuthority(ctx, &role, driver); err != nil {
		return r.rolePlanError(ctx, &role, &plan, "AuthorityRoleLookupFailed", err, nil)
	}
	state, err := driver.Reconcile(ctx, plan)
	if err != nil {
		reason := "SyncFailed"
		if errors.Is(err, roles.ErrOwnershipConflict) {
			reason = "OwnershipConflict"
		}
		return r.rolePlanError(ctx, &role, &plan, reason, err, &state)
	}
	if err := r.validateRoleExecution(ctx, &role, driver, plan); err != nil {
		return r.rolePlanError(ctx, &role, &plan, "StalePlan", err, &state)
	}
	if err := r.validateRoleAuthority(ctx, &role, driver); err != nil {
		return r.rolePlanError(ctx, &role, &plan, "ReservedAuthorityRole", err, &state)
	}
	return r.roleObservation(ctx, &role, plan, state, false)
}
func (r *HankoRoleReconciler) roleDriver(role *hankoshv1alpha1.HankoRole) roles.Driver {
	if r.DriverFactory != nil {
		return r.DriverFactory(role.Namespace, role.Labels)
	}
	return roles.NewKeycloakDriver(kcForObject(r.Pool, role.Namespace, role.Labels))
}
func (r *HankoRoleReconciler) compileRolePlan(ctx context.Context, role *hankoshv1alpha1.HankoRole, driver roles.Driver) (roles.Plan, error) {
	reader := &contractReferenceReader{Client: r.Client}
	var realm hankoshv1alpha1.HankoRealm
	if err := reader.Get(ctx, client.ObjectKey{Namespace: role.Namespace, Name: role.Spec.RealmRef}, &realm); err != nil {
		return roles.Plan{}, err
	}
	if !realm.DeletionTimestamp.IsZero() || (isImported(realm.Labels) && !isImported(role.Labels)) {
		return roles.Plan{}, iamcontract.ErrRejected
	}
	caps, err := driver.Capabilities(ctx)
	if err != nil {
		return roles.Plan{}, iamcontract.SafeError(err)
	}
	owner := string(role.UID)

	intent := roles.Intent{RealmRef: role.Spec.RealmRef, Name: role.Spec.Name, Description: role.Spec.Description, Composite: role.Spec.Composite, Composites: role.Spec.Composites}
	resolved := roles.ResolvedReferences{Realm: realm.Name, Owner: owner, Attributes: role.Spec.Attributes}
	mode := ModeManage
	if isImported(role.Labels) {
		mode = ModeObserve
	}
	plan, err := roles.Compile(intent, resolved, caps, executionPreconditions(role, reader.digest(), mode))
	if err != nil {
		return plan, iamEvaluationRejected{cause: err, identity: iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: roles.IntentIdentity(intent)}, roleCaps: caps.Supported, findings: caps.Findings}
	}
	return plan, nil
}
func (r *HankoRoleReconciler) validateRoleAuthority(ctx context.Context, role *hankoshv1alpha1.HankoRole, driver roles.Driver) error {
	if r.ProtectedRealm == "" || role.Spec.RealmRef != r.ProtectedRealm {
		return nil
	}
	for _, name := range append([]string{role.Spec.Name}, role.Spec.Composites...) {
		closure, err := driver.AuthorityClosure(ctx, role.Spec.RealmRef, name)
		if err != nil {
			return err
		}
		for _, effective := range closure {
			if isReservedAuthorityRole(effective) {
				return reservedAuthorityRoleError(r.ProtectedRealm, role.Spec.RealmRef, "HankoRole composite", effective)
			}
		}
	}
	return nil
}
func (r *HankoRoleReconciler) validateRoleExecution(ctx context.Context, obj *hankoshv1alpha1.HankoRole, driver roles.Driver, plan roles.Plan) error {
	var current hankoshv1alpha1.HankoRole
	if err := r.Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
		return err
	}
	if !current.DeletionTimestamp.IsZero() {
		return iamcontract.ErrStale
	}
	next, err := r.compileRolePlan(ctx, &current, driver)
	if err != nil {
		return err
	}
	return plan.Validate(next)
}
func (r *HankoRoleReconciler) rolePlanError(ctx context.Context, obj *hankoshv1alpha1.HankoRole, plan *roles.Plan, reason string, err error, state *roles.State) (ctrl.Result, error) {
	patch := client.MergeFrom(obj.DeepCopy())
	e := roleEvidence(&obj.Status)
	e.process(obj.Generation, isImported(obj.Labels))
	if plan != nil {
		e.evaluate(obj.Generation, plan.Identity())
		obj.Status.Capabilities = roleCapabilityStatus(plan.Evidence().Supported)
	}
	var rejected iamEvaluationRejected
	if errors.As(err, &rejected) {
		e.evaluate(obj.Generation, rejected.identity)
		obj.Status.Capabilities = roleCapabilityStatus(rejected.roleCaps)
		findings := rejected.findings
		if len(findings) == 0 {
			findings = []iamcontract.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "role", Code: "unsupported_semantics", Message: "desired semantics cannot be represented by the selected adapter"}}
		}
		obj.Status.Findings = findingsStatus(findings)
	}
	if state != nil {
		e.observe(obj.Generation, plan.Identity(), state.Observation)
		obj.Status.Findings = findingsStatus(state.Findings)
	}
	obj.Status.Phase = "Error"
	iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionUnknown, "NotProven", "current attempt has no proven provider observation")
	if state != nil && iamcontract.ValidDigest(string(state.Observation.StateHash)) {
		iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionTrue, "Observed", "bounded provider observation succeeded")
	}
	err = iamcontract.SafeError(err)
	iamCondition(&obj.Status.Conditions, obj.Generation, "Synced", metav1.ConditionFalse, iamFailureReason(err, reason), err.Error())
	if patchErr := r.Status().Patch(ctx, obj, patch); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, err
}
func (r *HankoRoleReconciler) roleObservation(ctx context.Context, obj *hankoshv1alpha1.HankoRole, plan roles.Plan, state roles.State, observe bool) (ctrl.Result, error) {
	if !observe {
		if err := observationError(state.Observation); err != nil {
			return r.rolePlanError(ctx, obj, &plan, "ReadBackFailed", err, &state)
		}
		if !state.Present || !state.Owned {
			return r.rolePlanError(ctx, obj, &plan, "OwnershipConflict", roles.ErrOwnershipConflict, &state)
		}
	}
	patch := client.MergeFrom(obj.DeepCopy())
	e := roleEvidence(&obj.Status)
	e.process(obj.Generation, observe)
	e.evaluate(obj.Generation, plan.Identity())
	e.observe(obj.Generation, plan.Identity(), state.Observation)
	if !observe {
		e.apply(obj.Generation, plan.Identity())
	}
	obj.Status.Capabilities = roleCapabilityStatus(plan.Evidence().Supported)
	obj.Status.Findings = findingsStatus(state.Findings)
	obj.Status.Phase = "Ready"
	if observationError(state.Observation) != nil {
		obj.Status.Phase = "Error"
	}
	now := metav1.Now()
	obj.Status.LastReconciled = &now
	reason, status, message := "Reconciled", metav1.ConditionTrue, "provider read-back matches the evaluated contract"
	if observe {
		obj.Status.AdoptionCandidate = refreshImportedCandidate(ctx, r.Client, r.APIReader, obj)
		reason, message = "Observed", "provider state observed without mutation"
	}
	if err := observationError(state.Observation); err != nil {
		status = metav1.ConditionFalse
		reason = iamFailureReason(err, "ObservationIncomplete")
		message = "provider observation does not prove synchronized state"
	}
	iamCondition(&obj.Status.Conditions, obj.Generation, "Synced", status, reason, message)
	iamCondition(&obj.Status.Conditions, obj.Generation, "ObservationSucceeded", metav1.ConditionTrue, "Observed", "bounded provider observation succeeded")
	if err := r.Status().Patch(ctx, obj, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoRoleReconciler) releaseInvalidRole(ctx context.Context, role *hankoshv1alpha1.HankoRole, message string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(role, roleFinalizerName) {
		return ctrl.Result{}, nil
	}
	controllerutil.RemoveFinalizer(role, roleFinalizerName)
	if err := r.Update(ctx, role); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove reserved-role finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released invalid reserved role without mutating Keycloak", "role", role.Spec.Name, "reason", message)
	return ctrl.Result{}, nil
}

func (r *HankoRoleReconciler) reconcileRoleDeletion(ctx context.Context, role *hankoshv1alpha1.HankoRole, driver roles.Driver) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(role, roleFinalizerName) {
		return ctrl.Result{}, nil
	}
	if isImported(role.Labels) {
		controllerutil.RemoveFinalizer(role, roleFinalizerName)
		return ctrl.Result{}, r.Update(ctx, role)
	}
	caps, err := driver.Capabilities(ctx)
	if err != nil {
		return ctrl.Result{}, iamcontract.SafeError(err)
	}
	plan, err := roles.Compile(roles.Intent{RealmRef: role.Spec.RealmRef, Name: role.Spec.Name}, roles.ResolvedReferences{Realm: role.Spec.RealmRef, Owner: string(role.UID)}, caps, executionPreconditions(role, "", ModeManage))
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := driver.DeleteOwned(ctx, plan); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete realm role %q: %w", role.Spec.Name, err)
	}
	controllerutil.RemoveFinalizer(role, roleFinalizerName)
	if err := r.Update(ctx, role); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove role finalizer: %w", err)
	}
	log.FromContext(ctx).Info("realm role deleted", "role", role.Spec.Name)
	return ctrl.Result{}, nil
}

func (r *HankoRoleReconciler) ensureRoleFinalizer(ctx context.Context, role *hankoshv1alpha1.HankoRole) error {
	if controllerutil.ContainsFinalizer(role, roleFinalizerName) {
		return nil
	}
	controllerutil.AddFinalizer(role, roleFinalizerName)
	if err := r.Update(ctx, role); err != nil {
		return fmt.Errorf("add role finalizer: %w", err)
	}
	return nil
}

func (r *HankoRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoRole{}).
		Complete(r)
}

func roleCapabilityStatus(c roles.Capabilities) hankoshv1alpha1.RoleCapabilitySnapshot {
	return hankoshv1alpha1.RoleCapabilitySnapshot{RealmRoles: c.RealmRoles, Composites: c.Composites, NativeAttributes: c.NativeAttributes}
}
