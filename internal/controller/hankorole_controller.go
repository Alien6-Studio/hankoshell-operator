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
		setCondition(&role.Status.Conditions, "Synced", metav1.ConditionFalse, "ReservedAuthorityRole", err.Error())
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
		reason := "AuthorityRoleLookupFailed"
		if isReservedAuthorityRoleViolation(err) {
			reason = "ReservedAuthorityRole"
		}
		setCondition(&role.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
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
		return r.roleError(ctx, &role, "PlanRejected", err)
	}
	if isImported(role.Labels) {
		if controllerutil.ContainsFinalizer(&role, roleFinalizerName) {
			controllerutil.RemoveFinalizer(&role, roleFinalizerName)
			if err := r.Update(ctx, &role); err != nil {
				return ctrl.Result{}, err
			}
		}
		if _, err := driver.Observe(ctx, plan); err != nil {
			return r.roleError(ctx, &role, "ObserveFailed", err)
		}
		return r.roleSuccess(ctx, &role, "Observed")
	}
	if err := r.ensureRoleFinalizer(ctx, &role); err != nil {
		return ctrl.Result{}, err
	}
	// Re-fetch source and relationships just before mutation. Concurrent changes
	// require a fresh compile; Kubernetes status is not execution authority.
	var current hankoshv1alpha1.HankoRole
	if err := r.Get(ctx, client.ObjectKeyFromObject(&role), &current); err != nil {
		return ctrl.Result{}, err
	}
	next, err := r.compileRolePlan(ctx, &current, driver)
	if err != nil {
		return r.roleError(ctx, &role, "PlanRejected", err)
	}
	if !current.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, iamcontract.ErrStale
	}
	if err := plan.Validate(next); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.validateRoleAuthority(ctx, &current, driver); err != nil {
		return r.roleError(ctx, &role, "AuthorityRoleLookupFailed", err)
	}
	if _, err := driver.Reconcile(ctx, plan); err != nil {
		reason := "SyncFailed"
		if errors.Is(err, roles.ErrOwnershipConflict) {
			reason = "OwnershipConflict"
		}
		return r.roleError(ctx, &role, reason, err)
	}
	return r.roleSuccess(ctx, &role, "Reconciled")
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
	return roles.Compile(intent, resolved, caps, executionPreconditions(role, reader.digest(), mode))
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
func (r *HankoRoleReconciler) roleError(ctx context.Context, role *hankoshv1alpha1.HankoRole, reason string, err error) (ctrl.Result, error) {
	err = iamcontract.SafeError(err)
	patch := client.MergeFrom(role.DeepCopy())
	role.Status.Phase = "Error"
	setCondition(&role.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
	if e := r.Status().Patch(ctx, role, patch); e != nil {
		return ctrl.Result{}, e
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, err
}
func (r *HankoRoleReconciler) roleSuccess(ctx context.Context, role *hankoshv1alpha1.HankoRole, reason string) (ctrl.Result, error) {
	patch := client.MergeFrom(role.DeepCopy())
	now := metav1.Now()
	role.Status.Phase = "Ready"
	role.Status.LastReconciled = &now
	setCondition(&role.Status.Conditions, "Synced", metav1.ConditionTrue, reason, "realm role contract evaluated")
	if err := r.Status().Patch(ctx, role, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoRole synced", "role", role.Spec.Name, "realm", role.Spec.RealmRef)
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoRole{}).
		Complete(r)
}
