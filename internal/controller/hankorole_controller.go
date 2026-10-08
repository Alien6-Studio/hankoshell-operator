package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
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

	kc := kcForObject(r.Pool, role.Namespace, role.Labels)
	if err := validateStandaloneEffectiveAuthorityRoles(ctx, &role, r.ProtectedRealm, kc); err != nil {
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
		return r.reconcileRoleDeletion(ctx, &role, kc)
	}

	// ── Ensure finalizer ──────────────────────────────────────────────────────
	if err := r.ensureRoleFinalizer(ctx, &role); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(role.DeepCopy())
	now := metav1.Now()

	// ── Sync role representation (name, description, attributes) ───────────────
	kcRole := keycloak.RealmRole{
		Name:        role.Spec.Name,
		Description: role.Spec.Description,
		Composite:   role.Spec.Composite,
		Attributes:  role.Spec.Attributes,
	}
	if err := kc.SyncRealmRole(ctx, role.Spec.RealmRef, kcRole); err != nil {
		role.Status.Phase = "Error"
		setCondition(&role.Status.Conditions, "Synced", metav1.ConditionFalse, "SyncFailed", err.Error())
		_ = r.Status().Patch(ctx, &role, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("sync realm role %q: %w", role.Spec.Name, err)
	}

	// ── Composites ───────────────────────────────────────────────────────────
	if err := r.reconcileRoleComposites(ctx, &role, kc, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}

	role.Status.Phase = "Ready"
	role.Status.LastReconciled = &now
	setCondition(&role.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "realm role present in Keycloak")

	if err := r.Status().Patch(ctx, &role, patch); err != nil {
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

func (r *HankoRoleReconciler) reconcileRoleDeletion(ctx context.Context, role *hankoshv1alpha1.HankoRole, kc *keycloak.Client) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(role, roleFinalizerName) {
		return ctrl.Result{}, nil
	}
	if err := kc.DeleteRealmRole(ctx, role.Spec.RealmRef, role.Spec.Name); err != nil {
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

func (r *HankoRoleReconciler) reconcileRoleComposites(ctx context.Context, role *hankoshv1alpha1.HankoRole, kc *keycloak.Client, patch client.Patch) error {
	if len(role.Spec.Composites) == 0 {
		return nil
	}
	if err := kc.EnsureRealmRoleComposites(ctx, role.Spec.RealmRef, role.Spec.Name, role.Spec.Composites); err != nil {
		role.Status.Phase = "Error"
		setCondition(&role.Status.Conditions, "Synced", metav1.ConditionFalse, "CompositesFailed", err.Error())
		_ = r.Status().Patch(ctx, role, patch)
		return fmt.Errorf("ensure composites for role %q: %w", role.Spec.Name, err)
	}
	return nil
}

func (r *HankoRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoRole{}).
		Complete(r)
}
