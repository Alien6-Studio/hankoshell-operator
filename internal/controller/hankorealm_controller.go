package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const realmFinalizerName = "hanko.sh/realm-cleanup"

// HankoRealmReconciler reconciles HankoRealm objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankothemes,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoiamprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type HankoRealmReconciler struct {
	client.Client
	ProtectedRealm string
	Scheme         *runtime.Scheme
	Pool           *keycloak.Pool
	Recorder       events.EventRecorder
}

func (r *HankoRealmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var realm hankoshv1alpha1.HankoRealm
	if err := r.Get(ctx, req.NamespacedName, &realm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Master realm is Keycloak's own admin realm — never manage it.
	if realm.Name == "master" {
		if r.Recorder != nil {
			r.Recorder.Eventf(&realm, nil, corev1.EventTypeWarning, "ProtectedRealm", "Reconcile", "%s", "hanko-operator does not manage the master realm")
		}
		return ctrl.Result{}, nil
	}

	observe := isImported(realm.Labels)
	if !observe {
		if err := validateRealmAuthorityRoles(&realm, r.ProtectedRealm); err != nil {
			if !realm.DeletionTimestamp.IsZero() {
				return r.releaseInvalidRealm(ctx, &realm, err.Error())
			}
			patch := client.MergeFrom(realm.DeepCopy())
			realm.Status.Phase = "Error"
			realm.Status.ObservedGeneration = realm.Generation
			setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "ReservedAuthorityRole", err.Error())
			if patchErr := r.Status().Patch(ctx, &realm, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
		}
	}
	kc := kcForObject(r.Pool, realm.Namespace, realm.Labels)
	if !observe && !realm.DeletionTimestamp.IsZero() && strings.TrimSpace(r.ProtectedRealm) != "" && realm.Name == strings.TrimSpace(r.ProtectedRealm) {
		return r.releaseProtectedAuthorityRealm(ctx, &realm)
	}
	if !observe {
		if err := validateRealmEffectiveAuthorityRoles(ctx, &realm, r.ProtectedRealm, kc); err != nil {
			patch := client.MergeFrom(realm.DeepCopy())
			realm.Status.Phase = "Error"
			realm.Status.ObservedGeneration = realm.Generation
			reason := "AuthorityRoleLookupFailed"
			if isReservedAuthorityRoleViolation(err) {
				reason = "ReservedAuthorityRole"
			}
			setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
			if patchErr := r.Status().Patch(ctx, &realm, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			if isReservedAuthorityRoleViolation(err) {
				return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify realm authority roles: %w", err)
		}
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !realm.DeletionTimestamp.IsZero() {
		return r.reconcileRealmDeletion(ctx, &realm, kc, observe)
	}

	// ── Ensure finalizer ──────────────────────────────────────────────────────
	// Imported realms describe pre-existing Keycloak state. Remove any finalizer
	// left by older operator versions, then switch to read-only status reporting.
	if observe {
		return r.prepareRealmObserve(ctx, &realm, kc)
	}

	if !controllerutil.ContainsFinalizer(&realm, realmFinalizerName) {
		controllerutil.AddFinalizer(&realm, realmFinalizerName)
		if err := r.Update(ctx, &realm); err != nil {
			return ctrl.Result{}, fmt.Errorf("add realm finalizer: %w", err)
		}
	}

	patch := client.MergeFrom(realm.DeepCopy())
	return r.reconcileManagedRealm(ctx, &realm, kc, patch)
}

func (r *HankoRealmReconciler) releaseProtectedAuthorityRealm(ctx context.Context, realm *hankoshv1alpha1.HankoRealm) (ctrl.Result, error) {
	message := fmt.Sprintf("fleet authority realm %q is provider-protected and was not deleted from Keycloak", realm.Name)
	patch := client.MergeFrom(realm.DeepCopy())
	realm.Status.Phase = "Error"
	realm.Status.ObservedGeneration = realm.Generation
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "ProtectedAuthorityRealm", message)
	if err := r.Status().Patch(ctx, realm, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("record protected authority realm deletion: %w", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(realm, nil, corev1.EventTypeWarning, "ProtectedAuthorityRealm", "Reconcile", "%s", message)
	}
	if controllerutil.ContainsFinalizer(realm, realmFinalizerName) {
		controllerutil.RemoveFinalizer(realm, realmFinalizerName)
		if err := r.Update(ctx, realm); err != nil {
			return ctrl.Result{}, fmt.Errorf("release protected authority realm finalizer: %w", err)
		}
	}
	log.FromContext(ctx).Info(message)
	return ctrl.Result{}, nil
}

func (r *HankoRealmReconciler) releaseInvalidRealm(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, message string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(realm, realmFinalizerName) {
		return ctrl.Result{}, nil
	}
	controllerutil.RemoveFinalizer(realm, realmFinalizerName)
	if err := r.Update(ctx, realm); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove invalid realm finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released realm with an invalid reserved authority role without mutating Keycloak", "realm", realm.Name, "reason", message)
	return ctrl.Result{}, nil
}

func (r *HankoRealmReconciler) reconcileRealmDeletion(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, observe bool) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(realm, realmFinalizerName) {
		return ctrl.Result{}, nil
	}
	if observe {
		log.FromContext(ctx).Info("Observe mode: dropping legacy finalizer without deleting Keycloak realm", "realm", realm.Name)
		return ctrl.Result{}, r.removeRealmFinalizer(ctx, realm, "remove imported realm finalizer")
	}
	blocking, err := r.realmDeletionBlockers(ctx, realm)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if len(blocking) > 0 {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("realm %q has %d managed resource(s) still present: %v — delete them first", realm.Name, len(blocking), blocking)
	}
	if err := kc.EnsureRealmDeletionAccess(ctx, realm.Name); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("ensure realm deletion access: %w", err)
	}
	if err := kc.DeleteRealm(ctx, realm.Name); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete realm from keycloak: %w", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(realm, nil, corev1.EventTypeNormal, "RealmDeleted", "Reconcile", "%s", fmt.Sprintf("HankoRealm %q deleted from Keycloak", realm.Name))
	}
	log.FromContext(ctx).Info("HankoRealm deleted from Keycloak", "realm", realm.Name)
	return ctrl.Result{}, r.removeRealmFinalizer(ctx, realm, "remove realm finalizer")
}

func (r *HankoRealmReconciler) realmDeletionBlockers(ctx context.Context, realm *hankoshv1alpha1.HankoRealm) ([]string, error) {
	var apps hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &apps, client.InNamespace(realm.Namespace)); err != nil {
		return nil, err
	}
	blocking := make([]string, 0)
	for _, app := range apps.Items {
		if app.Spec.RealmRef == realm.Name {
			blocking = append(blocking, app.Spec.ClientID)
		}
	}
	var accounts hankoshv1alpha1.HankoServiceAccountList
	if err := r.List(ctx, &accounts, client.InNamespace(realm.Namespace)); err != nil {
		return nil, err
	}
	for _, account := range accounts.Items {
		if account.Spec.RealmRef == realm.Name {
			blocking = append(blocking, account.Spec.ClientID)
		}
	}
	var issuers hankoshv1alpha1.HankoIssuerList
	if err := r.List(ctx, &issuers, client.InNamespace(realm.Namespace)); err != nil {
		return nil, err
	}
	for _, issuer := range issuers.Items {
		if issuer.Spec.RealmRef == realm.Name {
			blocking = append(blocking, "issuer/"+issuer.Spec.Host)
		}
	}
	return blocking, nil
}

func (r *HankoRealmReconciler) removeRealmFinalizer(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, action string) error {
	controllerutil.RemoveFinalizer(realm, realmFinalizerName)
	if err := r.Update(ctx, realm); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func (r *HankoRealmReconciler) prepareRealmObserve(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(realm, realmFinalizerName) {
		if err := r.removeRealmFinalizer(ctx, realm, "remove imported realm finalizer"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	return r.reconcileRealmObserve(ctx, realm, kc, client.MergeFrom(realm.DeepCopy()))
}

func (r *HankoRealmReconciler) reconcileManagedRealm(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, patch client.Patch) (ctrl.Result, error) { // NOSONAR -- managed realm convergence keeps ordered security checks explicit.
	patch, err := r.markRealmGeneration(ctx, realm, patch)
	if err != nil {
		return ctrl.Result{}, err
	}
	effectiveProfile, err := resolveRealmIAMProfile(ctx, r.Client, realm)
	if err != nil {
		realm.Status.Phase = "Error"
		setCondition(&realm.Status.Conditions, "IAMProfileReady", metav1.ConditionFalse, "ResolutionFailed", err.Error())
		if patchErr := r.Status().Patch(ctx, realm, patch); patchErr != nil {
			return ctrl.Result{}, fmt.Errorf("resolve IAM profile (%v); patch realm status: %w", err, patchErr)
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}
	if effectiveProfile.Security == nil {
		setCondition(&realm.Status.Conditions, "IAMProfileReady", metav1.ConditionTrue, "NoProfile", "realm uses provider defaults because no IAM profile is configured")
	} else {
		setCondition(&realm.Status.Conditions, "IAMProfileReady", metav1.ConditionTrue, "ProfileResolved", fmt.Sprintf("IAM profile %q resolved as %s", effectiveProfile.Name, effectiveProfile.Hash))
	}
	handled, result, err := r.waitForRealmTheme(ctx, realm, patch)
	if err != nil || handled {
		return result, err
	}
	kcRealm, err := r.ensureRealmAndManagementAccess(ctx, realm, effectiveProfile.Security, kc, patch)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	desiredRealm, err := r.applyManagedRealmConfiguration(ctx, realm, effectiveProfile.Security, kc, patch)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if err := r.enforceStrengthenedAuthenticationPolicy(ctx, realm, kc, desiredRealm, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if err := r.reconcileManagedRealmChildrenWithSecurity(ctx, realm, effectiveProfile.Security, kc, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if handled, result, err := r.reconcileManagedRealmSecurity(ctx, realm, kc, desiredRealm, patch); err != nil || handled {
		return result, err
	}

	now := metav1.Now()
	realm.Status.Phase = "Ready"
	realm.Status.ObservedGeneration = realm.Generation
	realm.Status.KeycloakRealmID = kcRealm.ID
	realm.Status.LastReconciled = &now
	if realm.Status.EffectivePolicyHash != effectiveProfile.Hash {
		realm.Status.PolicyRevision++
	}
	realm.Status.EffectiveIAMProfile = effectiveProfile.Name
	realm.Status.EffectivePolicyHash = effectiveProfile.Hash
	realm.Status.AppliedMFAPolicy = normalizedMFAPolicy(desiredRealm.MFAPolicy)
	setRealmSMTPCondition(&realm.Status.Conditions, kcRealm.SMTPServer)
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "realm present in Keycloak")

	if err := r.Status().Patch(ctx, realm, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch realm status: %w", err)
	}

	log.FromContext(ctx).Info("reconciled HankoRealm", "realm", realm.Name, "keycloakID", kcRealm.ID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoRealmReconciler) enforceStrengthenedAuthenticationPolicy(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, desired keycloak.RealmSpec, patch client.Patch) error {
	if !mfaPolicyStrengthened(realm.Status.AppliedMFAPolicy, desired.MFAPolicy) {
		setCondition(&realm.Status.Conditions, "SessionPolicyEnforced", metav1.ConditionTrue, "NoRevocationRequired", "effective MFA policy does not require existing session revocation")
		return nil
	}
	if err := kc.LogoutAllRealmSessions(ctx, realm.Name); err != nil {
		setCondition(&realm.Status.Conditions, "SessionPolicyEnforced", metav1.ConditionFalse, "SessionRevocationFailed", err.Error())
		return r.realmSyncError(ctx, realm, patch, fmt.Errorf("revoke sessions after MFA policy strengthening: %w", err), "patch status after session revocation failure")
	}
	setCondition(&realm.Status.Conditions, "SessionPolicyEnforced", metav1.ConditionTrue, "SessionsRevoked", fmt.Sprintf("existing sessions revoked after MFA policy changed from %q to %q", realm.Status.AppliedMFAPolicy, desired.MFAPolicy))
	if r.Recorder != nil {
		r.Recorder.Eventf(realm, nil, corev1.EventTypeNormal, "SessionsRevoked", "Reconcile", "%s", "Existing realm sessions were revoked after MFA policy strengthening")
	}
	return nil
}

func mfaPolicyStrengthened(previous, desired string) bool {
	// An empty previous value means this operator version has not established a
	// baseline yet. Recording the baseline without a mass logout makes the CRD
	// upgrade backward compatible; every subsequent strengthening is enforced.
	if previous == "" {
		return false
	}
	return mfaPolicyRank(desired) > mfaPolicyRank(previous)
}

func mfaPolicyRank(policy string) int {
	switch policy {
	case "required":
		return 2
	case "optional":
		return 1
	default:
		return 0
	}
}

func normalizedMFAPolicy(policy string) string {
	if policy == "optional" || policy == "required" {
		return policy
	}
	return "none"
}

func (r *HankoRealmReconciler) markRealmGeneration(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, patch client.Patch) (client.Patch, error) {
	if realm.Status.ObservedGeneration == realm.Generation {
		return patch, nil
	}
	realm.Status.Phase = "Reconciling"
	realm.Status.ObservedGeneration = realm.Generation
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "Reconciling", "applying the current HankoRealm generation to Keycloak")
	if err := r.Status().Patch(ctx, realm, patch); err != nil {
		return patch, fmt.Errorf("mark realm generation reconciling: %w", err)
	}
	return client.MergeFrom(realm.DeepCopy()), nil
}

func (r *HankoRealmReconciler) waitForRealmTheme(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, patch client.Patch) (bool, ctrl.Result, error) {
	ready, requeue, err := r.reconcileThemeReadiness(ctx, realm)
	if err != nil {
		realm.Status.Phase = "Error"
		setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionFalse, "ThemeLookupFailed", err.Error())
		_ = r.Status().Patch(ctx, realm, patch)
		return true, ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("check realm theme readiness: %w", err)
	}
	if ready {
		return false, ctrl.Result{}, nil
	}
	if err := r.Status().Patch(ctx, realm, patch); err != nil {
		return true, ctrl.Result{}, err
	}
	return true, ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *HankoRealmReconciler) ensureRealmAndManagementAccess(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, profile *hankoshv1alpha1.RealmSecurityProfile, kc *keycloak.Client, patch client.Patch) (*keycloak.Realm, error) {
	_, err := kc.GetRealm(ctx, realm.Name)
	if keycloak.IsNotFound(err) {
		if createErr := kc.CreateRealm(ctx, realmSpecWithSecurity(realm, profile)); createErr != nil {
			return nil, r.realmSyncError(ctx, realm, patch, fmt.Errorf("create realm in keycloak: %w", createErr), "patch status after create failure")
		}
		log.FromContext(ctx).Info("HankoRealm created in Keycloak", "realm", realm.Name)
	} else if err != nil {
		return nil, r.realmSyncError(ctx, realm, patch, fmt.Errorf("get realm from keycloak: %w", err), "patch status")
	}
	if err := kc.EnsureRealmManagementAccess(ctx, realm.Name); err != nil {
		return nil, r.realmSyncError(ctx, realm, patch, fmt.Errorf("ensure realm management access: %w", err), "patch status after realm access failure")
	}
	providerRealm, err := kc.GetRealm(ctx, realm.Name)
	if err != nil {
		return nil, fmt.Errorf("get realm after ensuring management access: %w", err)
	}
	return providerRealm, nil
}

func (r *HankoRealmReconciler) realmSyncError(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, patch client.Patch, err error, patchMessage string) error {
	realm.Status.Phase = "Error"
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "KeycloakError", err.Error())
	if patchErr := r.Status().Patch(ctx, realm, patch); patchErr != nil {
		log.FromContext(ctx).Error(patchErr, patchMessage)
	}
	return err
}

func (r *HankoRealmReconciler) applyManagedRealmConfiguration(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, profile *hankoshv1alpha1.RealmSecurityProfile, kc *keycloak.Client, patch client.Patch) (keycloak.RealmSpec, error) {
	desired := realmSpecWithSecurity(realm, profile)
	if err := kc.UpdateRealm(ctx, realm.Name, desired); err != nil {
		return desired, r.realmSyncError(ctx, realm, patch, fmt.Errorf("update realm in keycloak: %w", err), "patch status after update failure")
	}
	return desired, nil
}

func (r *HankoRealmReconciler) reconcileManagedRealmChildren(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, patch client.Patch) error {
	return r.reconcileManagedRealmChildrenWithSecurity(ctx, realm, realm.Spec.SecurityProfile, kc, patch)
}

func (r *HankoRealmReconciler) reconcileManagedRealmChildrenWithSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, security *hankoshv1alpha1.RealmSecurityProfile, kc *keycloak.Client, patch client.Patch) error {
	if err := reconcileRealmRoles(ctx, realm, kc); err != nil {
		realm.Status.Phase = "Error"
		setCondition(&realm.Status.Conditions, "RolesReady", metav1.ConditionFalse, "RoleError", err.Error())
		_ = r.Status().Patch(ctx, realm, patch)
		return fmt.Errorf("reconcile realm roles: %w", err)
	}
	setRealmCollectionCondition(&realm.Status.Conditions, "RolesReady", "NoRolesDeclared", "no realm roles requested", "realm role", len(realm.Spec.Roles))
	if err := r.reconcileRealmIdentityProvidersWithSecurity(ctx, realm, security, kc); err != nil {
		realm.Status.Phase = "Error"
		setCondition(&realm.Status.Conditions, "IdentityProvidersReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		_ = r.Status().Patch(ctx, realm, patch)
		return fmt.Errorf("reconcile realm identity providers: %w", err)
	}
	setRealmCollectionCondition(&realm.Status.Conditions, "IdentityProvidersReady", "NoProvidersDeclared", "no managed identity providers requested", "identity provider", len(realm.Spec.IdentityProviders))
	return nil
}

func setRealmCollectionCondition(conditions *[]metav1.Condition, conditionType, emptyReason, emptyMessage, resourceName string, count int) {
	if count == 0 {
		setCondition(conditions, conditionType, metav1.ConditionTrue, emptyReason, emptyMessage)
		return
	}
	setCondition(conditions, conditionType, metav1.ConditionTrue, "Reconciled", fmt.Sprintf("%d %s(s) reconciled", count, resourceName))
}

func (r *HankoRealmReconciler) reconcileManagedRealmSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, desired keycloak.RealmSpec, patch client.Patch) (bool, ctrl.Result, error) {
	if err := kc.ConfigureRealmEvents(ctx, realm.Name, desired); err != nil {
		if hasOperationalSecurityControls(realm.Spec.SecurityProfile) || hasOperationalSecuritySpec(desired) {
			result, reconcileErr := r.failOperationalSecurity(ctx, realm, patch, "AuditPolicyFailed", err)
			return true, result, reconcileErr
		}
		log.FromContext(ctx).Error(err, "failed to configure legacy realm events (non-fatal)", "realm", realm.Name)
	}
	if err := kc.ConfigureAdminConsoleExposure(ctx, realm.Name, desired.AdminConsoleExposure); err != nil {
		result, reconcileErr := r.failOperationalSecurity(ctx, realm, patch, "AdminConsolePolicyFailed", err)
		return true, result, reconcileErr
	}
	if err := kc.ConfigureIdentityProviderTrust(ctx, realm.Name, desired.IDPBrokerRequireSignature, desired.IDPBrokerTrustEmail); err != nil {
		result, reconcileErr := r.failOperationalSecurity(ctx, realm, patch, "IdentityProviderTrustFailed", err)
		return true, result, reconcileErr
	}
	if hasOperationalSecurityControls(realm.Spec.SecurityProfile) || hasOperationalSecuritySpec(desired) {
		setCondition(&realm.Status.Conditions, "OperationalSecurity", metav1.ConditionTrue, "Reconciled", "audit lifecycle, admin console and broker trust reconciled; client rotation default published")
	}
	return false, ctrl.Result{}, nil
}

func hasOperationalSecuritySpec(spec keycloak.RealmSpec) bool {
	return spec.EventsEnabled != nil || spec.AdminEventsEnabled != nil || spec.AuditRetentionDays != nil ||
		spec.AuditExportEnabled != nil || spec.AdminConsoleExposure != "" ||
		spec.IDPBrokerRequireSignature != nil || spec.IDPBrokerTrustEmail != nil
}

// reconcileRealmObserve reports whether an imported realm still exists without
// changing the realm, its security settings, roles, events, or management access.
func (r *HankoRealmReconciler) reconcileRealmObserve(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, patch client.Patch) (ctrl.Result, error) {
	observed, err := kc.GetRealm(ctx, realm.Name)
	if err != nil {
		realm.Status.Phase = "Error"
		if keycloak.IsNotFound(err) {
			setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "NotFound",
				"observed realm does not exist in Keycloak")
			if patchErr := r.Status().Patch(ctx, realm, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
		}
		setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "KeycloakError", err.Error())
		_ = r.Status().Patch(ctx, realm, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("observe: get realm %q: %w", realm.Name, err)
	}

	now := metav1.Now()
	realm.Status.Phase = "Ready"
	realm.Status.ObservedGeneration = realm.Generation
	realm.Status.KeycloakRealmID = observed.ID
	realm.Status.LastReconciled = &now
	setRealmSMTPCondition(&realm.Status.Conditions, observed.SMTPServer)
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionTrue, "Observed",
		"realm observed in Keycloak — imported realms are read-only")

	if err := r.Status().Patch(ctx, realm, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch observed realm status: %w", err)
	}
	log.FromContext(ctx).Info("HankoRealm observed", "realm", realm.Name)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func setRealmSMTPCondition(conditions *[]metav1.Condition, smtp map[string]string) {
	host := strings.TrimSpace(smtp["host"])
	from := strings.TrimSpace(smtp["from"])
	if host == "" || from == "" {
		setCondition(conditions, "EmailDeliveryReady", metav1.ConditionFalse, "RealmSMTPNotConfigured",
			"the Keycloak realm has no complete SMTP configuration")
		return
	}
	setCondition(conditions, "EmailDeliveryReady", metav1.ConditionTrue, "RealmSMTPConfigured",
		"the Keycloak realm owns its SMTP configuration; Hanko does not replace it with the platform Graph provider")
}

func reconcileRealmRoles(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client) error {
	// Create or update every role before adding composites so references can be
	// declared in any order in the HankoRealm manifest.
	for _, role := range realm.Spec.Roles {
		if err := kc.EnsureRealmRole(ctx, realm.Name, role.Name, role.Description); err != nil {
			return fmt.Errorf("ensure role %q: %w", role.Name, err)
		}
	}
	for _, role := range realm.Spec.Roles {
		if len(role.Composites) == 0 {
			continue
		}
		if err := kc.EnsureRealmRoleComposites(ctx, realm.Name, role.Name, role.Composites); err != nil {
			return fmt.Errorf("ensure composites for role %q: %w", role.Name, err)
		}
	}
	return nil
}

func (r *HankoRealmReconciler) reconcileRealmIdentityProviders(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client) error {
	return r.reconcileRealmIdentityProvidersWithSecurity(ctx, realm, realm.Spec.SecurityProfile, kc)
}

func (r *HankoRealmReconciler) reconcileRealmIdentityProvidersWithSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, security *hankoshv1alpha1.RealmSecurityProfile, kc *keycloak.Client) error {
	if err := r.findRealmIdentityProviderMapperConflict(ctx, realm); err != nil {
		return err
	}
	previous := append([]hankoshv1alpha1.ManagedRealmIdentityProviderReference(nil), realm.Status.ManagedIdentityProviders...)
	managed := make([]hankoshv1alpha1.ManagedRealmIdentityProviderReference, 0, len(realm.Spec.IdentityProviders))
	seenProviders := make(map[string]struct{}, len(realm.Spec.IdentityProviders))

	for _, provider := range realm.Spec.IdentityProviders {
		providerRef, err := r.reconcileRealmIdentityProviderWithSecurity(ctx, realm, security, kc, provider, managed, previous, seenProviders)
		if err != nil {
			return err
		}
		managed = append(managed, providerRef)
	}

	if err := deleteStaleRealmIdentityProviders(ctx, realm.Name, kc, previous, seenProviders); err != nil {
		return err
	}
	realm.Status.ManagedIdentityProviders = managed
	return nil
}

func (r *HankoRealmReconciler) reconcileRealmIdentityProviderWithSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, security *hankoshv1alpha1.RealmSecurityProfile, kc *keycloak.Client, provider hankoshv1alpha1.RealmIdentityProvider, managed, previous []hankoshv1alpha1.ManagedRealmIdentityProviderReference, seen map[string]struct{}) (hankoshv1alpha1.ManagedRealmIdentityProviderReference, error) { // NOSONAR -- parameters represent distinct trust inputs and immutable history.
	if err := validateRealmIdentityProvider(provider, seen); err != nil {
		return hankoshv1alpha1.ManagedRealmIdentityProviderReference{}, err
	}
	desired, err := r.identityProviderForRealmWithSecurity(ctx, realm, security, provider)
	if err != nil {
		return hankoshv1alpha1.ManagedRealmIdentityProviderReference{}, fmt.Errorf("prepare identity provider %q: %w", provider.Alias, err)
	}
	if _, err := kc.EnsureIdentityProvider(ctx, realm.Name, desired); err != nil {
		return hankoshv1alpha1.ManagedRealmIdentityProviderReference{}, fmt.Errorf("ensure identity provider %q: %w", provider.Alias, err)
	}
	providerRef := hankoshv1alpha1.ManagedRealmIdentityProviderReference{Alias: provider.Alias}
	realm.Status.ManagedIdentityProviders = checkpointManagedRealmIdentityProviders(append(managed, providerRef), previous)
	providerRef, err = reconcileRealmIdentityProviderMappers(ctx, realm, kc, provider, providerRef, managed, previous)
	if err != nil {
		return providerRef, err
	}
	return providerRef, deleteStaleRealmIdentityProviderMappers(ctx, realm.Name, kc, provider.Alias, providerRef.Mappers, previous)
}

func validateRealmIdentityProvider(provider hankoshv1alpha1.RealmIdentityProvider, seen map[string]struct{}) error {
	if strings.TrimSpace(provider.Alias) == "" || strings.TrimSpace(provider.ProviderID) == "" {
		return fmt.Errorf("identity-provider alias and providerID are required")
	}
	if _, duplicate := seen[provider.Alias]; duplicate {
		return fmt.Errorf("duplicate identity-provider alias %q", provider.Alias)
	}
	seen[provider.Alias] = struct{}{}
	return nil
}

func reconcileRealmIdentityProviderMappers(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, kc *keycloak.Client, provider hankoshv1alpha1.RealmIdentityProvider, providerRef hankoshv1alpha1.ManagedRealmIdentityProviderReference, managed, previous []hankoshv1alpha1.ManagedRealmIdentityProviderReference) (hankoshv1alpha1.ManagedRealmIdentityProviderReference, error) {
	seen := make(map[string]struct{}, len(provider.Mappers))
	for _, mapper := range provider.Mappers {
		if strings.TrimSpace(mapper.Name) == "" || strings.TrimSpace(mapper.IdentityProviderMapper) == "" {
			return providerRef, fmt.Errorf("identity provider %q has a mapper without name or implementation", provider.Alias)
		}
		if _, duplicate := seen[mapper.Name]; duplicate {
			return providerRef, fmt.Errorf("identity provider %q has duplicate mapper name %q", provider.Alias, mapper.Name)
		}
		seen[mapper.Name] = struct{}{}
		actual, err := kc.EnsureIdentityProviderMapper(ctx, realm.Name, keycloak.IdentityProviderMapper{
			Name: mapper.Name, IdentityProviderAlias: provider.Alias,
			IdentityProviderMapper: mapper.IdentityProviderMapper, Config: copyStringMap(mapper.Config),
		})
		if err != nil {
			return providerRef, fmt.Errorf("ensure identity provider %q mapper %q: %w", provider.Alias, mapper.Name, err)
		}
		providerRef.Mappers = append(providerRef.Mappers, hankoshv1alpha1.ManagedRealmIdentityProviderMapperReference{Name: mapper.Name, KeycloakID: actual.ID})
		checkpoint := append(managed, providerRef)
		realm.Status.ManagedIdentityProviders = checkpointManagedRealmIdentityProviders(checkpoint, previous)
	}
	return providerRef, nil
}

func deleteStaleRealmIdentityProviderMappers(ctx context.Context, realmName string, kc *keycloak.Client, alias string, current []hankoshv1alpha1.ManagedRealmIdentityProviderMapperReference, previous []hankoshv1alpha1.ManagedRealmIdentityProviderReference) error {
	prior, ok := managedRealmIdentityProvider(previous, alias)
	if !ok {
		return nil
	}
	for _, oldMapper := range prior.Mappers {
		if containsManagedRealmIdentityProviderMapper(current, oldMapper) {
			continue
		}
		if err := kc.DeleteIdentityProviderMapper(ctx, realmName, alias, oldMapper.KeycloakID); err != nil {
			return fmt.Errorf("delete stale mapper %q from identity provider %q: %w", oldMapper.Name, alias, err)
		}
	}
	return nil
}

func deleteStaleRealmIdentityProviders(ctx context.Context, realmName string, kc *keycloak.Client, previous []hankoshv1alpha1.ManagedRealmIdentityProviderReference, seen map[string]struct{}) error {
	for _, oldProvider := range previous {
		if _, keep := seen[oldProvider.Alias]; keep {
			continue
		}
		if err := kc.DeleteIdentityProvider(ctx, realmName, oldProvider.Alias); err != nil {
			return fmt.Errorf("delete stale identity provider %q: %w", oldProvider.Alias, err)
		}
	}
	return nil
}

func (r *HankoRealmReconciler) identityProviderForRealm(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, spec hankoshv1alpha1.RealmIdentityProvider) (keycloak.IdentityProvider, error) {
	return r.identityProviderForRealmWithSecurity(ctx, realm, realm.Spec.SecurityProfile, spec)
}

func (r *HankoRealmReconciler) identityProviderForRealmWithSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, security *hankoshv1alpha1.RealmSecurityProfile, spec hankoshv1alpha1.RealmIdentityProvider) (keycloak.IdentityProvider, error) {
	if _, forbidden := spec.Config["clientSecret"]; forbidden {
		return keycloak.IdentityProvider{}, fmt.Errorf("config.clientSecret is forbidden; use clientSecretRef")
	}
	desired := keycloak.IdentityProvider{
		Alias: spec.Alias, DisplayName: spec.DisplayName, ProviderID: spec.ProviderID,
		Enabled: boolOrDefault(spec.Enabled, true), TrustEmail: boolValue(spec.TrustEmail),
		StoreToken: boolValue(spec.StoreToken), AddReadTokenRoleOnCreate: boolValue(spec.AddReadTokenRoleOnCreate),
		LinkOnly: boolValue(spec.LinkOnly), FirstBrokerLoginFlowAlias: spec.FirstBrokerLoginFlowAlias,
		PostBrokerLoginFlowAlias: spec.PostBrokerLoginFlowAlias, Config: copyStringMap(spec.Config),
	}
	// Realm-wide broker trust controls are security minima and therefore take
	// precedence over a provider declaration. Applying them here also prevents
	// the provider and security reconciliation phases from fighting each other.
	if profile := security; profile != nil {
		if profile.IDPBrokerTrustEmail != nil {
			desired.TrustEmail = *profile.IDPBrokerTrustEmail
		}
		if profile.IDPBrokerRequireSignature != nil {
			if desired.Config == nil {
				desired.Config = map[string]string{}
			}
			desired.Config["validateSignature"] = fmt.Sprintf("%t", *profile.IDPBrokerRequireSignature)
		}
	}
	if spec.ClientSecretRef == nil {
		return desired, nil
	}
	var secret corev1.Secret
	secretName := types.NamespacedName{Name: spec.ClientSecretRef.Name, Namespace: realm.Namespace}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		return keycloak.IdentityProvider{}, fmt.Errorf("read client secret %s/%s: %w", realm.Namespace, spec.ClientSecretRef.Name, err)
	}
	value, ok := secret.Data[spec.ClientSecretRef.Key]
	if !ok || len(value) == 0 {
		return keycloak.IdentityProvider{}, fmt.Errorf("client secret %s/%s key %q is missing or empty", realm.Namespace, spec.ClientSecretRef.Name, spec.ClientSecretRef.Key)
	}
	if desired.Config == nil {
		desired.Config = map[string]string{}
	}
	desired.Config["clientSecret"] = string(value)
	return desired, nil
}

func (r *HankoRealmReconciler) findRealmIdentityProviderMapperConflict(ctx context.Context, realm *hankoshv1alpha1.HankoRealm) error {
	desired := make(map[string]struct{})
	for _, provider := range realm.Spec.IdentityProviders {
		for _, mapper := range provider.Mappers {
			desired[provider.Alias+"\x00"+mapper.Name] = struct{}{}
		}
	}
	if len(desired) == 0 {
		return nil
	}
	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(realm.Namespace)); err != nil {
		return fmt.Errorf("list applications for identity-provider mapper conflicts: %w", err)
	}
	for i := range applications.Items {
		app := &applications.Items[i]
		if app.Spec.RealmRef != realm.Name || effectiveMode(app) != ModeManage {
			continue
		}
		for _, mapping := range app.Spec.IdentityMappings {
			name := identityMappingKeycloakName(app, mapping)
			if _, conflict := desired[mapping.IdentityProvider+"\x00"+name]; conflict {
				return fmt.Errorf("identity-provider mapper %q is already declared by HankoApplication %q", name, app.Name)
			}
		}
	}
	return nil
}

func managedRealmIdentityProvider(items []hankoshv1alpha1.ManagedRealmIdentityProviderReference, alias string) (hankoshv1alpha1.ManagedRealmIdentityProviderReference, bool) {
	for _, item := range items {
		if item.Alias == alias {
			return item, true
		}
	}
	return hankoshv1alpha1.ManagedRealmIdentityProviderReference{}, false
}

func containsManagedRealmIdentityProvider(items []hankoshv1alpha1.ManagedRealmIdentityProviderReference, target hankoshv1alpha1.ManagedRealmIdentityProviderReference) bool {
	_, ok := managedRealmIdentityProvider(items, target.Alias)
	return ok
}

func containsManagedRealmIdentityProviderMapper(items []hankoshv1alpha1.ManagedRealmIdentityProviderMapperReference, target hankoshv1alpha1.ManagedRealmIdentityProviderMapperReference) bool {
	for _, item := range items {
		if item.Name == target.Name && item.KeycloakID == target.KeycloakID {
			return true
		}
	}
	return false
}

func checkpointManagedRealmIdentityProviders(current, previous []hankoshv1alpha1.ManagedRealmIdentityProviderReference) []hankoshv1alpha1.ManagedRealmIdentityProviderReference {
	checkpoint := append([]hankoshv1alpha1.ManagedRealmIdentityProviderReference(nil), current...)
	for _, item := range previous {
		if !containsManagedRealmIdentityProvider(checkpoint, item) {
			checkpoint = append(checkpoint, item)
		}
	}
	return checkpoint
}

func copyStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (r *HankoRealmReconciler) failOperationalSecurity(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, patch client.Patch, reason string, err error) (ctrl.Result, error) {
	realm.Status.Phase = "Error"
	setCondition(&realm.Status.Conditions, "OperationalSecurity", metav1.ConditionFalse, reason, err.Error())
	if patchErr := r.Status().Patch(ctx, realm, patch); patchErr != nil {
		log.FromContext(ctx).Error(patchErr, "patch status after operational security failure")
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("reconcile realm operational security: %w", err)
}

func hasOperationalSecurityControls(profile *hankoshv1alpha1.RealmSecurityProfile) bool {
	return profile != nil && (profile.AuditRetentionDays != nil || profile.AuditExportEnabled != nil ||
		profile.ClientSecretRotationDays != nil || profile.AdminConsoleExposure != "" ||
		profile.IDPBrokerRequireSignature != nil || profile.IDPBrokerTrustEmail != nil)
}

func (r *HankoRealmReconciler) reconcileThemeReadiness(ctx context.Context, realm *hankoshv1alpha1.HankoRealm) (bool, time.Duration, error) {
	if realm.Spec.LoginTheme == "" {
		setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionTrue, "KeycloakDefault",
			"no realm login theme requested; the Keycloak default applies")
		return true, 0, nil
	}

	var theme hankoshv1alpha1.HankoTheme
	err := r.Get(ctx, types.NamespacedName{Name: realm.Spec.LoginTheme, Namespace: realm.Namespace}, &theme)
	if apierrors.IsNotFound(err) {
		setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionUnknown, "ExternalTheme",
			fmt.Sprintf("no HankoTheme %q exists; treating it as an externally installed Keycloak theme", realm.Spec.LoginTheme))
		return true, 0, nil
	}
	if err != nil {
		return false, requeueOnError, err
	}
	if !theme.DeletionTimestamp.IsZero() {
		realm.Status.Phase = "Reconciling"
		setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionFalse, "ThemeDeleting",
			fmt.Sprintf("HankoTheme %q is being deleted", theme.Name))
		return false, requeueOnError, nil
	}
	if theme.Status.Phase == "Ready" && theme.Status.JarPath != "" &&
		theme.Status.ObservedGeneration == theme.Generation {
		setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionTrue, "ManagedThemeReady",
			fmt.Sprintf("HankoTheme %q is installed at %s", theme.Name, theme.Status.JarPath))
		return true, 0, nil
	}

	realm.Status.Phase = "Reconciling"
	reason := "ThemeBuilding"
	message := fmt.Sprintf("waiting for HankoTheme %q to become Ready", theme.Name)
	if theme.Status.Phase == "Error" {
		reason = "ThemeError"
		message = fmt.Sprintf("HankoTheme %q build is in Error", theme.Name)
	}
	setCondition(&realm.Status.Conditions, "ThemeReady", metav1.ConditionFalse, reason, message)
	return false, requeueOnError, nil
}

// SetupWithManager registers the reconciler. Spec generation changes and the
// explicit reconcile-request annotation enqueue the primary resource; ordinary
// status and metadata writes remain filtered to avoid tight reconcile loops.
func (r *HankoRealmReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoRealm{}, builder.WithPredicates(generationOrReconcileRequestChanged())).
		Watches(&hankoshv1alpha1.HankoTheme{}, handler.EnqueueRequestsFromMapFunc(r.realmRequestsForTheme)).
		Watches(&hankoshv1alpha1.HankoIAMProfile{}, handler.EnqueueRequestsFromMapFunc(r.realmRequestsForIAMProfile), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

func (r *HankoRealmReconciler) realmRequestsForIAMProfile(ctx context.Context, obj client.Object) []reconcile.Request {
	profile, ok := obj.(*hankoshv1alpha1.HankoIAMProfile)
	if !ok {
		return nil
	}
	return r.realmRequests(ctx, profile.Namespace, func(realm *hankoshv1alpha1.HankoRealm) bool {
		return realm.Spec.IAMProfileRef == profile.Name
	})
}

func (r *HankoRealmReconciler) realmRequestsForTheme(ctx context.Context, obj client.Object) []reconcile.Request {
	theme, ok := obj.(*hankoshv1alpha1.HankoTheme)
	if !ok {
		return nil
	}
	return r.realmRequests(ctx, theme.Namespace, func(realm *hankoshv1alpha1.HankoRealm) bool {
		return realm.Spec.LoginTheme == theme.Name
	})
}

func (r *HankoRealmReconciler) realmRequests(ctx context.Context, namespace string, matches func(*hankoshv1alpha1.HankoRealm) bool) []reconcile.Request {
	var realms hankoshv1alpha1.HankoRealmList
	if err := r.List(ctx, &realms, client.InNamespace(namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range realms.Items {
		realm := &realms.Items[i]
		if matches(realm) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: realm.Name, Namespace: realm.Namespace}})
		}
	}
	return requests
}

func realmSpec(realm *hankoshv1alpha1.HankoRealm) keycloak.RealmSpec {
	return realmSpecWithSecurity(realm, realm.Spec.SecurityProfile)
}

func realmSpecWithSecurity(realm *hankoshv1alpha1.HankoRealm, profile *hankoshv1alpha1.RealmSecurityProfile) keycloak.RealmSpec {
	rs := keycloak.RealmSpec{
		ID:          realm.Name,
		DisplayName: realm.Spec.DisplayName,
		FrontendURL: realm.Spec.FrontendURL,
		LoginTheme:  realm.Spec.LoginTheme,
		Enabled:     true,
	}
	if profile != nil {
		applyRealmSecurityProfile(&rs, profile)
	}
	// Legacy OTPRequired: only applies when SecurityProfile does not override.
	if realm.Spec.OTPRequired {
		if rs.MFAPolicy == "" {
			rs.MFAPolicy = "required"
		}
		if rs.PasswordPolicy == "" {
			rs.PasswordPolicy = "length(8)"
		}
	}
	return rs
}

func applyRealmSecurityProfile(spec *keycloak.RealmSpec, profile *hankoshv1alpha1.RealmSecurityProfile) {
	spec.MFAPolicy = profile.MFAPolicy
	if profile.PasswordMinLength > 0 {
		spec.PasswordPolicy = realmPasswordPolicy(profile)
	}
	applyRealmBruteForce(spec, profile.BruteForce)
	spec.SSOSessionMaxLifespan = durationSeconds(profile.SessionLifetime)
	spec.SSOSessionIdleTimeout = durationSeconds(profile.SessionIdleTimeout)
	if profile.SSLRequired != "" {
		spec.SSLRequired = profile.SSLRequired
	}
	spec.RevokeRefreshToken = profile.RevokeRefreshToken
	spec.RefreshTokenMaxReuse = profile.RefreshTokenMaxReuse
	if profile.OTPAlgorithm != "" {
		spec.OTPAlgorithm = profile.OTPAlgorithm
	}
	spec.OTPDigits = profile.OTPDigits
	spec.OTPPeriod = profile.OTPPeriodSeconds
	spec.VerifyEmail = profile.EmailVerificationRequired
	spec.RememberMe = profile.RememberMeEnabled
	spec.RegistrationAllowed = profile.UserRegistrationEnabled
	spec.EventsEnabled = profile.UserEventsEnabled
	spec.AdminEventsEnabled = profile.AdminEventsEnabled
	spec.AuditRetentionDays = profile.AuditRetentionDays
	spec.AuditExportEnabled = profile.AuditExportEnabled
	spec.AdminConsoleExposure = profile.AdminConsoleExposure
	spec.IDPBrokerRequireSignature = profile.IDPBrokerRequireSignature
	spec.IDPBrokerTrustEmail = profile.IDPBrokerTrustEmail
}

func applyRealmBruteForce(spec *keycloak.RealmSpec, bruteForce *hankoshv1alpha1.BruteForcePolicy) {
	if bruteForce == nil || !bruteForce.Enabled {
		return
	}
	spec.BruteForceProtected = true
	spec.FailureFactor = bruteForce.MaxFailures
	spec.WaitIncrementSeconds = durationSeconds(bruteForce.WaitIncrements)
}

func durationSeconds(value string) int {
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return int(duration.Seconds())
}

func realmPasswordPolicy(profile *hankoshv1alpha1.RealmSecurityProfile) string {
	parts := []string{fmt.Sprintf("length(%d)", profile.PasswordMinLength)}
	if profile.PasswordRequireUppercase == nil || boolValue(profile.PasswordRequireUppercase) {
		parts = append(parts, "upperCase(1)")
	}
	if profile.PasswordRequireLowercase == nil || boolValue(profile.PasswordRequireLowercase) {
		parts = append(parts, "lowerCase(1)")
	}
	if profile.PasswordRequireDigit == nil || boolValue(profile.PasswordRequireDigit) {
		parts = append(parts, "digits(1)")
	}
	if boolValue(profile.PasswordRequireSpecial) {
		parts = append(parts, "specialChars(1)")
	}
	if profile.PasswordDisallowUsername == nil || boolValue(profile.PasswordDisallowUsername) {
		parts = append(parts, "notUsername(undefined)")
	}
	if boolValue(profile.PasswordDisallowEmail) {
		parts = append(parts, "notEmail(undefined)")
	}
	if profile.PasswordHistory != nil && *profile.PasswordHistory > 0 {
		parts = append(parts, fmt.Sprintf("passwordHistory(%d)", *profile.PasswordHistory))
	} else if profile.PasswordHistory == nil {
		parts = append(parts, "passwordHistory(3)")
	}
	if profile.PasswordExpiryDays > 0 {
		parts = append(parts, fmt.Sprintf("forceExpiredPasswordChange(%d)", profile.PasswordExpiryDays))
	}
	return strings.Join(parts, " and ")
}

func boolValue(value *bool) bool {
	return value != nil && *value
}
