package controller

import (
	"context"
	"crypto/sha256"
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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const finalizerName = "hanko.sh/client-cleanup"

const (
	clientSecretProjectionLabel          = "hanko.sh/client-secret-projection"
	clientSecretProjectionOwnerName      = "hanko.sh/application-name"
	clientSecretProjectionOwnerNamespace = "hanko.sh/application-namespace"
	clientSecretProjectionOwnerUID       = "hanko.sh/application-uid"
	clientSecretProjectionClientID       = "hanko.sh/client-id"
	clientSecretProjectionSourceSecret   = "hanko.sh/source-secret"
)

var reservedTokenClaims = map[string]struct{}{
	"sub": {}, "iss": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"azp": {}, "typ": {}, "sid": {}, "scope": {}, "session_state": {},
	"nonce": {}, "auth_time": {}, "acr": {}, "amr": {}, "at_hash": {},
	"c_hash": {}, "s_hash": {}, "client_id": {}, "hanko_token_use": {},
	"realm_access": {}, "resource_access": {}, "authorization": {},
	"permissions": {}, "https://hanko.sh/authorization": {}, "cnf": {},
	"act": {}, "may_act": {}, "authorization_details": {},
}

var structuredReservedTokenClaims = []string{
	"realm_access",
	"resource_access",
	"authorization",
	"permissions",
	"https://hanko.sh/authorization",
	"cnf",
	"act",
	"may_act",
	"authorization_details",
}

type tokenClaimOwner struct {
	uid        string
	namespace  string
	name       string
	generation int64
	realm      string
	clientID   string
}

// HankoApplicationReconciler reconciles HankoApplication objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoserviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
type HankoApplicationReconciler struct {
	client.Client
	// OwnershipReader should be the manager's uncached API reader in production.
	// It closes the cache-staleness window before finalizer, provider or secret
	// mutations involving a logically shared Keycloak client.
	OwnershipReader        client.Reader
	SecretProjectionClient client.Client
	// RuntimeClient is an uncached client with namespace-scoped target RBAC.
	RuntimeClient client.Client
	// ProtectedClientIDs are control-plane clients in ProtectedRealm. They may
	// be owned by one deterministic HankoApplication, but never by a
	// HankoServiceAccount.
	ProtectedClientIDs []string
	ProtectedRealm     string
	Scheme             *runtime.Scheme
	Pool               *keycloak.Pool
	Recorder           events.EventRecorder
}

func (r *HankoApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var app hankoshv1alpha1.HankoApplication
	if err := r.Get(ctx, req.NamespacedName, &app); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	kc := kcForObject(r.Pool, app.Namespace, app.Labels)
	mode := effectiveMode(&app)
	if mode == ModeObserve && app.Annotations[applicationbinding.JournalAnnotation] != "" {
		return r.runtimeCleanupFailure(ctx, &app, &applicationbinding.Failure{Reason: "CleanupConflict"})
	}
	if !app.DeletionTimestamp.IsZero() && mode == ModeManage && app.Annotations[applicationbinding.JournalAnnotation] != "" {
		if err := r.cleanupRuntimeApplication(ctx, &app); err != nil {
			return r.runtimeCleanupFailure(ctx, &app, err)
		}
	}
	if app.DeletionTimestamp.IsZero() {
		if err := validateApplicationProtocol(&app); err != nil {
			return r.applicationContractError(ctx, &app, client.MergeFrom(app.DeepCopy()), nil, nil, err)
		}
	}
	protectedApplication := isProtectedControlPlaneApplication(r.ProtectedRealm, r.ProtectedClientIDs, &app)
	if protectedApplication && !app.DeletionTimestamp.IsZero() {
		return r.releaseProtectedApplication(ctx, &app)
	}
	if mode == ModeManage {
		patch := client.MergeFrom(app.DeepCopy())
		if protectedApplication && (app.Name != app.Spec.ClientID || !isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, app.Spec.RealmRef, app.Name)) {
			message := fmt.Sprintf("protected control-plane client %q must be owned by the canonical HankoApplication of the same name", app.Spec.ClientID)
			return r.recordApplicationConflict(ctx, &app, patch, "ProtectedClientOwner", message)
		}
		if err := validateApplicationAuthorityRoles(&app, r.ProtectedRealm); err != nil {
			if !app.DeletionTimestamp.IsZero() {
				return r.releaseConflictingApplication(ctx, &app, err.Error())
			}
			return r.recordApplicationConflict(ctx, &app, patch, "ReservedAuthorityRole", err.Error())
		}
		if err := validateApplicationEffectiveAuthorityRoles(ctx, &app, r.ProtectedRealm, r.ProtectedClientIDs, kc); err != nil {
			if !app.DeletionTimestamp.IsZero() {
				if isReservedAuthorityRoleViolation(err) {
					return r.releaseConflictingApplication(ctx, &app, err.Error())
				}
				return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify application authority roles before deletion: %w", err)
			}
			if isReservedAuthorityRoleViolation(err) {
				return r.recordApplicationConflict(ctx, &app, patch, "ReservedAuthorityRole", err.Error())
			}
			app.Status.Phase = "Error"
			app.Status.ObservedGeneration = app.Generation
			markRuntimePending(&app, "ApplicationNotReady")
			setCondition(&app.Status.Conditions, "Synced", metav1.ConditionFalse, "AuthorityRoleLookupFailed", err.Error())
			if patchErr := r.Status().Patch(ctx, &app, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify application authority roles: %w", err)
		}
		reason, ownershipConflict, err := r.applicationOwnershipConflict(ctx, &app, kc)
		if err != nil {
			return r.applicationContractError(ctx, &app, patch, nil, nil, err)
		}
		if ownershipConflict != "" {
			if !app.DeletionTimestamp.IsZero() {
				return r.releaseConflictingApplication(ctx, &app, ownershipConflict)
			}
			return r.recordApplicationConflict(ctx, &app, patch, reason, ownershipConflict)
		}
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !app.DeletionTimestamp.IsZero() {
		return r.reconcileApplicationDeletion(ctx, &app, kc, mode)
	}

	// ── Ensure finalizer is registered (Manage only — Observe must never gain
	// the destructive finalizer, even implicitly) ────────────────────────────
	if mode == ModeManage && !controllerutil.ContainsFinalizer(&app, finalizerName) {
		controllerutil.AddFinalizer(&app, finalizerName)
		if err := r.Update(ctx, &app); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	patch := client.MergeFrom(app.DeepCopy())

	// ── Conflict guard: two Manage objects must never both write the same
	// (realmRef, clientID). No Keycloak mutation call is made while conflicting. ─
	if mode == ModeManage {
		handled, result, err := r.reconcileApplicationConflicts(ctx, &app, patch)
		if err != nil || handled {
			return result, err
		}
	}

	// ── Observe mode: read-only status reporting, no writes, no secret reads ──
	if mode == ModeObserve {
		if len(app.Spec.ClientSecretProjections) != 0 {
			err := fmt.Errorf("client secret projections require Manage mode for %q", app.Spec.ClientID)
			app.Status.Phase = "Error"
			app.Status.ObservedGeneration = app.Generation
			setCondition(&app.Status.Conditions, "SecretProjections", metav1.ConditionFalse, "Invalid", err.Error())
			_ = r.Status().Patch(ctx, &app, patch)
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		return r.reconcileObserve(ctx, &app, kc, patch)
	}
	return r.reconcileManagedApplication(ctx, &app, kc, patch)
}

func isProtectedControlPlaneApplication(protectedRealm string, protectedClientIDs []string, app *hankoshv1alpha1.HankoApplication) bool {
	if app == nil || strings.TrimSpace(app.Spec.RealmRef) != strings.TrimSpace(protectedRealm) {
		return false
	}
	if isProtectedControlPlaneClient(protectedRealm, protectedClientIDs, app.Spec.RealmRef, app.Spec.ClientID) {
		return true
	}
	for _, clientID := range protectedClientIDs {
		if app.Name == strings.TrimSpace(clientID) {
			return true
		}
	}
	return false
}

func (r *HankoApplicationReconciler) releaseProtectedApplication(ctx context.Context, app *hankoshv1alpha1.HankoApplication) (ctrl.Result, error) {
	message := fmt.Sprintf("protected control-plane client %q was not cleaned up or deleted from Keycloak", app.Spec.ClientID)
	patch := client.MergeFrom(app.DeepCopy())
	app.Status.Phase = "Error"
	app.Status.ObservedGeneration = app.Generation
	setCondition(&app.Status.Conditions, "Synced", metav1.ConditionFalse, "ProtectedControlPlaneClient", message)
	if err := r.Status().Patch(ctx, app, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("record protected control-plane client deletion: %w", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(app, nil, corev1.EventTypeWarning, "ProtectedControlPlaneClient", "Reconcile", "%s", message)
	}
	if controllerutil.ContainsFinalizer(app, finalizerName) {
		controllerutil.RemoveFinalizer(app, finalizerName)
		if err := r.Update(ctx, app); err != nil {
			return ctrl.Result{}, fmt.Errorf("release protected control-plane client finalizer: %w", err)
		}
	}
	log.FromContext(ctx).Info(message)
	return ctrl.Result{}, nil
}

func (r *HankoApplicationReconciler) reconcileManagedApplication(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client, patch client.Patch) (ctrl.Result, error) {
	if len(app.Spec.ClientSecretProjections) != 0 && app.Spec.Type != "web" && app.Spec.Type != "m2m" {
		err := fmt.Errorf("client secret projections require confidential web or m2m client %q", app.Spec.ClientID)
		app.Status.Phase = "Error"
		app.Status.ObservedGeneration = app.Generation
		setCondition(&app.Status.Conditions, "SecretProjections", metav1.ConditionFalse, "Invalid", err.Error())
		_ = r.Status().Patch(ctx, app, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	// Validate every requested token mapper before making any provider call.
	// Admission normally enforces the same constraints through CRD CEL rules;
	// this is the defense-in-depth boundary for objects written without the API.
	if invalidClaims, err := preflightTokenClaims(app.Namespace, app.Name, app.Generation, app.Spec.TokenClaims, app.Status.ManagedTokenClaims); err != nil {
		app.Status.Phase = "Error"
		app.Status.ObservedGeneration = app.Generation
		app.Status.ManagedTokenClaims = invalidClaims
		markRuntimePending(app, "ApplicationNotReady")
		setCondition(&app.Status.Conditions, "Mappings", metav1.ConditionFalse, "Invalid", err.Error())
		_ = r.Status().Patch(ctx, app, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("validate token claims for %q: %w", app.Spec.ClientID, err)
	}

	// A declared HankoTheme is the managed build dependency for spec.theme.
	// Gate Keycloak assignment until the matching JAR is Ready. For backward
	// compatibility, a theme name with no HankoTheme object is treated as an
	// externally installed theme and remains assignable with ConditionUnknown.
	themeReady, themeRequeue, err := r.reconcileThemeReadiness(ctx, app)
	if err != nil {
		app.Status.Phase = "Error"
		app.Status.ObservedGeneration = app.Generation
		markRuntimePending(app, "ApplicationNotReady")
		setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionFalse, "ThemeLookupFailed", err.Error())
		_ = r.Status().Patch(ctx, app, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("check theme readiness: %w", err)
	}
	if !themeReady {
		markRuntimePending(app, "ApplicationNotReady")
		if err := r.Status().Patch(ctx, app, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: themeRequeue}, nil
	}
	return r.reconcileApplicationContract(ctx, app, kc, patch, false)
}

func (r *HankoApplicationReconciler) reconcileApplicationDeletion(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client, mode string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(app, finalizerName) {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)
	if mode == ModeManage {
		plan, err := applicationDeletionPlan(app)
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		driver := applications.NewKeycloakDriver(kc)
		state, err := driver.CheckOwned(ctx, plan)
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		if state.Present && !state.Owned {
			return r.releaseConflictingApplication(ctx, app, "provider UID ownership does not authorize deletion")
		}
		if err := r.cleanupSecretProjections(ctx, app); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete client secret projections: %w", err)
		}
		if err := r.cleanupApplicationMappings(ctx, app, kc); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete application mappers: %w", err)
		}
		logger.Info("deleting Keycloak client", "clientID", app.Spec.ClientID)
		if err := driver.DeleteOwned(ctx, plan); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete client %q from keycloak: %w", app.Spec.ClientID, err)
		}
	} else {
		logger.Info("Observe mode: dropping legacy finalizer without deleting Keycloak client", "clientID", app.Spec.ClientID)
	}
	controllerutil.RemoveFinalizer(app, finalizerName)
	if err := r.Update(ctx, app); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	logger.Info("finalizer removed", "clientID", app.Spec.ClientID, "mode", mode)
	return ctrl.Result{}, nil
}

func (r *HankoApplicationReconciler) reconcileApplicationConflicts(ctx context.Context, app *hankoshv1alpha1.HankoApplication, patch client.Patch) (bool, ctrl.Result, error) {
	mappingConflict, otherName, mapperName, err := r.findIdentityMappingConflict(ctx, app)
	if err != nil {
		return true, ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("check identity mapping conflict: %w", err)
	}
	if mappingConflict {
		message := fmt.Sprintf("another Manage object %q already governs identity-provider mapper %q in realm %q", otherName, mapperName, app.Spec.RealmRef)
		result, err := r.recordApplicationConflict(ctx, app, patch, "DuplicateMapperManager", message)
		return true, result, err
	}
	setCondition(&app.Status.Conditions, "Conflict", metav1.ConditionFalse, "NoConflict",
		"no other Manage object governs this realm/clientID or its identity-provider mapper names")
	return false, ctrl.Result{}, nil
}

func (r *HankoApplicationReconciler) applicationOwnershipConflict(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) (string, string, error) {
	clientID := strings.TrimSpace(app.Spec.ClientID)
	if keycloakInternalClients[clientID] {
		return "ReservedClient", fmt.Sprintf("client %q is a built-in Keycloak client and cannot be governed by HankoApplication", app.Spec.ClientID), nil
	}
	if kc != nil {
		credentialClientID := strings.TrimSpace(kc.CredentialClientID())
		if credentialClientID != "" && clientID == credentialClientID {
			return "ReservedClient", fmt.Sprintf("client %q authorizes this operator and cannot be governed by HankoApplication", app.Spec.ClientID), nil
		}
	}

	reader := client.Reader(r.Client)
	if r.OwnershipReader != nil {
		reader = r.OwnershipReader
	}
	candidates := []clientOwnershipCandidate{newClientOwnershipCandidate("HankoApplication", app)}
	var applications hankoshv1alpha1.HankoApplicationList
	if err := reader.List(ctx, &applications, client.InNamespace(app.Namespace)); err != nil {
		return "", "", fmt.Errorf("list HankoApplication ownership candidates: %w", err)
	}
	for i := range applications.Items {
		other := &applications.Items[i]
		if other.Name == app.Name || effectiveMode(other) != ModeManage || !sameClientIdentity(other.Spec.RealmRef, other.Spec.ClientID, app.Spec.RealmRef, clientID) {
			continue
		}
		candidates = append(candidates, newClientOwnershipCandidate("HankoApplication", other))
	}

	var accounts hankoshv1alpha1.HankoServiceAccountList
	if err := reader.List(ctx, &accounts, client.InNamespace(app.Namespace)); err != nil {
		return "", "", fmt.Errorf("list HankoServiceAccount ownership candidates: %w", err)
	}
	// Fleet-authority clients are application-owned by definition. The service
	// account reconciler rejects them, so a stale or legacy HSA must not displace
	// the authoritative application declaration. We still perform the live list
	// above and fail closed if the ownership API is unavailable.
	if !isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, app.Spec.RealmRef, clientID) {
		for i := range accounts.Items {
			account := &accounts.Items[i]
			if isImported(account.Labels) || !sameClientIdentity(account.Spec.RealmRef, account.Spec.ClientID, app.Spec.RealmRef, clientID) {
				continue
			}
			candidates = append(candidates, newClientOwnershipCandidate("HankoServiceAccount", account))
		}
	}

	winner := clientOwnershipWinner(candidates)
	if winner.kind == "HankoApplication" && winner.name == app.Name {
		return "", "", nil
	}
	reason := "CrossKindOwnershipConflict"
	if winner.kind == "HankoApplication" {
		reason = "DuplicateManager"
	}
	return reason, fmt.Sprintf("%s %q is the deterministic owner of realm %q client %q", winner.kind, winner.name, app.Spec.RealmRef, app.Spec.ClientID), nil
}

func (r *HankoApplicationReconciler) releaseConflictingApplication(ctx context.Context, app *hankoshv1alpha1.HankoApplication, message string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(app, finalizerName) {
		return ctrl.Result{}, nil
	}
	controllerutil.RemoveFinalizer(app, finalizerName)
	if err := r.Update(ctx, app); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove conflicting application finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released conflicting application without deleting Keycloak client", "clientID", app.Spec.ClientID, "reason", message)
	return ctrl.Result{}, nil
}

func (r *HankoApplicationReconciler) recordApplicationConflict(ctx context.Context, app *hankoshv1alpha1.HankoApplication, patch client.Patch, reason, message string) (ctrl.Result, error) {
	markRuntimePending(app, "ApplicationNotReady")
	app.Status.Phase = "Conflict"
	app.Status.ObservedGeneration = app.Generation
	setCondition(&app.Status.Conditions, "Synced", metav1.ConditionFalse, "Conflict", message)
	setCondition(&app.Status.Conditions, "Conflict", metav1.ConditionTrue, reason, message)
	if err := r.Status().Patch(ctx, app, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("Manage conflict detected — skipping all Keycloak calls", "clientID", app.Spec.ClientID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func setApplicationSecretStatus(app *hankoshv1alpha1.HankoApplication, rotatedAt *metav1.Time, policy *hankoshv1alpha1.SecretRotationPolicy) {
	app.Status.ClientSecret = &hankoshv1alpha1.SecretReference{SecretRef: corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: secretName(app.Spec.ClientID)}, Key: "client_secret",
	}}
	app.Status.LastRotated = rotatedAt
	setApplicationNextRotation(app, policy)
}

func setApplicationNextRotation(app *hankoshv1alpha1.HankoApplication, policy *hankoshv1alpha1.SecretRotationPolicy) {
	if policy == nil || !policy.Enabled || policy.IntervalDays <= 0 || app.Status.LastRotated == nil {
		app.Status.NextRotation = nil
		return
	}
	next := metav1.NewTime(app.Status.LastRotated.AddDate(0, 0, policy.IntervalDays))
	app.Status.NextRotation = &next
}

// ensureSecret verifies the K8s Secret exists for confidential clients and recovers
// it from Keycloak if it was deleted while the Keycloak client still exists.
func (r *HankoApplicationReconciler) ensureSecret(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	if app.Spec.Type == "spa" || isSAMLApplication(app) {
		return nil // public/SAML client — no secret
	}
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: secretName(app.Spec.ClientID), Namespace: app.Namespace}, &s)
	if err == nil {
		recoverApplicationRotationCheckpoint(app, &s)
		current := string(s.Data["client_secret"])
		if current == "" {
			current = s.StringData["client_secret"]
		}
		if current != "" {
			return r.reconcileSecretProjections(ctx, app, current)
		}
	}
	if err != nil && client.IgnoreNotFound(err) != nil {
		return err
	}
	// Secret is missing or malformed — fetch the current value from Keycloak
	// without rotating, then repair the canonical and projected copies.
	current, fetchErr := kc.GetClientSecret(ctx, app.Spec.RealmRef, app.Spec.ClientID)
	if fetchErr != nil {
		return fmt.Errorf("recover secret for %q: %w", app.Spec.ClientID, fetchErr)
	}
	if err := r.upsertSecret(ctx, app, current); err != nil {
		return err
	}
	app.Status.ClientSecret = &hankoshv1alpha1.SecretReference{
		SecretRef: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: secretName(app.Spec.ClientID)},
			Key:                  "client_secret",
		},
	}
	return nil
}

func (r *HankoApplicationReconciler) maybeRotateApplicationSecret(ctx context.Context, app *hankoshv1alpha1.HankoApplication, policy *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time, kc *keycloak.Client) error {
	if policy == nil || !policy.Enabled {
		app.Status.NextRotation = nil
		return nil
	}
	if app.Spec.Type == "spa" {
		return fmt.Errorf("secret rotation is unavailable for public SPA client %q", app.Spec.ClientID)
	}

	if !applicationRotationDue(app, policy, now) {
		setApplicationNextRotation(app, policy)
		return nil
	}

	secret, err := kc.RotateClientSecret(ctx, app.Spec.RealmRef, app.Spec.ClientID)
	if err != nil {
		return fmt.Errorf("rotate secret for %q: %w", app.Spec.ClientID, err)
	}
	// Persist the non-secret rotation checkpoint with the canonical credential.
	// A later runtime/status failure must not repeat this provider rotation.
	app.Status.LastRotated = now
	if err := r.upsertSecret(ctx, app, secret); err != nil {
		return err
	}
	app.Status.LastRotated = now
	setApplicationNextRotation(app, policy)
	setCondition(&app.Status.Conditions, "SecretRotation", metav1.ConditionTrue, "Rotated", "confidential client secret rotated")
	if r.Recorder != nil {
		r.Recorder.Eventf(app, nil, corev1.EventTypeNormal, "SecretRotated", "Reconcile", "%s", fmt.Sprintf("client secret rotated for %q", app.Spec.ClientID))
	}
	return nil
}

func applicationRotationDue(app *hankoshv1alpha1.HankoApplication, policy *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time) bool {
	if policy.ForceRotateAt != nil && !policy.ForceRotateAt.IsZero() && now.After(policy.ForceRotateAt.Time) &&
		(app.Status.LastRotated == nil || app.Status.LastRotated.Before(policy.ForceRotateAt)) {
		return true
	}
	if policy.IntervalDays <= 0 {
		return false
	}
	if app.Status.LastRotated == nil {
		return true
	}
	return now.After(app.Status.LastRotated.AddDate(0, 0, policy.IntervalDays))
}

// findIdentityMappingConflict prevents two Manage objects (applications or the
// parent realm) from reconciling the same realm-scoped mapper name.
func (r *HankoApplicationReconciler) findIdentityMappingConflict(ctx context.Context, app *hankoshv1alpha1.HankoApplication) (bool, string, string, error) {
	if len(app.Spec.IdentityMappings) == 0 {
		return false, "", "", nil
	}
	desired := desiredIdentityMappingNames(app)
	conflict, owner, mapper, err := r.realmIdentityMappingConflict(ctx, app, desired)
	if err != nil || conflict {
		return conflict, owner, mapper, err
	}
	return r.applicationIdentityMappingConflict(ctx, app, desired)
}

func desiredIdentityMappingNames(app *hankoshv1alpha1.HankoApplication) map[string]string {
	desired := make(map[string]string, len(app.Spec.IdentityMappings))
	for _, mapping := range app.Spec.IdentityMappings {
		name := identityMappingKeycloakName(app, mapping)
		desired[mapping.IdentityProvider+"\x00"+name] = name
	}
	return desired
}

func (r *HankoApplicationReconciler) realmIdentityMappingConflict(ctx context.Context, app *hankoshv1alpha1.HankoApplication, desired map[string]string) (bool, string, string, error) {
	var realm hankoshv1alpha1.HankoRealm
	if err := r.Get(ctx, types.NamespacedName{Name: app.Spec.RealmRef, Namespace: app.Namespace}, &realm); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, "", "", err
		}
		return false, "", "", nil
	}
	if isImported(realm.Labels) {
		return false, "", "", nil
	}
	for _, provider := range realm.Spec.IdentityProviders {
		for _, mapper := range provider.Mappers {
			if managedName, exists := desired[provider.Alias+"\x00"+mapper.Name]; exists {
				return true, "HankoRealm/" + realm.Name, managedName, nil
			}
		}
	}
	return false, "", "", nil
}

func (r *HankoApplicationReconciler) applicationIdentityMappingConflict(ctx context.Context, app *hankoshv1alpha1.HankoApplication, desired map[string]string) (bool, string, string, error) {
	var candidates hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &candidates, client.InNamespace(app.Namespace)); err != nil {
		return false, "", "", err
	}
	for _, other := range candidates.Items {
		if other.Name == app.Name || effectiveMode(&other) != ModeManage || other.Spec.RealmRef != app.Spec.RealmRef {
			continue
		}
		for _, mapping := range other.Spec.IdentityMappings {
			name := identityMappingKeycloakName(&other, mapping)
			if managedName, exists := desired[mapping.IdentityProvider+"\x00"+name]; exists {
				return true, other.Name, managedName, nil
			}
		}
	}
	return false, "", "", nil
}

func (r *HankoApplicationReconciler) reconcileThemeReadiness(ctx context.Context, app *hankoshv1alpha1.HankoApplication) (bool, time.Duration, error) {
	if app.Spec.Theme == "" {
		setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionTrue, "RealmDefault",
			"no client theme requested; Keycloak realm default applies")
		return true, 0, nil
	}

	var theme hankoshv1alpha1.HankoTheme
	err := r.Get(ctx, types.NamespacedName{Name: app.Spec.Theme, Namespace: app.Namespace}, &theme)
	if apierrors.IsNotFound(err) {
		setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionUnknown, "ExternalTheme",
			fmt.Sprintf("no HankoTheme %q exists; treating it as an externally installed Keycloak theme", app.Spec.Theme))
		return true, 0, nil
	}
	if err != nil {
		return false, requeueOnError, err
	}

	if !theme.DeletionTimestamp.IsZero() {
		app.Status.Phase = "Reconciling"
		setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionFalse, "ThemeDeleting",
			fmt.Sprintf("HankoTheme %q is being deleted", theme.Name))
		return false, requeueOnError, nil
	}
	if theme.Status.Phase == "Ready" && theme.Status.JarPath != "" &&
		theme.Status.ObservedGeneration == theme.Generation {
		setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionTrue, "ManagedThemeReady",
			fmt.Sprintf("HankoTheme %q is installed at %s", theme.Name, theme.Status.JarPath))
		return true, 0, nil
	}

	app.Status.Phase = "Reconciling"
	reason := "ThemeBuilding"
	message := fmt.Sprintf("waiting for HankoTheme %q to become Ready", theme.Name)
	if theme.Status.Phase == "Error" {
		reason = "ThemeError"
		message = fmt.Sprintf("HankoTheme %q build is in Error", theme.Name)
	}
	setCondition(&app.Status.Conditions, "ThemeReady", metav1.ConditionFalse, reason, message)
	return false, requeueOnError, nil
}

// reconcileObserve implements the Observe-mode reconcile path: read-only status
// reporting. It never calls CreateApp, UpdateApp, DeleteApp, role mutations, or any
// secret-retrieving Keycloak API — Observe must not learn or store the client secret.
func (r *HankoApplicationReconciler) reconcileObserve(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client, patch client.Patch) (ctrl.Result, error) {
	return r.reconcileApplicationContract(ctx, app, kc, patch, true)
}

// reconcileRoles ensures the Keycloak client roles match spec.Roles.
func (r *HankoApplicationReconciler) reconcileRoles(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	log := log.FromContext(ctx)
	desired := make(map[string]string, len(app.Spec.Roles))
	for _, role := range app.Spec.Roles {
		desired[role.Name] = role.Description
	}
	for name, desc := range desired {
		if err := kc.EnsureClientRole(ctx, app.Spec.RealmRef, app.Spec.ClientID, name, desc); err != nil {
			return fmt.Errorf("ensure role %q: %w", name, err)
		}
	}
	// Only reconcile deletions when the operator explicitly owns roles for this app.
	if len(app.Spec.Roles) == 0 {
		return nil
	}
	existing, err := kc.ListClientRoles(ctx, app.Spec.RealmRef, app.Spec.ClientID)
	if err != nil {
		return fmt.Errorf("list roles for drift check: %w", err)
	}
	for _, role := range existing {
		if _, ok := desired[role.Name]; !ok {
			if err := kc.DeleteClientRole(ctx, app.Spec.RealmRef, app.Spec.ClientID, role.Name); err != nil {
				log.Error(err, "delete orphan client role", "role", role.Name)
			} else {
				log.Info("deleted orphan client role", "role", role.Name)
			}
		}
	}
	return nil
}

func (r *HankoApplicationReconciler) reconcileRealmRoleScopes(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	if app.Spec.RealmRoleScopes == nil {
		setCondition(&app.Status.Conditions, "RoleScopes", metav1.ConditionUnknown, "Unmanaged",
			"realm-role scope mappings are not managed")
		return nil
	}
	if err := kc.ReconcileClientRealmRoleScopes(ctx, app.Spec.RealmRef, app.Spec.ClientID, app.Spec.RealmRoleScopes); err != nil {
		return fmt.Errorf("reconcile realm-role scopes for %q: %w", app.Spec.ClientID, err)
	}
	setCondition(&app.Status.Conditions, "RoleScopes", metav1.ConditionTrue, "Synced",
		fmt.Sprintf("%d realm-role scope mapping(s) reconciled", len(app.Spec.RealmRoleScopes)))
	return nil
}

func (r *HankoApplicationReconciler) reconcileApplicationMappings(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	if err := r.reconcileIdentityMappings(ctx, app, kc); err != nil {
		return fmt.Errorf("reconcile identity mappings for %q: %w", app.Spec.ClientID, err)
	}
	if err := r.reconcileTokenClaims(ctx, app, kc); err != nil {
		return fmt.Errorf("reconcile token claims for %q: %w", app.Spec.ClientID, err)
	}
	setCondition(&app.Status.Conditions, "Mappings", metav1.ConditionTrue, "Synced",
		fmt.Sprintf("%d identity mapping(s) and %d token claim(s) reconciled",
			len(app.Spec.IdentityMappings), len(app.Spec.TokenClaims)))
	return nil
}

func (r *HankoApplicationReconciler) reconcileIdentityMappings(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	previousMappings := append([]hankoshv1alpha1.ManagedIdentityMappingReference(nil), app.Status.ManagedIdentityMappings...)
	roleNames := make(map[string]struct{}, len(app.Spec.Roles))
	for _, role := range app.Spec.Roles {
		roleNames[role.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(app.Spec.IdentityMappings))
	managed := make([]hankoshv1alpha1.ManagedIdentityMappingReference, 0, len(app.Spec.IdentityMappings))
	for _, mapping := range app.Spec.IdentityMappings {
		mapperStatus := previousIdentityMappingStatus(previousMappings, mapping.Name)
		if mapperStatus.Name == "" {
			mapperStatus.Name = mapping.Name
			mapperStatus.IdentityProvider = mapping.IdentityProvider
		}
		if _, duplicate := seen[mapping.Name]; duplicate {
			err := fmt.Errorf("duplicate identity mapping name %q", mapping.Name)
			setMapperCondition(&mapperStatus.Conditions, app.Generation, metav1.ConditionFalse, "Invalid", err.Error())
			managed = append(managed, mapperStatus)
			app.Status.ManagedIdentityMappings = checkpointIdentityMappings(managed, previousMappings)
			return err
		}
		seen[mapping.Name] = struct{}{}
		desired, err := identityProviderMapperForApplication(app, mapping, roleNames)
		if err != nil {
			setMapperCondition(&mapperStatus.Conditions, app.Generation, metav1.ConditionFalse, "Invalid", err.Error())
			managed = append(managed, mapperStatus)
			app.Status.ManagedIdentityMappings = checkpointIdentityMappings(managed, previousMappings)
			return err
		}
		desired.Config[applications.OwnerAttribute] = string(app.UID)
		actual, err := kc.EnsureIdentityProviderMapper(ctx, app.Spec.RealmRef, desired)
		if err != nil {
			err = fmt.Errorf("ensure identity mapping %q: %w", mapping.Name, err)
			setMapperCondition(&mapperStatus.Conditions, app.Generation, metav1.ConditionFalse, "EnsureFailed", err.Error())
			managed = append(managed, mapperStatus)
			app.Status.ManagedIdentityMappings = checkpointIdentityMappings(managed, previousMappings)
			return err
		}
		mapperStatus.Name = mapping.Name
		mapperStatus.IdentityProvider = mapping.IdentityProvider
		mapperStatus.KeycloakID = actual.ID
		setMapperCondition(&mapperStatus.Conditions, app.Generation, metav1.ConditionTrue, "Synced", "identity-provider mapper reconciled")
		managed = append(managed, mapperStatus)
		// Keep every successful external mutation represented in status even if a
		// later mapper fails during this same reconcile. The caller patches status
		// on error, allowing the finalizer to clean up partial progress.
		app.Status.ManagedIdentityMappings = checkpointIdentityMappings(managed, previousMappings)
	}
	for _, previous := range previousMappings {
		if currentIdentityMapperID(managed, previous) {
			continue
		}
		if err := deleteOwnedApplicationIdentityMapper(ctx, app, kc, previous.IdentityProvider, previous.KeycloakID); err != nil {
			err = fmt.Errorf("delete stale identity mapping %q: %w", previous.Name, err)
			setMapperCondition(&previous.Conditions, app.Generation, metav1.ConditionFalse, "DeleteFailed", err.Error())
			managed = append(managed, previous)
			app.Status.ManagedIdentityMappings = checkpointIdentityMappings(managed, previousMappings)
			return err
		}
	}
	app.Status.ManagedIdentityMappings = managed
	return nil
}

func identityProviderMapperForApplication(app *hankoshv1alpha1.HankoApplication, mapping hankoshv1alpha1.ApplicationIdentityMapping, roleNames map[string]struct{}) (keycloak.IdentityProviderMapper, error) {
	if strings.TrimSpace(mapping.Name) == "" || strings.TrimSpace(mapping.IdentityProvider) == "" || strings.TrimSpace(mapping.Claim) == "" {
		return keycloak.IdentityProviderMapper{}, fmt.Errorf("identity mapping name, identityProvider and claim are required")
	}
	targets := 0
	if mapping.Target.RealmRole != "" {
		targets++
	}
	if mapping.Target.ClientRole != "" {
		targets++
	}
	if mapping.Target.UserAttribute != "" {
		targets++
	}
	if targets != 1 {
		return keycloak.IdentityProviderMapper{}, fmt.Errorf("identity mapping %q must select exactly one target", mapping.Name)
	}
	syncMode := mapping.SyncMode
	if syncMode == "" {
		syncMode = "FORCE"
	}
	mapper := keycloak.IdentityProviderMapper{
		Name:                  identityMappingKeycloakName(app, mapping),
		IdentityProviderAlias: mapping.IdentityProvider,
	}
	if mapping.Target.UserAttribute != "" {
		if mapping.MatchValue != "" {
			return keycloak.IdentityProviderMapper{}, fmt.Errorf("identity mapping %q must omit matchValue for a userAttribute target", mapping.Name)
		}
		mapper.IdentityProviderMapper = "oidc-user-attribute-idp-mapper"
		mapper.Config = map[string]string{
			"syncMode": syncMode, "claim": mapping.Claim, "user.attribute": mapping.Target.UserAttribute,
		}
		return mapper, nil
	}
	if mapping.MatchValue == "" {
		return keycloak.IdentityProviderMapper{}, fmt.Errorf("identity mapping %q requires matchValue for a role target", mapping.Name)
	}
	role := mapping.Target.RealmRole
	if mapping.Target.ClientRole != "" {
		if _, declared := roleNames[mapping.Target.ClientRole]; !declared {
			return keycloak.IdentityProviderMapper{}, fmt.Errorf("identity mapping %q targets undeclared client role %q", mapping.Name, mapping.Target.ClientRole)
		}
		role = app.Spec.ClientID + "." + mapping.Target.ClientRole
	}
	mapper.IdentityProviderMapper = "oidc-role-idp-mapper"
	mapper.Config = map[string]string{
		"syncMode": syncMode, "claim": mapping.Claim, "claim.value": mapping.MatchValue, "role": role,
	}
	return mapper, nil
}

func (r *HankoApplicationReconciler) reconcileTokenClaims(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	owner := tokenClaimOwner{uid: string(app.UID), namespace: app.Namespace, name: app.Name, generation: app.Generation, realm: app.Spec.RealmRef, clientID: app.Spec.ClientID}
	managed, err := reconcileClientTokenClaims(ctx, kc, owner, app.Spec.TokenClaims, app.Status.ManagedTokenClaims)
	app.Status.ManagedTokenClaims = managed
	return err
}

func preflightTokenClaims(
	ownerNamespace, ownerName string,
	generation int64,
	claims []hankoshv1alpha1.ApplicationTokenClaim,
	previousClaims []hankoshv1alpha1.ManagedTokenClaimReference,
) ([]hankoshv1alpha1.ManagedTokenClaimReference, error) {
	seen := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		mapperStatus := previousTokenClaimStatus(previousClaims, claim.Name)
		if mapperStatus.Name == "" {
			mapperStatus.Name = claim.Name
		}
		if _, duplicate := seen[claim.Name]; duplicate {
			err := fmt.Errorf("duplicate token claim name %q", claim.Name)
			setMapperCondition(&mapperStatus.Conditions, generation, metav1.ConditionFalse, "Invalid", err.Error())
			return checkpointTokenClaims([]hankoshv1alpha1.ManagedTokenClaimReference{mapperStatus}, previousClaims), err
		}
		seen[claim.Name] = struct{}{}
		if _, err := protocolMapperForClient(ownerNamespace, ownerName, claim); err != nil {
			setMapperCondition(&mapperStatus.Conditions, generation, metav1.ConditionFalse, "Invalid", err.Error())
			return checkpointTokenClaims([]hankoshv1alpha1.ManagedTokenClaimReference{mapperStatus}, previousClaims), err
		}
	}
	return nil, nil
}

func reconcileClientTokenClaims(
	ctx context.Context,
	kc *keycloak.Client,
	owner tokenClaimOwner,
	claims []hankoshv1alpha1.ApplicationTokenClaim,
	previousClaims []hankoshv1alpha1.ManagedTokenClaimReference,
) ([]hankoshv1alpha1.ManagedTokenClaimReference, error) {
	previousClaims = append([]hankoshv1alpha1.ManagedTokenClaimReference(nil), previousClaims...)
	seen := make(map[string]struct{}, len(claims))
	managed := make([]hankoshv1alpha1.ManagedTokenClaimReference, 0, len(claims))
	for _, claim := range claims {
		status, err := reconcileClientTokenClaim(ctx, kc, owner, claim, previousClaims, seen)
		managed = append(managed, status)
		if err != nil {
			return checkpointTokenClaims(managed, previousClaims), err
		}
	}
	return deleteStaleClientTokenClaims(ctx, kc, owner, managed, previousClaims)
}

func reconcileClientTokenClaim(ctx context.Context, kc *keycloak.Client, owner tokenClaimOwner, claim hankoshv1alpha1.ApplicationTokenClaim, previous []hankoshv1alpha1.ManagedTokenClaimReference, seen map[string]struct{}) (hankoshv1alpha1.ManagedTokenClaimReference, error) {
	status := previousTokenClaimStatus(previous, claim.Name)
	if status.Name == "" {
		status.Name = claim.Name
	}
	if _, duplicate := seen[claim.Name]; duplicate {
		err := fmt.Errorf("duplicate token claim name %q", claim.Name)
		setMapperCondition(&status.Conditions, owner.generation, metav1.ConditionFalse, "Invalid", err.Error())
		return status, err
	}
	seen[claim.Name] = struct{}{}
	desired, err := protocolMapperForClient(owner.namespace, owner.name, claim)
	if err != nil {
		setMapperCondition(&status.Conditions, owner.generation, metav1.ConditionFalse, "Invalid", err.Error())
		return status, err
	}
	if owner.uid != "" {
		desired.Config[applications.OwnerAttribute] = owner.uid
	}
	actual, err := kc.EnsureClientProtocolMapper(ctx, owner.realm, owner.clientID, desired)
	if err != nil {
		err = fmt.Errorf("ensure token claim %q: %w", claim.Name, err)
		setMapperCondition(&status.Conditions, owner.generation, metav1.ConditionFalse, "EnsureFailed", err.Error())
		return status, err
	}
	status.Name = claim.Name
	status.KeycloakID = actual.ID
	setMapperCondition(&status.Conditions, owner.generation, metav1.ConditionTrue, "Synced", "client protocol mapper reconciled")
	return status, nil
}

func deleteStaleClientTokenClaims(ctx context.Context, kc *keycloak.Client, owner tokenClaimOwner, managed, previous []hankoshv1alpha1.ManagedTokenClaimReference) ([]hankoshv1alpha1.ManagedTokenClaimReference, error) {
	for _, stale := range previous {
		if currentTokenMapperID(managed, stale.KeycloakID) {
			continue
		}
		if err := deleteOwnedApplicationTokenMapper(ctx, kc, owner, stale.KeycloakID); err != nil {
			err = fmt.Errorf("delete stale token claim %q: %w", stale.Name, err)
			setMapperCondition(&stale.Conditions, owner.generation, metav1.ConditionFalse, "DeleteFailed", err.Error())
			managed = append(managed, stale)
			return checkpointTokenClaims(managed, previous), err
		}
	}
	return managed, nil
}

func protocolMapperForClient(ownerNamespace, ownerName string, claim hankoshv1alpha1.ApplicationTokenClaim) (keycloak.ProtocolMapper, error) {
	if strings.TrimSpace(claim.Name) == "" || strings.TrimSpace(claim.Claim) == "" {
		return keycloak.ProtocolMapper{}, fmt.Errorf("token claim name and claim are required")
	}
	if isReservedTokenClaim(claim.Claim) {
		return keycloak.ProtocolMapper{}, fmt.Errorf("token claim %q targets reserved claim %q", claim.Name, claim.Claim)
	}
	if tokenClaimSourceCount(claim) != 1 {
		return keycloak.ProtocolMapper{}, fmt.Errorf("token claim %q must select exactly one of userAttribute, value or realmRoles", claim.Name)
	}
	jsonType := claim.JSONType
	if jsonType == "" {
		jsonType = "String"
	}
	accessToken := boolOrDefault(claim.AddToAccessToken, true)
	if claim.RealmRoles {
		return realmRoleProtocolMapper(ownerNamespace, ownerName, claim, jsonType, accessToken), nil
	}
	if claim.Claim == "aud" {
		if claim.UserAttribute != "" {
			return keycloak.ProtocolMapper{}, fmt.Errorf("token claim %q audience must use a fixed value", claim.Name)
		}
		audience := strings.TrimSpace(*claim.Value)
		if audience == "" {
			return keycloak.ProtocolMapper{}, fmt.Errorf("token claim %q audience must not be empty", claim.Name)
		}
		return keycloak.ProtocolMapper{
			Name:           tokenClaimKeycloakName(ownerNamespace, ownerName, claim),
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-audience-mapper",
			Config: map[string]string{
				"included.client.audience":  "",
				"included.custom.audience":  audience,
				"id.token.claim":            fmt.Sprintf("%t", boolOrDefault(claim.AddToIDToken, false)),
				"access.token.claim":        fmt.Sprintf("%t", accessToken),
				"introspection.token.claim": fmt.Sprintf("%t", boolOrDefault(claim.AddToIntrospection, accessToken)),
			},
		}, nil
	}
	config := map[string]string{
		"claim.name":                claim.Claim,
		"jsonType.label":            jsonType,
		"id.token.claim":            fmt.Sprintf("%t", boolOrDefault(claim.AddToIDToken, true)),
		"access.token.claim":        fmt.Sprintf("%t", accessToken),
		"userinfo.token.claim":      fmt.Sprintf("%t", boolOrDefault(claim.AddToUserInfo, true)),
		"introspection.token.claim": fmt.Sprintf("%t", boolOrDefault(claim.AddToIntrospection, accessToken)),
	}
	mapper := keycloak.ProtocolMapper{
		Name: tokenClaimKeycloakName(ownerNamespace, ownerName, claim), Protocol: "openid-connect", Config: config,
	}
	if claim.UserAttribute != "" {
		mapper.ProtocolMapper = "oidc-usermodel-attribute-mapper"
		config["user.attribute"] = claim.UserAttribute
		config["multivalued"] = fmt.Sprintf("%t", claim.Multivalued)
		config["aggregate.attrs"] = "false"
	} else {
		if claim.Multivalued {
			return keycloak.ProtocolMapper{}, fmt.Errorf("token claim %q cannot be multivalued when using a fixed value", claim.Name)
		}
		mapper.ProtocolMapper = "oidc-hardcoded-claim-mapper"
		config["claim.value"] = *claim.Value
	}
	return mapper, nil
}

func isReservedTokenClaim(claim string) bool {
	if _, reserved := reservedTokenClaims[claim]; reserved {
		return true
	}
	for _, root := range structuredReservedTokenClaims {
		if strings.HasPrefix(claim, root+".") {
			return true
		}
	}
	return false
}

// tokenClaimSourceCount counts how many mutually exclusive value sources a token
// claim selects. Exactly one of userAttribute, value or realmRoles is valid.
func tokenClaimSourceCount(claim hankoshv1alpha1.ApplicationTokenClaim) int {
	count := 0
	if claim.UserAttribute != "" {
		count++
	}
	if claim.Value != nil {
		count++
	}
	if claim.RealmRoles {
		count++
	}
	return count
}

// realmRoleProtocolMapper builds a Keycloak realm-role user-model mapper that
// projects the caller's realm roles into a multivalued claim. This is the
// projection substrate for HKX-09: a member inherits realm roles from their
// organization group and the consuming application reads them from this claim.
func realmRoleProtocolMapper(ownerNamespace, ownerName string, claim hankoshv1alpha1.ApplicationTokenClaim, jsonType string, accessToken bool) keycloak.ProtocolMapper {
	return keycloak.ProtocolMapper{
		Name:           tokenClaimKeycloakName(ownerNamespace, ownerName, claim),
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-realm-role-mapper",
		Config: map[string]string{
			"claim.name":                            claim.Claim,
			"jsonType.label":                        jsonType,
			"multivalued":                           "true",
			"usermodel.realmRoleMapping.rolePrefix": claim.RealmRolePrefix,
			"id.token.claim":                        fmt.Sprintf("%t", boolOrDefault(claim.AddToIDToken, true)),
			"access.token.claim":                    fmt.Sprintf("%t", accessToken),
			"userinfo.token.claim":                  fmt.Sprintf("%t", boolOrDefault(claim.AddToUserInfo, true)),
			"introspection.token.claim":             fmt.Sprintf("%t", boolOrDefault(claim.AddToIntrospection, accessToken)),
		},
	}
}

func (r *HankoApplicationReconciler) cleanupApplicationMappings(ctx context.Context, app *hankoshv1alpha1.HankoApplication, kc *keycloak.Client) error {
	for _, mapping := range app.Status.ManagedIdentityMappings {
		if mapping.KeycloakID == "" {
			continue
		}
		if err := deleteOwnedApplicationIdentityMapper(ctx, app, kc, mapping.IdentityProvider, mapping.KeycloakID); err != nil {
			return err
		}
	}
	for _, claim := range app.Status.ManagedTokenClaims {
		if claim.KeycloakID == "" {
			continue
		}
		if err := deleteOwnedApplicationTokenMapper(ctx, kc, tokenClaimOwner{uid: string(app.UID), realm: app.Spec.RealmRef, clientID: app.Spec.ClientID}, claim.KeycloakID); err != nil {
			return err
		}
	}
	return nil
}

func containsManagedIdentityMapping(items []hankoshv1alpha1.ManagedIdentityMappingReference, target hankoshv1alpha1.ManagedIdentityMappingReference) bool {
	for _, item := range items {
		if item.Name == target.Name && item.IdentityProvider == target.IdentityProvider && item.KeycloakID == target.KeycloakID {
			return true
		}
	}
	return false
}

func containsManagedTokenClaim(items []hankoshv1alpha1.ManagedTokenClaimReference, target hankoshv1alpha1.ManagedTokenClaimReference) bool {
	for _, item := range items {
		if item.Name == target.Name && item.KeycloakID == target.KeycloakID {
			return true
		}
	}
	return false
}

func previousIdentityMappingStatus(items []hankoshv1alpha1.ManagedIdentityMappingReference, name string) hankoshv1alpha1.ManagedIdentityMappingReference {
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	return hankoshv1alpha1.ManagedIdentityMappingReference{}
}

func previousTokenClaimStatus(items []hankoshv1alpha1.ManagedTokenClaimReference, name string) hankoshv1alpha1.ManagedTokenClaimReference {
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	return hankoshv1alpha1.ManagedTokenClaimReference{}
}

func setMapperCondition(conditions *[]metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string) {
	setCondition(conditions, "Synced", status, reason, message)
	for i := range *conditions {
		if (*conditions)[i].Type == "Synced" {
			(*conditions)[i].ObservedGeneration = generation
			return
		}
	}
}

func checkpointIdentityMappings(current, previous []hankoshv1alpha1.ManagedIdentityMappingReference) []hankoshv1alpha1.ManagedIdentityMappingReference {
	checkpoint := append([]hankoshv1alpha1.ManagedIdentityMappingReference(nil), current...)
	for _, item := range previous {
		if !containsManagedIdentityMapping(checkpoint, item) {
			checkpoint = append(checkpoint, item)
		}
	}
	return checkpoint
}

func checkpointTokenClaims(current, previous []hankoshv1alpha1.ManagedTokenClaimReference) []hankoshv1alpha1.ManagedTokenClaimReference {
	checkpoint := append([]hankoshv1alpha1.ManagedTokenClaimReference(nil), current...)
	for _, item := range previous {
		if !containsManagedTokenClaim(checkpoint, item) {
			checkpoint = append(checkpoint, item)
		}
	}
	return checkpoint
}

func managedMapperName(app *hankoshv1alpha1.HankoApplication, kind, name string) string {
	return managedMapperNameForOwner(app.Namespace, app.Name, kind, name)
}

func managedMapperNameForOwner(namespace, ownerName, kind, name string) string {
	value := fmt.Sprintf("hanko:%s:%s:%s:%s", namespace, ownerName, kind, name)
	if len(value) <= 180 {
		return value
	}
	hash := sha256.Sum256([]byte(value))
	return value[:155] + ":" + fmt.Sprintf("%x", hash[:12])
}

func identityMappingKeycloakName(app *hankoshv1alpha1.HankoApplication, mapping hankoshv1alpha1.ApplicationIdentityMapping) string {
	if mapping.KeycloakName != "" {
		return mapping.KeycloakName
	}
	return managedMapperName(app, "idp", mapping.Name)
}

func tokenClaimKeycloakName(namespace, ownerName string, claim hankoshv1alpha1.ApplicationTokenClaim) string {
	if claim.KeycloakName != "" {
		return claim.KeycloakName
	}
	return managedMapperNameForOwner(namespace, ownerName, "claim", claim.Name)
}

func boolOrDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func (r *HankoApplicationReconciler) upsertSecret(ctx context.Context, app *hankoshv1alpha1.HankoApplication, secret string) error {
	name := secretName(app.Spec.ClientID)
	s := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: app.Namespace}, s)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if err != nil {
		s = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   app.Namespace,
				Labels:      map[string]string{"app.kubernetes.io/managed-by": "hanko-operator"},
				Annotations: applicationRotationCheckpoint(app),
			},
			StringData: map[string]string{"client_secret": secret},
		}
		if err := controllerutil.SetControllerReference(app, s, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference on secret: %w", err)
		}
		if err := r.Create(ctx, s); err != nil {
			return err
		}
		return r.reconcileSecretProjections(ctx, app, secret)
	}
	p := client.MergeFrom(s.DeepCopy())
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	for key, value := range applicationRotationCheckpoint(app) {
		s.Annotations[key] = value
	}
	s.StringData = map[string]string{"client_secret": secret}
	if err := r.Patch(ctx, s, p); err != nil {
		return err
	}
	return r.reconcileSecretProjections(ctx, app, secret)
}

func (r *HankoApplicationReconciler) reconcileSecretProjections(ctx context.Context, app *hankoshv1alpha1.HankoApplication, secret string) error {
	desired := make(map[types.NamespacedName]struct{}, len(app.Spec.ClientSecretProjections))
	canonical := types.NamespacedName{Name: secretName(app.Spec.ClientID), Namespace: app.Namespace}
	for _, target := range app.Spec.ClientSecretProjections {
		key := types.NamespacedName{Name: target.Name, Namespace: target.Namespace}
		if key.Name == "" || key.Namespace == "" {
			return fmt.Errorf("client secret projection namespace and name are required")
		}
		if key == canonical {
			return fmt.Errorf("client secret projection %s/%s duplicates the canonical secret", key.Namespace, key.Name)
		}
		if _, duplicate := desired[key]; duplicate {
			return fmt.Errorf("duplicate client secret projection %s/%s", key.Namespace, key.Name)
		}
		desired[key] = struct{}{}
		if err := r.upsertSecretProjection(ctx, app, key, secret); err != nil {
			return err
		}
		recordManagedSecretProjection(app, target)
	}
	if err := r.cleanupStaleSecretProjections(ctx, app, desired); err != nil {
		return err
	}
	setCondition(&app.Status.Conditions, "SecretProjections", metav1.ConditionTrue, "Synced",
		fmt.Sprintf("%d client secret projection(s) reconciled", len(desired)))
	return nil
}

func (r *HankoApplicationReconciler) upsertSecretProjection(ctx context.Context, app *hankoshv1alpha1.HankoApplication, key types.NamespacedName, secret string) error {
	projectionClient := r.secretProjectionClient()
	var projected corev1.Secret
	err := projectionClient.Get(ctx, key, &projected)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("client secret projection %s/%s is not pre-provisioned by the Hanko deployment", key.Namespace, key.Name)
	}
	if err != nil {
		return fmt.Errorf("read client secret projection %s/%s: %w", key.Namespace, key.Name, err)
	}
	if !secretProjectionOwnedBy(&projected, app) {
		return fmt.Errorf("refusing to overwrite client secret projection %s/%s not pre-authorized for %s/%s", key.Namespace, key.Name, app.Namespace, app.Name)
	}
	patch := client.MergeFrom(projected.DeepCopy())
	if projected.Annotations == nil {
		projected.Annotations = map[string]string{}
	}
	for annotation, value := range secretProjectionAnnotations(app) {
		projected.Annotations[annotation] = value
	}
	projected.Type = corev1.SecretTypeOpaque
	projected.Data = map[string][]byte{"client_secret": []byte(secret)}
	projected.StringData = nil
	if err := projectionClient.Patch(ctx, &projected, patch); err != nil {
		return fmt.Errorf("update client secret projection %s/%s: %w", key.Namespace, key.Name, err)
	}
	return nil
}

func secretProjectionAnnotations(app *hankoshv1alpha1.HankoApplication) map[string]string {
	return map[string]string{
		clientSecretProjectionOwnerName:      app.Name,
		clientSecretProjectionOwnerNamespace: app.Namespace,
		clientSecretProjectionOwnerUID:       string(app.UID),
		clientSecretProjectionClientID:       app.Spec.ClientID,
		clientSecretProjectionSourceSecret:   app.Namespace + "/" + secretName(app.Spec.ClientID),
	}
}

func secretProjectionOwnedBy(secret *corev1.Secret, app *hankoshv1alpha1.HankoApplication) bool {
	annotations := secret.GetAnnotations()
	ownerUID := annotations[clientSecretProjectionOwnerUID]
	return secret.GetLabels()[clientSecretProjectionLabel] == "true" &&
		annotations[clientSecretProjectionOwnerName] == app.Name &&
		annotations[clientSecretProjectionOwnerNamespace] == app.Namespace &&
		annotations[clientSecretProjectionClientID] == app.Spec.ClientID &&
		(ownerUID == "" || ownerUID == string(app.UID))
}

func recordManagedSecretProjection(app *hankoshv1alpha1.HankoApplication, target hankoshv1alpha1.ApplicationSecretProjection) {
	for _, managed := range app.Status.ManagedClientSecretProjections {
		if managed == target {
			return
		}
	}
	app.Status.ManagedClientSecretProjections = append(app.Status.ManagedClientSecretProjections, target)
}

func (r *HankoApplicationReconciler) cleanupStaleSecretProjections(ctx context.Context, app *hankoshv1alpha1.HankoApplication, desired map[types.NamespacedName]struct{}) error {
	for _, previous := range app.Status.ManagedClientSecretProjections {
		key := types.NamespacedName{Name: previous.Name, Namespace: previous.Namespace}
		if _, keep := desired[key]; keep {
			continue
		}
		if err := r.clearSecretProjection(ctx, app, key); err != nil {
			return err
		}
	}
	app.Status.ManagedClientSecretProjections = append([]hankoshv1alpha1.ApplicationSecretProjection(nil), app.Spec.ClientSecretProjections...)
	return nil
}

func (r *HankoApplicationReconciler) cleanupSecretProjections(ctx context.Context, app *hankoshv1alpha1.HankoApplication) error {
	targets := make(map[types.NamespacedName]struct{}, len(app.Spec.ClientSecretProjections)+len(app.Status.ManagedClientSecretProjections))
	all := append(append([]hankoshv1alpha1.ApplicationSecretProjection(nil), app.Spec.ClientSecretProjections...), app.Status.ManagedClientSecretProjections...)
	for _, target := range all {
		targets[types.NamespacedName{Name: target.Name, Namespace: target.Namespace}] = struct{}{}
	}
	for key := range targets {
		if err := r.clearSecretProjection(ctx, app, key); err != nil {
			return err
		}
	}
	return nil
}

func (r *HankoApplicationReconciler) clearSecretProjection(ctx context.Context, app *hankoshv1alpha1.HankoApplication, key types.NamespacedName) error {
	projectionClient := r.secretProjectionClient()
	var projected corev1.Secret
	if err := projectionClient.Get(ctx, key, &projected); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("read stale client secret projection %s/%s: %w", key.Namespace, key.Name, err)
	}
	if !secretProjectionOwnedBy(&projected, app) {
		return fmt.Errorf("refusing to clear client secret projection %s/%s not owned by %s/%s", key.Namespace, key.Name, app.Namespace, app.Name)
	}
	patch := client.MergeFrom(projected.DeepCopy())
	projected.Data = map[string][]byte{}
	projected.StringData = nil
	if err := projectionClient.Patch(ctx, &projected, patch); err != nil {
		return fmt.Errorf("clear stale client secret projection %s/%s: %w", key.Namespace, key.Name, err)
	}
	return nil
}

func (r *HankoApplicationReconciler) secretProjectionClient() client.Client {
	if r.SecretProjectionClient != nil {
		return r.SecretProjectionClient
	}
	return r.Client
}

func secretName(clientID string) string { return "hanko-app-" + clientID }

func applicationRealmClientIndex(obj client.Object) []string {
	app, ok := obj.(*hankoshv1alpha1.HankoApplication)
	if !ok {
		return nil
	}
	return []string{realmClientKey(app.Spec.RealmRef, app.Spec.ClientID)}
}

func (r *HankoApplicationReconciler) requestsForServiceAccountOwnership(ctx context.Context, obj client.Object) []reconcile.Request {
	account, ok := obj.(*hankoshv1alpha1.HankoServiceAccount)
	if !ok {
		return nil
	}
	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(account.Namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range applications.Items {
		application := &applications.Items[i]
		if effectiveMode(application) == ModeManage && sameClientIdentity(application.Spec.RealmRef, application.Spec.ClientID, account.Spec.RealmRef, account.Spec.ClientID) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: application.Name, Namespace: application.Namespace}})
		}
	}
	return requests
}

func (r *HankoApplicationReconciler) requestsForApplicationTheme(ctx context.Context, obj client.Object) []reconcile.Request {
	theme, ok := obj.(*hankoshv1alpha1.HankoTheme)
	if !ok {
		return nil
	}
	var apps hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &apps, client.InNamespace(theme.Namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range apps.Items {
		if apps.Items[i].Spec.Theme == theme.Name {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: apps.Items[i].Name, Namespace: apps.Items[i].Namespace}})
		}
	}
	return requests
}

func (r *HankoApplicationReconciler) requestsForApplicationRealm(ctx context.Context, obj client.Object) []reconcile.Request {
	realm, ok := obj.(*hankoshv1alpha1.HankoRealm)
	if !ok {
		return nil
	}
	var apps hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &apps, client.InNamespace(realm.Namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range apps.Items {
		app := &apps.Items[i]
		if app.Spec.RealmRef == realm.Name && app.Spec.Type != "spa" && app.Spec.SecretRotationPolicy == nil {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
		}
	}
	return requests
}

// SetupWithManager registers the reconciler. Spec generation changes and the
// explicit reconcile-request annotation enqueue the primary resource; ordinary
// status and metadata writes remain filtered to avoid tight reconcile loops.
func (r *HankoApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &hankoshv1alpha1.HankoApplication{}, realmClientIndexKey,
		applicationRealmClientIndex); err != nil {
		return fmt.Errorf("index HankoApplication by realmRef/clientID: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoApplication{}, builder.WithPredicates(generationOrReconcileRequestChanged())).
		Watches(&hankoshv1alpha1.HankoServiceAccount{}, handler.EnqueueRequestsFromMapFunc(r.requestsForServiceAccountOwnership)).
		Watches(&hankoshv1alpha1.HankoTheme{}, handler.EnqueueRequestsFromMapFunc(r.requestsForApplicationTheme)).
		Watches(&hankoshv1alpha1.HankoRealm{}, handler.EnqueueRequestsFromMapFunc(r.requestsForApplicationRealm)).
		Complete(r)
}
