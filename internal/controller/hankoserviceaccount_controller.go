package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const saFinalizerName = "hanko.sh/sa-cleanup"

// HankoServiceAccountReconciler reconciles HankoServiceAccount objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoserviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoserviceaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoserviceaccounts/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
type HankoServiceAccountReconciler struct {
	client.Client
	// OwnershipReader should be the manager's uncached API reader in production.
	// An authoritative read closes the cache-staleness window before any client
	// adoption, secret recovery, rotation or deletion.
	OwnershipReader client.Reader
	// ProtectedClientIDs mirrors the API control-plane authorized-client list.
	// Comparisons are whitespace-normalized but remain case-sensitive because
	// OAuth client identifiers are case-sensitive.
	ProtectedClientIDs []string
	// ProtectedRealm scopes ProtectedClientIDs to the fleet authority realm. A
	// tenant realm may legitimately use the same client ID without inheriting
	// fleet-level authority or being blocked by this guard.
	ProtectedRealm string
	Scheme         *runtime.Scheme
	Pool           *keycloak.Pool
	Recorder       events.EventRecorder
}

func (r *HankoServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var sa hankoshv1alpha1.HankoServiceAccount
	if err := r.Get(ctx, req.NamespacedName, &sa); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	kc := kcForObject(r.Pool, sa.Namespace, sa.Labels)
	observe := isImported(sa.Labels)
	if !observe {
		ownershipConflict, err := r.serviceAccountOwnershipConflict(ctx, &sa, kc)
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("check M2M client ownership for %q: %w", sa.Spec.ClientID, err)
		}
		if ownershipConflict != "" {
			if !sa.DeletionTimestamp.IsZero() {
				return r.releaseConflictingServiceAccount(ctx, &sa, ownershipConflict)
			}
			return r.recordServiceAccountOwnershipConflict(ctx, &sa, ownershipConflict)
		}
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !sa.DeletionTimestamp.IsZero() {
		return r.reconcileServiceAccountDeletion(ctx, &sa, kc, observe)
	}

	// ── Ensure finalizer ──────────────────────────────────────────────────────
	// Imported service accounts are inventory only: never retrieve or rotate
	// their secrets and never change or delete their Keycloak client.
	if observe {
		return r.prepareServiceAccountObserve(ctx, &sa, kc)
	}

	if !controllerutil.ContainsFinalizer(&sa, saFinalizerName) {
		controllerutil.AddFinalizer(&sa, saFinalizerName)
		if err := r.Update(ctx, &sa); err != nil {
			return ctrl.Result{}, fmt.Errorf("add SA finalizer: %w", err)
		}
	}

	return r.reconcileManagedServiceAccount(ctx, &sa, kc)
}

func (r *HankoServiceAccountReconciler) serviceAccountOwnershipConflict(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client) (string, error) {
	clientID := strings.TrimSpace(sa.Spec.ClientID)
	if isStaticallyProtectedServiceAccountClient(clientID) {
		return fmt.Sprintf("client %q is a built-in Keycloak client and cannot be governed by HankoServiceAccount", sa.Spec.ClientID), nil
	}
	if isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, sa.Spec.RealmRef, clientID) {
		return fmt.Sprintf("client %q is authorized in fleet authority realm %q and cannot be governed by HankoServiceAccount", sa.Spec.ClientID, sa.Spec.RealmRef), nil
	}
	if kc != nil {
		credentialClientID := strings.TrimSpace(kc.CredentialClientID())
		if credentialClientID != "" && clientID == credentialClientID {
			return fmt.Sprintf("client %q authorizes this operator and cannot be governed by HankoServiceAccount", sa.Spec.ClientID), nil
		}
	}

	reader := client.Reader(r.Client)
	if r.OwnershipReader != nil {
		reader = r.OwnershipReader
	}
	candidates := []clientOwnershipCandidate{newClientOwnershipCandidate("HankoServiceAccount", sa)}
	var accounts hankoshv1alpha1.HankoServiceAccountList
	if err := reader.List(ctx, &accounts, client.InNamespace(sa.Namespace)); err != nil {
		return "", fmt.Errorf("list HankoServiceAccount ownership candidates: %w", err)
	}
	for i := range accounts.Items {
		account := &accounts.Items[i]
		if account.Name == sa.Name || isImported(account.Labels) || !sameClientIdentity(account.Spec.RealmRef, account.Spec.ClientID, sa.Spec.RealmRef, clientID) {
			continue
		}
		candidates = append(candidates, newClientOwnershipCandidate("HankoServiceAccount", account))
	}

	var applications hankoshv1alpha1.HankoApplicationList
	if err := reader.List(ctx, &applications, client.InNamespace(sa.Namespace)); err != nil {
		return "", fmt.Errorf("list HankoApplication ownership candidates: %w", err)
	}
	for i := range applications.Items {
		application := &applications.Items[i]
		if effectiveMode(application) == ModeManage && sameClientIdentity(application.Spec.RealmRef, application.Spec.ClientID, sa.Spec.RealmRef, clientID) {
			candidates = append(candidates, newClientOwnershipCandidate("HankoApplication", application))
		}
	}

	winner := clientOwnershipWinner(candidates)
	if winner.kind != "HankoServiceAccount" || winner.name != sa.Name {
		return fmt.Sprintf("%s %q is the deterministic owner of realm %q client %q", winner.kind, winner.name, sa.Spec.RealmRef, sa.Spec.ClientID), nil
	}
	return "", nil
}

func isStaticallyProtectedServiceAccountClient(clientID string) bool {
	clientID = strings.TrimSpace(clientID)
	return keycloakInternalClients[clientID]
}

func (r *HankoServiceAccountReconciler) recordServiceAccountOwnershipConflict(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, message string) (ctrl.Result, error) {
	patch := client.MergeFrom(sa.DeepCopy())
	sa.Status.ObservedGeneration = sa.Generation
	sa.Status.Phase = "Error"
	setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionFalse, "OwnershipConflict", message)
	if err := r.Status().Patch(ctx, sa, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("service-account ownership conflict detected; skipping all Keycloak calls", "clientID", sa.Spec.ClientID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoServiceAccountReconciler) releaseConflictingServiceAccount(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, message string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(sa, saFinalizerName) {
		return ctrl.Result{}, nil
	}
	controllerutil.RemoveFinalizer(sa, saFinalizerName)
	if err := r.Update(ctx, sa); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove conflicting service-account finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released conflicting service account without deleting Keycloak client", "clientID", sa.Spec.ClientID, "reason", message)
	return ctrl.Result{}, nil
}

func (r *HankoServiceAccountReconciler) reconcileServiceAccountDeletion(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client, observe bool) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(sa, saFinalizerName) {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)
	if observe {
		logger.Info("Observe mode: dropping legacy finalizer without deleting M2M client", "clientID", sa.Spec.ClientID)
	} else if err := kc.DeleteApp(ctx, sa.Spec.RealmRef, sa.Spec.ClientID); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete M2M client %q: %w", sa.Spec.ClientID, err)
	}
	controllerutil.RemoveFinalizer(sa, saFinalizerName)
	if err := r.Update(ctx, sa); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove SA finalizer: %w", err)
	}
	logger.Info("service account finalizer removed", "clientID", sa.Spec.ClientID, "observe", observe)
	return ctrl.Result{}, nil
}

func (r *HankoServiceAccountReconciler) prepareServiceAccountObserve(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(sa, saFinalizerName) {
		controllerutil.RemoveFinalizer(sa, saFinalizerName)
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove imported service account finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	return r.reconcileServiceAccountObserve(ctx, sa, kc, client.MergeFrom(sa.DeepCopy()))
}

func (r *HankoServiceAccountReconciler) reconcileManagedServiceAccount(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client) (ctrl.Result, error) {
	patch := client.MergeFrom(sa.DeepCopy())
	sa.Status.ObservedGeneration = sa.Generation
	// Fail closed before any provider call, including an otherwise harmless
	// client drift correction, when a token mapper is invalid.
	if invalidClaims, err := preflightTokenClaims(sa.Namespace, sa.Name, sa.Generation, sa.Spec.TokenClaims, sa.Status.ManagedTokenClaims); err != nil {
		sa.Status.Phase = "Error"
		sa.Status.ManagedTokenClaims = invalidClaims
		setCondition(&sa.Status.Conditions, "Mappings", metav1.ConditionFalse, "Invalid", err.Error())
		_ = r.Status().Patch(ctx, sa, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("validate M2M token claims for %q: %w", sa.Spec.ClientID, err)
	}
	now := metav1.Now()
	rotationPolicy, err := effectiveSecretRotationPolicy(ctx, r.Client, sa.Namespace, sa.Spec.RealmRef, sa.Spec.SecretRotationPolicy)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("resolve service-account secret rotation policy: %w", err)
	}

	if err := r.ensureServiceAccountClient(ctx, sa, kc, rotationPolicy, &now, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}

	owner := tokenClaimOwner{namespace: sa.Namespace, name: sa.Name, generation: sa.Generation, realm: sa.Spec.RealmRef, clientID: sa.Spec.ClientID}
	managedClaims, err := reconcileClientTokenClaims(ctx, kc, owner, sa.Spec.TokenClaims, sa.Status.ManagedTokenClaims)
	sa.Status.ManagedTokenClaims = managedClaims
	if err != nil {
		sa.Status.Phase = "Error"
		setCondition(&sa.Status.Conditions, "Mappings", metav1.ConditionFalse, "MappingError", err.Error())
		_ = r.Status().Patch(ctx, sa, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("reconcile M2M token claims for %q: %w", sa.Spec.ClientID, err)
	}
	setCondition(&sa.Status.Conditions, "Mappings", metav1.ConditionTrue, "Synced",
		fmt.Sprintf("%d token claim(s) reconciled", len(sa.Spec.TokenClaims)))

	// ── Secret rotation ────────────────────────────────────────────────────────
	if err := r.maybeRotate(ctx, sa, rotationPolicy, &now, kc); err != nil {
		sa.Status.Phase = "Error"
		setCondition(&sa.Status.Conditions, "SecretRotation", metav1.ConditionFalse, "RotationFailed", err.Error())
		_ = r.Status().Patch(ctx, sa, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}

	sa.Status.Phase = "Ready"
	sa.Status.LastReconciled = &now
	setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "M2M client present in Keycloak")

	if err := r.Status().Patch(ctx, sa, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoServiceAccount synced", "clientID", sa.Spec.ClientID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoServiceAccountReconciler) ensureServiceAccountClient(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client, rotationPolicy *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time, patch client.Patch) error {
	found, err := kc.ClientExists(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if err != nil {
		return r.serviceAccountStatusError(ctx, sa, patch, "KeycloakError", fmt.Errorf("check M2M client existence: %w", err))
	}
	if !found {
		return r.createServiceAccountClient(ctx, sa, kc, rotationPolicy, now, patch)
	}
	if sa.Spec.Attributes != nil {
		if err := kc.SyncClientAttributes(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, sa.Spec.Attributes); err != nil {
			return r.serviceAccountStatusError(ctx, sa, patch, "UpdateFailed", fmt.Errorf("update M2M client attributes %q: %w", sa.Spec.ClientID, err))
		}
	}
	if err := r.ensureSASecret(ctx, sa, kc); err != nil {
		return r.serviceAccountStatusError(ctx, sa, patch, "SecretDrift", err)
	}
	return nil
}

func (r *HankoServiceAccountReconciler) createServiceAccountClient(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client, rotationPolicy *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time, patch client.Patch) error {
	secret, err := kc.CreateApp(ctx, sa.Spec.RealmRef, keycloak.CreateAppSpec{ClientID: sa.Spec.ClientID, Name: sa.Spec.ClientID, Type: "m2m", Attributes: sa.Spec.Attributes})
	if err != nil {
		return r.serviceAccountStatusError(ctx, sa, patch, "CreateFailed", fmt.Errorf("create M2M client %q: %w", sa.Spec.ClientID, err))
	}
	if err := r.upsertSASecret(ctx, sa, secret); err != nil {
		return err
	}
	setServiceAccountSecretStatus(sa, now)
	setServiceAccountNextRotation(sa, rotationPolicy)
	log.FromContext(ctx).Info("M2M client created", "clientID", sa.Spec.ClientID)
	return nil
}

func (r *HankoServiceAccountReconciler) serviceAccountStatusError(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, patch client.Patch, reason string, err error) error {
	sa.Status.Phase = "Error"
	setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
	_ = r.Status().Patch(ctx, sa, patch)
	return err
}

func setServiceAccountSecretStatus(sa *hankoshv1alpha1.HankoServiceAccount, rotatedAt *metav1.Time) {
	sa.Status.SecretRef = &hankoshv1alpha1.SecretReference{SecretRef: corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: saSecretName(sa.Spec.ClientID)}, Key: "client_secret",
	}}
	sa.Status.LastRotated = rotatedAt
}

func setServiceAccountNextRotation(sa *hankoshv1alpha1.HankoServiceAccount, policy *hankoshv1alpha1.SecretRotationPolicy) {
	if policy == nil || !policy.Enabled || policy.IntervalDays <= 0 || sa.Status.LastRotated == nil {
		sa.Status.NextRotation = nil
		return
	}
	next := metav1.NewTime(sa.Status.LastRotated.AddDate(0, 0, policy.IntervalDays))
	sa.Status.NextRotation = &next
}

// reconcileServiceAccountObserve reports presence only. In particular, it does
// not recover the Keycloak client secret into Kubernetes.
func (r *HankoServiceAccountReconciler) reconcileServiceAccountObserve(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client, patch client.Patch) (ctrl.Result, error) {
	sa.Status.ObservedGeneration = sa.Generation
	found, err := kc.ClientExists(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if err != nil {
		sa.Status.Phase = "Error"
		setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionFalse, "KeycloakError", err.Error())
		_ = r.Status().Patch(ctx, sa, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("observe: check M2M client existence: %w", err)
	}

	if !found {
		sa.Status.Phase = "Error"
		setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionFalse, "NotFound",
			"observed M2M client does not exist in Keycloak")
		if err := r.Status().Patch(ctx, sa, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}

	now := metav1.Now()
	sa.Status.Phase = "Ready"
	sa.Status.SecretRef = nil
	sa.Status.LastRotated = nil
	sa.Status.NextRotation = nil
	sa.Status.ManagedTokenClaims = nil
	sa.Status.LastReconciled = &now
	setCondition(&sa.Status.Conditions, "Mappings", metav1.ConditionUnknown, "Unmanaged",
		"service-account token claims are not managed in Observe mode")
	setCondition(&sa.Status.Conditions, "Synced", metav1.ConditionTrue, "Observed",
		"M2M client observed in Keycloak — imported service accounts are read-only")
	if err := r.Status().Patch(ctx, sa, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoServiceAccount observed", "clientID", sa.Spec.ClientID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

// ensureSASecret verifies the K8s Secret exists and recovers it from Keycloak if deleted.
func (r *HankoServiceAccountReconciler) ensureSASecret(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, kc *keycloak.Client) error {
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: saSecretName(sa.Spec.ClientID), Namespace: sa.Namespace}, &s)
	if err == nil {
		return nil
	}
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	// Secret missing — fetch current value from Keycloak without rotating.
	current, fetchErr := kc.GetClientSecret(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if fetchErr != nil {
		return fmt.Errorf("recover secret for %q: %w", sa.Spec.ClientID, fetchErr)
	}
	if upsertErr := r.upsertSASecret(ctx, sa, current); upsertErr != nil {
		return upsertErr
	}
	sa.Status.SecretRef = &hankoshv1alpha1.SecretReference{
		SecretRef: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: saSecretName(sa.Spec.ClientID)},
			Key:                  "client_secret",
		},
	}
	return nil
}

// maybeRotate rotates the client secret if the rotation policy demands it.
func (r *HankoServiceAccountReconciler) maybeRotate(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, p *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time, kc *keycloak.Client) error {
	if p == nil || !p.Enabled {
		sa.Status.NextRotation = nil
		return nil
	}
	if !serviceAccountRotationDue(sa, p, now) {
		setServiceAccountNextRotation(sa, p)
		return nil
	}
	logger := log.FromContext(ctx)
	logger.Info("rotating M2M client secret", "clientID", sa.Spec.ClientID)
	newSecret, err := kc.RotateClientSecret(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if err != nil {
		return fmt.Errorf("rotate secret for %q: %w", sa.Spec.ClientID, err)
	}
	// Write K8s secret before updating status: if this fails the controller will
	// retry rotation on the next reconcile (LastRotated not yet updated).
	if err := r.upsertSASecret(ctx, sa, newSecret); err != nil {
		return err
	}
	setServiceAccountSecretStatus(sa, now)
	setServiceAccountNextRotation(sa, p)
	r.Recorder.Eventf(sa, nil, corev1.EventTypeNormal, "SecretRotated", "Reconcile", "%s", fmt.Sprintf("M2M client secret rotated for %q", sa.Spec.ClientID))
	logger.Info("M2M client secret rotated", "clientID", sa.Spec.ClientID)
	return nil
}

func serviceAccountRotationDue(sa *hankoshv1alpha1.HankoServiceAccount, policy *hankoshv1alpha1.SecretRotationPolicy, now *metav1.Time) bool {
	if policy.ForceRotateAt != nil && !policy.ForceRotateAt.IsZero() && now.After(policy.ForceRotateAt.Time) &&
		(sa.Status.LastRotated == nil || sa.Status.LastRotated.Before(policy.ForceRotateAt)) {
		return true
	}
	if policy.IntervalDays <= 0 {
		return false
	}
	if sa.Status.LastRotated == nil {
		return true
	}
	return now.After(sa.Status.LastRotated.AddDate(0, 0, policy.IntervalDays))
}

func (r *HankoServiceAccountReconciler) upsertSASecret(ctx context.Context, sa *hankoshv1alpha1.HankoServiceAccount, secret string) error {
	name := saSecretName(sa.Spec.ClientID)
	s := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: sa.Namespace}, s)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if err != nil {
		s = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: sa.Namespace,
				Labels:    map[string]string{"app.kubernetes.io/managed-by": "hanko-operator"},
			},
			StringData: map[string]string{"client_secret": secret},
		}
		if err := controllerutil.SetControllerReference(sa, s, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference on SA secret: %w", err)
		}
		return r.Create(ctx, s)
	}
	p := client.MergeFrom(s.DeepCopy())
	s.StringData = map[string]string{"client_secret": secret}
	return r.Patch(ctx, s, p)
}

func saSecretName(clientID string) string { return "hanko-sa-" + clientID }

func (r *HankoServiceAccountReconciler) requestsForApplicationOwnership(ctx context.Context, obj client.Object) []reconcile.Request {
	application, ok := obj.(*hankoshv1alpha1.HankoApplication)
	if !ok {
		return nil
	}
	var accounts hankoshv1alpha1.HankoServiceAccountList
	if err := r.List(ctx, &accounts, client.InNamespace(application.Namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range accounts.Items {
		account := &accounts.Items[i]
		if account.Spec.RealmRef == application.Spec.RealmRef && strings.TrimSpace(account.Spec.ClientID) == strings.TrimSpace(application.Spec.ClientID) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: account.Name, Namespace: account.Namespace}})
		}
	}
	return requests
}

func (r *HankoServiceAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoServiceAccount{}).
		Watches(&hankoshv1alpha1.HankoApplication{}, handler.EnqueueRequestsFromMapFunc(r.requestsForApplicationOwnership)).
		Watches(&hankoshv1alpha1.HankoRealm{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []reconcile.Request {
				realm, ok := obj.(*hankoshv1alpha1.HankoRealm)
				if !ok {
					return nil
				}
				var accounts hankoshv1alpha1.HankoServiceAccountList
				if err := r.List(ctx, &accounts, client.InNamespace(realm.Namespace)); err != nil {
					return nil
				}
				requests := make([]reconcile.Request, 0)
				for i := range accounts.Items {
					if accounts.Items[i].Spec.RealmRef == realm.Name && accounts.Items[i].Spec.SecretRotationPolicy == nil {
						requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: accounts.Items[i].Name, Namespace: accounts.Items[i].Namespace}})
					}
				}
				return requests
			},
		)).
		Complete(r)
}
