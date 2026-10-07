package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/decommission"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/selfupdate"
	"github.com/Alien6-Studio/hankoshell-operator/internal/supervision"
	"github.com/Alien6-Studio/hankoshell-operator/internal/version"
)

const (
	meshPolicyDataKey         = "policy.json"
	meshPolicyStateAnnotation = "mesh.hanko.io/state"
	hankoOperatorFieldManager = "hanko-operator"
)

// HankoTenantReconciler reconciles HankoTenant objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankotenants,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankotenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankotenants/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankomeshservices,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,resourceNames=kube-system,verbs=get
type HankoTenantReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Pool   *keycloak.Pool
	// ClusterIdentityReader bypasses the namespace-scoped cache for the one
	// permitted GET of the kube-system Namespace during initial enrollment.
	ClusterIdentityReader client.Reader
	// Supervision collects the summary attached to successful heartbeats;
	// nil disables supervision reporting.
	Supervision *supervision.Collector
	// HubHTTPClient is scoped to private Hub synchronization. Enrollment uses
	// the public system trust store through hub.Enroll.
	HubHTTPClient *http.Client
	// HubTransportPolicy pins enterprise reconciliation to its private relay.
	// Nil retains the independently configurable standard installation.
	HubTransportPolicy *hub.ContinuumPolicy
	// MeshPolicyConfigMapName enables the audit-only signed policy projection
	// for the HankoTenant. Empty keeps the legacy heartbeat behavior.
	MeshPolicyConfigMapName string
	// MeshPolicyConfigMapNamespace optionally targets the namespace of the
	// Continuum node DaemonSet. Cross-namespace projections must be
	// pre-provisioned and bound to the operator by exact annotations.
	MeshPolicyConfigMapNamespace string
	// MeshPolicyProjectionClient bypasses the namespace-scoped manager cache
	// for an explicitly authorized cross-namespace projection.
	MeshPolicyProjectionClient client.Client
	// Decommission names the release-owned resources this operator may remove
	// when Hub delivers a decommission command on the heartbeat. Nil keeps the
	// command pending on Hub and the operator untouched.
	Decommission *decommission.Config
	// AgentUpdate identifies this operator's own Deployment for the
	// Hub-commanded digest-pinned self-update. Nil keeps the command pending
	// on Hub and the operator untouched.
	AgentUpdate *selfupdate.Config

	// degradedMu guards degradedDetail.
	degradedMu sync.Mutex
	// degradedDetail remembers, per tenant, the reason of the last reported
	// failure so successful heartbeats keep reporting one stable degraded
	// state — instead of flapping between Synced and Error on every cycle
	// while a Hub command stays blocked — until a reconcile fully completes.
	degradedDetail map[types.NamespacedName]string
}

func (r *HankoTenantReconciler) rememberDegraded(tenant *hankoshv1alpha1.HankoTenant, reason string) {
	r.degradedMu.Lock()
	defer r.degradedMu.Unlock()
	if r.degradedDetail == nil {
		r.degradedDetail = make(map[types.NamespacedName]string)
	}
	r.degradedDetail[client.ObjectKeyFromObject(tenant)] = reason
}

func (r *HankoTenantReconciler) clearDegraded(tenant *hankoshv1alpha1.HankoTenant) {
	r.degradedMu.Lock()
	defer r.degradedMu.Unlock()
	delete(r.degradedDetail, client.ObjectKeyFromObject(tenant))
}

func (r *HankoTenantReconciler) degradedReason(tenant *hankoshv1alpha1.HankoTenant) (string, bool) {
	r.degradedMu.Lock()
	defer r.degradedMu.Unlock()
	reason, exists := r.degradedDetail[client.ObjectKeyFromObject(tenant)]
	return reason, exists
}

// meshPolicyAuditReason reports whether a reconcile failure belongs to the
// audit-only mesh policy projection. Those failures happen after the Hub
// heartbeat, and the Hub refuses to serve the mesh policy to an operator whose
// last report was not Synced/healthy: letting them poison the sticky degraded
// state or the fleet phase would deadlock a recovering operator forever. They
// stay visible through the Synced condition and the quarantined projection.
func meshPolicyAuditReason(reason string) bool {
	switch reason {
	case "MeshPolicyStatusReportFailed", "MeshPolicyFetchFailed", "MeshPolicyProjectionFailed":
		return true
	}
	return false
}

func (r *HankoTenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { // NOSONAR -- reconciliation keeps each fail-closed state transition explicit.
	log := log.FromContext(ctx)

	var tenant hankoshv1alpha1.HankoTenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	patch := client.MergeFrom(tenant.DeepCopy())
	now := metav1.Now()
	tenant.Status.LastReconciled = &now
	if r.HubTransportPolicy != nil {
		if err := r.HubTransportPolicy.Validate(tenant.Spec.HubEndpoint, tenant.Spec.HubTransport,
			tenant.Spec.HubEnrollmentEndpoint, tenant.Spec.HubEnrollSecretRef != nil); err != nil {
			return r.setError(ctx, nil, &tenant, patch, "EnterpriseTransportRequired", err)
		}
	}

	// ── Read Hub credential (self-enroll only when the Secret is absent) ───────
	credentials, err := r.readHubCredentials(ctx, tenant.Namespace, tenant.Spec.HubTokenSecretRef.Name)
	if apierrors.IsNotFound(err) {
		if tenant.Status.ClusterID != "" {
			return r.setError(ctx, nil, &tenant, patch, "HubIdentityRecoveryRequired",
				fmt.Errorf("hub credential Secret %q is missing for registered cluster %q; recover credentials for this identity instead of enrolling again", tenant.Spec.HubTokenSecretRef.Name, tenant.Status.ClusterID))
		}
		if tenant.Spec.HubEnrollSecretRef == nil {
			return r.setError(ctx, nil, &tenant, patch, "HubTokenMissing", err)
		}
		credentials, err = r.enrollWithHub(ctx, &tenant)
		if err != nil {
			// A successful exchange owns a Hub identity even if local validation
			// or Secret persistence fails. Remember it rather than spending a new token.
			if credentials.ClusterID != "" {
				tenant.Status.ClusterID = credentials.ClusterID
				tenant.Status.TenantID = credentials.TenantID
			}
			return r.setError(ctx, nil, &tenant, patch, "HubEnrollFailed", err)
		}
	} else if err != nil {
		return r.setError(ctx, nil, &tenant, patch, "HubCredentialsInvalid", err)
	}

	// The tenant ID is either declared in the spec or learned at enrollment
	// and persisted next to the short-lived token.
	if r.HubTransportPolicy != nil && (credentials.ClusterID == "" || credentials.TenantID == "" ||
		credentials.ExpiresAt.IsZero() || !credentials.ExpiresAt.After(now.Time)) {
		return r.setError(ctx, nil, &tenant, patch, "EnterpriseCredentialInvalid",
			fmt.Errorf("enterprise Hub credentials require an identified tenant and cluster and a future expiration"))
	}
	tenantID := tenant.Spec.HubTenantID
	if tenantID == "" {
		tenantID = credentials.TenantID
	}
	if tenantID == "" {
		return r.setError(ctx, nil, &tenant, patch, "HubTenantIDUnknown",
			fmt.Errorf("hub tenant ID is absent from both spec and credential Secret"))
	}
	if credentials.TenantID != "" && tenantID != credentials.TenantID {
		return r.setError(ctx, nil, &tenant, patch, "HubTenantIDMismatch",
			fmt.Errorf("hub credential belongs to tenant %q, spec declares %q", credentials.TenantID, tenantID))
	}
	if (tenant.Status.ClusterID != "" && tenant.Status.ClusterID != credentials.ClusterID) ||
		(tenant.Status.TenantID != "" && tenant.Status.TenantID != tenantID) {
		return r.setError(ctx, nil, &tenant, patch, "HubIdentityMismatch",
			fmt.Errorf("hub credential Secret does not match the registered tenant/cluster identity; recover credentials for the existing identity"))
	}

	// Persist enrollment identity before synchronization can fail. Losing the
	// credential Secret after a failed first bundle must not create a new ID.
	if credentials.ClusterID != "" && (tenant.Status.ClusterID == "" || tenant.Status.TenantID == "") {
		tenant.Status.TenantID = tenantID
		tenant.Status.ClusterID = credentials.ClusterID
		if err := r.Status().Patch(ctx, &tenant, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("persist enrolled tenant identity: %w", err)
		}
		patch = client.MergeFrom(tenant.DeepCopy())
	}

	credentials, err = r.ensureHubCredential(ctx, &tenant, credentials, tenantID)
	if err != nil {
		return r.setError(ctx, nil, &tenant, patch, "HubCredentialRotationFailed", err)
	}
	// Legacy credentials may only acquire their bounded ID during rotation.
	// Preserve it even if a later bundle or mesh policy request fails.
	tenant.Status.TenantID = tenantID
	tenant.Status.ClusterID = credentials.ClusterID

	// ── Fetch bundle from Hub ─────────────────────────────────────────────────
	hubClient := hub.NewWithHTTPClient(tenant.Spec.HubEndpoint, tenantID, credentials.Token, r.HubHTTPClient)

	sb, err := hubClient.FetchBundle(ctx)
	if err != nil {
		return r.setError(ctx, hubClient, &tenant, patch, "BundleFetchFailed", err)
	}

	if !hubClient.VerifyBundle(sb) {
		return r.setError(ctx, hubClient, &tenant, patch, "BundleSignatureInvalid",
			fmt.Errorf("HMAC-SHA256 signature mismatch for bundle version %q", sb.Bundle.Version))
	}

	// ── Dedicated Keycloak client (keycloak / cluster isolation) ──────────────
	if reason, err := r.registerTenantKeycloak(ctx, &tenant); err != nil {
		return r.setError(ctx, hubClient, &tenant, patch, reason, err)
	}

	// ── Apply bundle resources ────────────────────────────────────────────────
	counts, err := r.applyBundle(ctx, &tenant, &sb.Bundle)
	if err != nil {
		return r.setError(ctx, hubClient, &tenant, patch, "BundleApplyFailed", err)
	}
	meshRegistrations, err := r.collectMeshRegistrations(ctx, &tenant, tenantID, credentials.ClusterID)
	if err != nil {
		return r.setError(ctx, hubClient, &tenant, patch, "MeshRegistrationInvalid", err)
	}
	counts["meshServices"] = len(meshRegistrations)

	// ── Report status to Hub ──────────────────────────────────────────────────
	phase, health, detail := "Synced", "healthy", ""
	if reason, blocked := r.degradedReason(&tenant); blocked {
		// A command or projection failed on a previous cycle. Report one
		// stable degraded state so the fleet view does not flap between
		// Synced and Error on every reconcile while the condition persists;
		// it is cleared only when a reconcile fully completes.
		phase, health, detail = "Error", "degraded", reason
	}
	status := hub.OperatorStatus{
		TenantID:          tenantID,
		BundleVersion:     sb.Bundle.Version,
		Phase:             phase,
		ResourceCount:     counts,
		AgentVersion:      version.Agent,
		Transport:         hubTransport(tenant.Spec.HubTransport),
		Health:            health,
		Detail:            detail,
		MeshRegistrations: &meshRegistrations,
	}
	if r.Supervision != nil {
		// Collected only on the success path: the error path stays cheap and
		// the Hub keeps the last summary with its own received timestamp.
		status.Supervision = r.Supervision.Collect(ctx)
	}
	ack, reportErr := hubClient.ReportStatus(ctx, status)
	if reportErr != nil {
		if r.MeshPolicyConfigMapName != "" {
			return r.setError(ctx, hubClient, &tenant, patch, "MeshPolicyStatusReportFailed", reportErr)
		}
		log.Error(reportErr, "report status to hub (non-fatal)")
	} else if ack != nil && ack.Decommission != nil {
		// Hub asked this operator to uninstall itself. Nothing else is worth
		// reconciling: run the ordered removal instead of finishing the sync.
		return r.executeDecommission(ctx, &tenant, patch, hubClient, ack.Decommission)
	} else if ack != nil && ack.AgentUpdate != nil {
		// Hub asked this operator to converge on the reference agent release.
		// The current sync already completed; restart on the pinned image.
		return r.executeAgentUpdate(ctx, &tenant, patch, hubClient, ack.AgentUpdate)
	} else if r.MeshPolicyConfigMapName != "" {
		envelope, fetchErr := hubClient.FetchMeshPolicy(ctx)
		if fetchErr != nil {
			return r.setError(ctx, hubClient, &tenant, patch, "MeshPolicyFetchFailed", fetchErr)
		}
		if projectionErr := r.projectMeshPolicy(ctx, &tenant, tenantID, credentials.ClusterID, envelope); projectionErr != nil {
			return r.setError(ctx, hubClient, &tenant, patch, "MeshPolicyProjectionFailed", projectionErr)
		}
	}

	// ── Update status ─────────────────────────────────────────────────────────
	syncTime := metav1.Now()
	tenant.Status.Phase = "Synced"
	tenant.Status.ObservedGeneration = tenant.Generation
	tenant.Status.TenantID = tenantID
	tenant.Status.ClusterID = credentials.ClusterID
	tenant.Status.BundleVersion = sb.Bundle.Version
	tenant.Status.ConnectedHub = tenant.Spec.HubEndpoint
	tenant.Status.LastSync = &syncTime
	setCondition(&tenant.Status.Conditions, "Synced", metav1.ConditionTrue, "BundleApplied",
		fmt.Sprintf("bundle %s applied successfully", sb.Bundle.Version))

	if err := r.Status().Patch(ctx, &tenant, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch tenant status: %w", err)
	}
	r.clearDegraded(&tenant)

	log.Info("HankoTenant reconciled", "tenant", tenant.Name, "bundle", sb.Bundle.Version)
	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

// executeDecommission runs the Hub-requested self-uninstall. Any refusal or
// failure is reported as an error phase so Hub keeps the command pending and
// re-delivers it on the next heartbeat; success ends with the deletion of the
// operator's own Deployment, so no requeue is scheduled.
func (r *HankoTenantReconciler) executeDecommission(
	ctx context.Context,
	tenant *hankoshv1alpha1.HankoTenant,
	patch client.Patch,
	hubClient *hub.Client,
	command *hub.DecommissionCommand,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("hub requested cluster decommission",
		"tenant", tenant.Name, "requestedAt", command.RequestedAt, "deadline", command.Deadline)

	if r.Decommission == nil {
		return r.setError(ctx, hubClient, tenant, patch, "DecommissionUnsupported",
			errors.New("this operator deployment is not configured for remote decommission; uninstall it with the reviewed manual procedure"))
	}

	config := *r.Decommission
	if strings.TrimSpace(config.Namespace) == "" {
		config.Namespace = tenant.Namespace
	}
	config.TenantName = tenant.Name
	config.CredentialSecretName = tenant.Spec.HubTokenSecretRef.Name

	// The transport is subordinate to the hub-spoke link: tearing it down is
	// part of breaking the link, executed right after the confirmation that
	// still travels over it. Without the transport release identity the
	// removal stays fail-closed and the command pending on Hub.
	if hubTransport(tenant.Spec.HubTransport) == "continuum" && config.Transport == nil {
		return r.setError(ctx, hubClient, tenant, patch, "DecommissionBlocked",
			errors.New("continuum tenant transport teardown is not configured; set the transport decommission release for this operator"))
	}
	if r.MeshPolicyConfigMapName != "" {
		config.MeshProjection = &decommission.MeshProjectionConfig{
			Namespace:     r.meshPolicyProjectionNamespace(tenant.Namespace),
			ConfigMapName: r.MeshPolicyConfigMapName,
			WriterName:    config.ReleaseName + "-mesh-policy",
		}
	}

	engine := &decommission.Engine{
		Writer:  r.Client,
		Reader:  r.ClusterIdentityReader,
		Config:  config,
		Confirm: hubClient.ConfirmDecommission,
	}
	removed, err := engine.Run(ctx)
	if errors.Is(err, decommission.ErrAfterConfirmation) {
		// The receipt is recorded and the credential surrendered: Hub cannot
		// re-deliver the command, so the residue is logged once for the
		// reviewed manual cleanup instead of looping on a revoked credential.
		logger.Error(err, "decommission confirmed with local residue", "removedResources", removed)
		return ctrl.Result{}, nil
	}
	if err != nil {
		return r.setError(ctx, hubClient, tenant, patch, "DecommissionFailed", err)
	}
	logger.Info("cluster decommission complete; operator deletion accepted", "removedResources", removed)
	return ctrl.Result{}, nil
}

func (r *HankoTenantReconciler) projectMeshPolicy( // NOSONAR -- projection validates ownership and immutable identity in one auditable path.
	ctx context.Context,
	tenant *hankoshv1alpha1.HankoTenant,
	tenantID, clusterID string,
	envelope []byte,
) error {
	name := strings.TrimSpace(r.MeshPolicyConfigMapName)
	if problems := validation.IsDNS1123Subdomain(name); len(problems) != 0 {
		return fmt.Errorf("mesh policy ConfigMap name is invalid: %s", strings.Join(problems, "; "))
	}
	namespace := r.meshPolicyProjectionNamespace(tenant.Namespace)
	if problems := validation.IsDNS1123Label(namespace); len(problems) != 0 {
		return fmt.Errorf("mesh policy ConfigMap namespace is invalid: %s", strings.Join(problems, "; "))
	}
	if len(envelope) == 0 || len(envelope) > 1<<20 || !json.Valid(envelope) {
		return fmt.Errorf("mesh policy envelope is empty, oversized, or invalid JSON")
	}
	projectionClient := r.meshPolicyProjectionClient()
	key := types.NamespacedName{Namespace: namespace, Name: name}
	var configMap corev1.ConfigMap
	err := projectionClient.Get(ctx, key, &configMap)
	if apierrors.IsNotFound(err) {
		if namespace != tenant.Namespace {
			return fmt.Errorf("cross-namespace mesh policy ConfigMap %q must be pre-provisioned", name)
		}
		configMap = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Data:       map[string]string{meshPolicyDataKey: string(envelope)},
		}
		configMap.Labels = meshPolicyProjectionLabels(tenantID, clusterID)
		configMap.Annotations = map[string]string{"mesh.hanko.io/mode": "audit-only", meshPolicyStateAnnotation: "current"}
		if err := controllerutil.SetControllerReference(tenant, &configMap, r.Scheme); err != nil {
			return fmt.Errorf("set mesh policy ConfigMap owner: %w", err)
		}
		if err := projectionClient.Create(ctx, &configMap); err != nil {
			return fmt.Errorf("create mesh policy ConfigMap: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get mesh policy ConfigMap: %w", err)
	}
	if !authorizedMeshPolicyProjection(&configMap, tenant) {
		return fmt.Errorf("mesh policy ConfigMap %q is not controlled by HankoTenant %q", name, tenant.Name)
	}
	configMap.Data = map[string]string{meshPolicyDataKey: string(envelope)}
	configMap.BinaryData = nil
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}
	for key, value := range meshPolicyProjectionLabels(tenantID, clusterID) {
		if key == "app.kubernetes.io/managed-by" && configMap.Labels[key] != "" {
			continue
		}
		configMap.Labels[key] = value
	}
	if configMap.Annotations == nil {
		configMap.Annotations = make(map[string]string)
	}
	configMap.Annotations["mesh.hanko.io/mode"] = "audit-only"
	configMap.Annotations[meshPolicyStateAnnotation] = "current"
	if err := projectionClient.Update(ctx, &configMap); err != nil {
		return fmt.Errorf("update mesh policy ConfigMap: %w", err)
	}
	return nil
}

func (r *HankoTenantReconciler) meshPolicyProjectionNamespace(tenantNamespace string) string {
	if namespace := strings.TrimSpace(r.MeshPolicyConfigMapNamespace); namespace != "" {
		return namespace
	}
	return tenantNamespace
}

func (r *HankoTenantReconciler) meshPolicyProjectionClient() client.Client {
	if r.MeshPolicyProjectionClient != nil {
		return r.MeshPolicyProjectionClient
	}
	return r.Client
}

func authorizedMeshPolicyProjection(configMap *corev1.ConfigMap, tenant *hankoshv1alpha1.HankoTenant) bool {
	if configMap.Namespace == tenant.Namespace {
		return metav1.IsControlledBy(configMap, tenant)
	}
	annotations := configMap.GetAnnotations()
	return annotations["mesh.hanko.io/projection"] == hankoOperatorFieldManager &&
		annotations["mesh.hanko.io/operator-namespace"] == tenant.Namespace &&
		annotations["mesh.hanko.io/tenant-name"] == tenant.Name
}

func meshPolicyProjectionLabels(tenantID, clusterID string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": hankoOperatorFieldManager,
		"mesh.hanko.io/tenant-sha256":  sha256LabelValue(tenantID),
		"mesh.hanko.io/cluster-sha256": sha256LabelValue(clusterID),
	}
}

func sha256LabelValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (r *HankoTenantReconciler) quarantineMeshPolicyProjection(ctx context.Context, tenant *hankoshv1alpha1.HankoTenant) {
	if r.MeshPolicyConfigMapName == "" {
		return
	}
	projectionClient := r.meshPolicyProjectionClient()
	var configMap corev1.ConfigMap
	if err := projectionClient.Get(ctx, types.NamespacedName{
		Namespace: r.meshPolicyProjectionNamespace(tenant.Namespace), Name: r.MeshPolicyConfigMapName,
	}, &configMap); err != nil {
		return
	}
	if !authorizedMeshPolicyProjection(&configMap, tenant) {
		return
	}
	configMap.Data = map[string]string{meshPolicyDataKey: "{}"}
	configMap.BinaryData = nil
	if configMap.Annotations == nil {
		configMap.Annotations = make(map[string]string)
	}
	configMap.Annotations[meshPolicyStateAnnotation] = "quarantined"
	_ = projectionClient.Update(ctx, &configMap)
}

func (r *HankoTenantReconciler) collectMeshRegistrations(ctx context.Context, tenant *hankoshv1alpha1.HankoTenant, tenantID, clusterID string) ([]hub.MeshRegistration, error) { // NOSONAR -- registration joins remain explicit to preserve tenant isolation.
	var registrations hankoshv1alpha1.HankoMeshServiceList
	if err := r.List(ctx, &registrations, client.InNamespace(tenant.Namespace)); err != nil {
		return nil, fmt.Errorf("list HankoMeshService registrations: %w", err)
	}
	result := make([]hub.MeshRegistration, 0, len(registrations.Items))
	workloadIDs := make(map[string]string)
	audiences := make(map[string]string)
	for index := range registrations.Items {
		registration := &registrations.Items[index]
		if registration.Spec.TenantRef != tenant.Name {
			continue
		}
		status := registration.Status
		if status.Phase != "Ready" || status.ObservedGeneration != registration.Generation ||
			status.TenantID != tenantID || status.ClusterID != clusterID {
			continue
		}
		if status.ReceiverNodeUIDs == nil {
			continue
		}
		if previous, exists := workloadIDs[status.WorkloadID]; exists {
			return nil, fmt.Errorf("mesh services %q and %q resolve to duplicate workload ID %q", previous, registration.Name, status.WorkloadID)
		}
		workloadIDs[status.WorkloadID] = registration.Name
		if previous, exists := audiences[status.Audience]; exists {
			return nil, fmt.Errorf("mesh services %q and %q resolve to duplicate audience %q", previous, registration.Name, status.Audience)
		}
		audiences[status.Audience] = registration.Name
		ports := make([]hub.MeshPort, len(status.ResolvedPorts))
		for portIndex := range status.ResolvedPorts {
			port := status.ResolvedPorts[portIndex]
			if port.Port < 1 || port.Port > 65535 {
				return nil, fmt.Errorf("mesh service %q has invalid resolved port %d", registration.Name, port.Port)
			}
			ports[portIndex] = hub.MeshPort{Protocol: port.Protocol, Port: uint16(port.Port)}
		}
		egress := make([]hub.MeshEgress, len(status.ResolvedEgress))
		for egressIndex := range status.ResolvedEgress {
			resolvedEgress := status.ResolvedEgress[egressIndex]
			egressPorts := make([]hub.MeshPort, len(resolvedEgress.Ports))
			for portIndex := range resolvedEgress.Ports {
				port := resolvedEgress.Ports[portIndex]
				if port.Port < 1 || port.Port > 65535 {
					return nil, fmt.Errorf("mesh service %q has invalid reviewed egress port %d", registration.Name, port.Port)
				}
				egressPorts[portIndex] = hub.MeshPort{Protocol: port.Protocol, Port: uint16(port.Port)}
			}
			egress[egressIndex] = hub.MeshEgress{
				Namespace: resolvedEgress.Namespace, ServiceName: resolvedEgress.ServiceName,
				ServiceUID: resolvedEgress.ServiceUID, Ports: egressPorts,
			}
		}
		result = append(result, hub.MeshRegistration{
			Name: registration.Name, Namespace: registration.Namespace,
			Realm:       status.Realm,
			IdentityRef: registration.Spec.IdentityRef, ResourceServerRef: registration.Spec.ResourceServerRef,
			WorkloadID: status.WorkloadID, Audience: status.Audience,
			ServiceName: registration.Spec.ServiceRef, ServiceUID: status.ServiceUID,
			ServiceAccountName: registration.Spec.WorkloadServiceAccountRef,
			ServiceAccountUID:  status.WorkloadServiceAccountUID,
			SelectorSHA256:     status.SelectorSHA256,
			EnforcementMode:    status.EnforcementMode,
			ReceiverNodeUIDs:   append([]string{}, status.ReceiverNodeUIDs...),
			Ports:              ports,
			Egress:             egress,
		})
	}
	if len(result) > 4096 {
		return nil, fmt.Errorf("mesh registration snapshot exceeds 4096 services")
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Namespace != result[right].Namespace {
			return result[left].Namespace < result[right].Namespace
		}
		return result[left].Name < result[right].Name
	})
	return result, nil
}

type storedHubCredentials struct {
	Token           string
	TenantID        string
	ClusterID       string
	ExpiresAt       time.Time
	RotationID      string
	RotationPending bool
}

const credentialRotationLeadTime = 6 * time.Hour

// enrollWithHub exchanges the single-use enrollment token referenced by
// spec.hubEnrollSecretRef for a bounded Hub credential and persists it in the
// Secret referenced by spec.hubTokenSecretRef.
func (r *HankoTenantReconciler) enrollWithHub(ctx context.Context, tenant *hankoshv1alpha1.HankoTenant) (storedHubCredentials, error) {
	identity, err := r.enrollmentIdentity(ctx, tenant.Spec.ClusterName)
	if err != nil {
		return storedHubCredentials{}, err
	}
	enrollToken, err := r.readSecret(ctx, tenant.Namespace, tenant.Spec.HubEnrollSecretRef.Name, "enroll_token")
	if err != nil {
		return storedHubCredentials{}, err
	}
	enrollmentEndpoint := tenant.Spec.HubEnrollmentEndpoint
	if enrollmentEndpoint == "" {
		enrollmentEndpoint = tenant.Spec.HubEndpoint
	}
	var res *hub.EnrollResult
	if r.HubTransportPolicy != nil {
		res, err = r.HubTransportPolicy.Enroll(ctx, enrollToken, identity)
	} else {
		res, err = hub.EnrollWithIdentity(ctx, enrollmentEndpoint, enrollToken, identity)
	}
	if err != nil {
		return storedHubCredentials{}, err
	}
	if tenant.Spec.HubTenantID != "" && tenant.Spec.HubTenantID != res.TenantID {
		return storedHubCredentials{TenantID: res.TenantID, ClusterID: res.ClusterID}, fmt.Errorf("enrolled identity belongs to tenant %q, spec declares %q; recover or revoke this identity before another enrollment", res.TenantID, tenant.Spec.HubTenantID)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenant.Spec.HubTokenSecretRef.Name,
			Namespace: tenant.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"hub_token":  []byte(res.Token),
			"tenant_id":  []byte(res.TenantID),
			"cluster_id": []byte(res.ClusterID),
			"expires_at": []byte(res.ExpiresAt.Format(time.RFC3339Nano)),
		},
	}
	if err := r.Create(ctx, secret); err != nil {
		return storedHubCredentials{TenantID: res.TenantID, ClusterID: res.ClusterID}, fmt.Errorf("persist hub credentials in secret %q: %w; recover this enrolled identity before retrying", secret.Name, err)
	}
	log.FromContext(ctx).Info("enrolled with hub", "tenantID", res.TenantID, "clusterID", res.ClusterID)
	return storedHubCredentials{Token: res.Token, TenantID: res.TenantID, ClusterID: res.ClusterID, ExpiresAt: res.ExpiresAt}, nil
}

func (r *HankoTenantReconciler) readHubCredentials(ctx context.Context, namespace, name string) (storedHubCredentials, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret); err != nil {
		return storedHubCredentials{}, err
	}
	credentials := storedHubCredentials{
		Token:      string(secret.Data["hub_token"]),
		TenantID:   string(secret.Data["tenant_id"]),
		ClusterID:  string(secret.Data["cluster_id"]),
		RotationID: string(secret.Data["rotation_id"]),
	}
	if credentials.Token == "" {
		return storedHubCredentials{}, fmt.Errorf("secret %q has no non-empty key %q", name, "hub_token")
	}
	if value := string(secret.Data["expires_at"]); value != "" {
		expiresAt, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return storedHubCredentials{}, fmt.Errorf("secret %q has invalid expires_at: %w", name, err)
		}
		credentials.ExpiresAt = expiresAt
	}
	if value := string(secret.Data["rotation_pending"]); value != "" {
		if value != "true" {
			return storedHubCredentials{}, fmt.Errorf("secret %q has invalid rotation_pending marker", name)
		}
		credentials.RotationPending = true
		if credentials.RotationID == "" {
			return storedHubCredentials{}, fmt.Errorf("secret %q marks a pending rotation without rotation_id", name)
		}
	}
	return credentials, nil
}

func (r *HankoTenantReconciler) ensureHubCredential( // NOSONAR -- rotation is an ordered fail-closed credential state machine.
	ctx context.Context,
	tenant *hankoshv1alpha1.HankoTenant,
	credentials storedHubCredentials,
	tenantID string,
) (storedHubCredentials, error) {
	secretKey := types.NamespacedName{Namespace: tenant.Namespace, Name: tenant.Spec.HubTokenSecretRef.Name}
	var secret corev1.Secret
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		return storedHubCredentials{}, fmt.Errorf("load Hub credential secret for rotation: %w", err)
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}

	if credentials.RotationPending {
		client := hub.NewWithHTTPClient(tenant.Spec.HubEndpoint, tenantID, credentials.Token, r.HubHTTPClient)
		if err := client.ConfirmRotation(ctx); err != nil {
			return storedHubCredentials{}, err
		}
		delete(secret.Data, "rotation_id")
		delete(secret.Data, "rotation_pending")
		if err := r.Update(ctx, &secret); err != nil {
			return storedHubCredentials{}, fmt.Errorf("clear confirmed Hub credential rotation state: %w", err)
		}
		credentials.RotationID = ""
		credentials.RotationPending = false
		return credentials, nil
	}

	if credentials.RotationID == "" && !credentials.ExpiresAt.IsZero() && time.Until(credentials.ExpiresAt) > credentialRotationLeadTime {
		return credentials, nil
	}

	if credentials.RotationID == "" {
		rotationID, err := newRotationID()
		if err != nil {
			return storedHubCredentials{}, err
		}
		credentials.RotationID = rotationID
		secret.Data["rotation_id"] = []byte(rotationID)
		if err := r.Update(ctx, &secret); err != nil {
			return storedHubCredentials{}, fmt.Errorf("persist Hub credential rotation ID: %w", err)
		}
	}

	currentClient := hub.NewWithHTTPClient(tenant.Spec.HubEndpoint, tenantID, credentials.Token, r.HubHTTPClient)
	rotated, err := currentClient.PrepareRotation(ctx, credentials.RotationID)
	if err != nil {
		return storedHubCredentials{}, err
	}
	if rotated.TenantID != tenantID {
		return storedHubCredentials{}, fmt.Errorf("rotated credential belongs to tenant %q, want %q", rotated.TenantID, tenantID)
	}
	if credentials.ClusterID != "" && rotated.ClusterID != credentials.ClusterID {
		return storedHubCredentials{}, fmt.Errorf("rotated credential belongs to cluster %q, want %q", rotated.ClusterID, credentials.ClusterID)
	}

	if err := r.Get(ctx, secretKey, &secret); err != nil {
		return storedHubCredentials{}, fmt.Errorf("reload Hub credential secret after rotation prepare: %w", err)
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data["hub_token"] = []byte(rotated.Token)
	secret.Data["tenant_id"] = []byte(rotated.TenantID)
	secret.Data["cluster_id"] = []byte(rotated.ClusterID)
	secret.Data["expires_at"] = []byte(rotated.ExpiresAt.Format(time.RFC3339Nano))
	secret.Data["rotation_id"] = []byte(credentials.RotationID)
	secret.Data["rotation_pending"] = []byte("true")
	if err := r.Update(ctx, &secret); err != nil {
		return storedHubCredentials{}, fmt.Errorf("persist pending Hub credential: %w", err)
	}

	credentials.Token = rotated.Token
	credentials.TenantID = rotated.TenantID
	credentials.ClusterID = rotated.ClusterID
	credentials.ExpiresAt = rotated.ExpiresAt
	credentials.RotationPending = true
	newClient := hub.NewWithHTTPClient(tenant.Spec.HubEndpoint, tenantID, credentials.Token, r.HubHTTPClient)
	if err := newClient.ConfirmRotation(ctx); err != nil {
		return storedHubCredentials{}, err
	}

	if err := r.Get(ctx, secretKey, &secret); err != nil {
		return storedHubCredentials{}, fmt.Errorf("reload Hub credential secret after confirmation: %w", err)
	}
	delete(secret.Data, "rotation_id")
	delete(secret.Data, "rotation_pending")
	if err := r.Update(ctx, &secret); err != nil {
		return storedHubCredentials{}, fmt.Errorf("clear confirmed Hub credential rotation state: %w", err)
	}
	credentials.RotationID = ""
	credentials.RotationPending = false
	return credentials, nil
}

func newRotationID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate Hub credential rotation ID: %w", err)
	}
	return "rot_" + hex.EncodeToString(raw), nil
}

func (r *HankoTenantReconciler) registerTenantKeycloak(ctx context.Context, tenant *hankoshv1alpha1.HankoTenant) (string, error) {
	if tenant.Spec.IsolationMode != "keycloak" && tenant.Spec.IsolationMode != "cluster" {
		return "", nil
	}
	if tenant.Spec.KeycloakSecretRef == nil {
		return "KeycloakSecretRefMissing", fmt.Errorf("isolationMode %q requires keycloakSecretRef", tenant.Spec.IsolationMode)
	}
	secretName := tenant.Spec.KeycloakSecretRef.Name
	values := make([]string, 3)
	for index, key := range []string{"HANKO_KEYCLOAK_URL", "HANKO_KC_CLIENT_ID", "HANKO_KC_CLIENT_SECRET"} {
		value, err := r.readSecret(ctx, tenant.Namespace, secretName, key)
		if err != nil {
			return "KeycloakSecretReadFailed", err
		}
		values[index] = value
	}
	tenantKey := tenant.Namespace + "/" + tenant.Name
	kc := keycloak.New(values[0], values[1], values[2])
	if r.HubTransportPolicy != nil {
		if err := kc.RequireHTTPS(); err != nil {
			return "EnterpriseKeycloakHTTPSRequired", err
		}
	}
	r.Pool.Register(tenantKey, kc)
	log.FromContext(ctx).Info("registered dedicated Keycloak client", "tenantKey", tenantKey)
	return "", nil
}

// applyBundle patches each resource from the bundle into Kubernetes using
// server-side apply. It returns the count of applied resources per type.
func (r *HankoTenantReconciler) applyBundle(
	ctx context.Context,
	tenant *hankoshv1alpha1.HankoTenant,
	bundle *hub.Bundle,
) (map[string]int, error) {
	counts := map[string]int{
		"iamProfiles":     0,
		"realms":          0,
		"apps":            0,
		"themes":          0,
		"serviceAccounts": 0,
	}
	ssaOpts := []client.PatchOption{
		client.FieldOwner(hankoOperatorFieldManager),
		client.ForceOwnership,
	}
	tenantLabel := map[string]string{"hanko.sh/tenant": tenant.Name}

	var err error
	base := bundleApplyOptions{client: r.Client, namespace: tenant.Namespace, labels: tenantLabel, patchOptions: ssaOpts}
	counts["iamProfiles"], err = applyBundleObjects(ctx, bundle.IAMProfiles, base.withType("IAM profile", func() client.Object { return &hankoshv1alpha1.HankoIAMProfile{} }))
	if err != nil {
		return counts, err
	}
	counts["realms"], err = applyBundleObjects(ctx, bundle.Realms, base.withType("realm", func() client.Object { return &hankoshv1alpha1.HankoRealm{} }))
	if err != nil {
		return counts, err
	}
	counts["apps"], err = applyBundleObjects(ctx, bundle.Apps, base.withType("application", func() client.Object { return &hankoshv1alpha1.HankoApplication{} }))
	if err != nil {
		return counts, err
	}
	counts["themes"], err = applyBundleObjects(ctx, bundle.Themes, base.withType("theme", func() client.Object { return &hankoshv1alpha1.HankoTheme{} }))
	if err != nil {
		return counts, err
	}
	counts["serviceAccounts"], err = applyBundleObjects(ctx, bundle.ServiceAccounts, base.withType("service account", func() client.Object { return &hankoshv1alpha1.HankoServiceAccount{} }))
	if err != nil {
		return counts, err
	}

	return counts, nil
}

type bundleApplyOptions struct {
	client       client.Client
	namespace    string
	labels       map[string]string
	patchOptions []client.PatchOption
	newObject    func() client.Object
	kind         string
}

func (options bundleApplyOptions) withType(kind string, newObject func() client.Object) bundleApplyOptions {
	options.kind = kind
	options.newObject = newObject
	return options
}

func applyBundleObjects(ctx context.Context, objects []json.RawMessage, options bundleApplyOptions) (int, error) {
	for index, raw := range objects {
		object := options.newObject()
		if err := json.Unmarshal(raw, object); err != nil {
			return index, fmt.Errorf("unmarshal %s: %w", options.kind, err)
		}
		object.SetNamespace(options.namespace)
		mergedLabels := object.GetLabels()
		mergeLabels(&mergedLabels, options.labels)
		object.SetLabels(mergedLabels)
		if err := options.client.Patch(ctx, object, client.Apply, options.patchOptions...); err != nil {
			return index, fmt.Errorf("apply %s %q: %w", options.kind, object.GetName(), err)
		}
	}
	return len(objects), nil
}

func (r *HankoTenantReconciler) setError(
	ctx context.Context,
	hubClient *hub.Client,
	tenant *hankoshv1alpha1.HankoTenant,
	patch client.Patch,
	reason string,
	err error,
) (ctrl.Result, error) {
	log.FromContext(ctx).Error(err, "tenant reconcile error", "reason", reason)
	if !meshPolicyAuditReason(reason) {
		r.rememberDegraded(tenant, reason)
	}
	r.quarantineMeshPolicyProjection(ctx, tenant)
	tenant.Status.Phase = "Error"
	tenant.Status.ObservedGeneration = tenant.Generation
	setCondition(&tenant.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
	if patchErr := r.Status().Patch(ctx, tenant, patch); patchErr != nil {
		log.FromContext(ctx).Error(patchErr, "patch tenant status after error")
	}
	// Best-effort degraded report so the fleet view reflects the failure
	// instead of showing the last successful phase until staleness kicks in.
	// Only the error reason is sent — never the full error, which may embed
	// resource names or endpoints the hub has no need to store. Audit-only
	// mesh policy failures are excluded: reporting Error for them would make
	// the Hub keep refusing the policy that the next cycle needs to recover.
	if hubClient != nil && !meshPolicyAuditReason(reason) {
		emptyMeshRegistrations := []hub.MeshRegistration{}
		if _, reportErr := hubClient.ReportStatus(ctx, hub.OperatorStatus{
			TenantID:          tenant.Spec.HubTenantID,
			BundleVersion:     tenant.Status.BundleVersion,
			Phase:             "Error",
			AgentVersion:      version.Agent,
			Transport:         hubTransport(tenant.Spec.HubTransport),
			Health:            "degraded",
			Detail:            reason,
			MeshRegistrations: &emptyMeshRegistrations,
		}); reportErr != nil {
			log.FromContext(ctx).Error(reportErr, "report degraded status to hub (non-fatal)")
		}
	}
	// The Result alone carries the retry cadence. Returning an error as well
	// would make controller-runtime discard the Result and requeue with its
	// own exponential backoff starting near zero, flooding Hub with
	// alternating status reports while a command stays blocked.
	return ctrl.Result{RequeueAfter: requeueOnError}, nil
}

func hubTransport(value string) string {
	if value == "continuum" {
		return value
	}
	return "direct"
}

func (r *HankoTenantReconciler) readSecret(ctx context.Context, namespace, name, key string) (string, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s); err != nil {
		return "", fmt.Errorf("get secret %q: %w", name, err)
	}
	val, ok := s.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %q has no key %q", name, key)
	}
	return string(val), nil
}

func mergeLabels(dst *map[string]string, src map[string]string) {
	if *dst == nil {
		*dst = make(map[string]string, len(src))
	}
	maps.Copy(*dst, src)
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *HankoTenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoTenant{}).
		Complete(r)
}
