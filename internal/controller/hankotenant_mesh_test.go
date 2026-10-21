package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

func readyMeshRegistration(name, workloadID, audience string) *hankoshv1alpha1.HankoMeshService {
	return &hankoshv1alpha1.HankoMeshService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Generation: 2},
		Spec: hankoshv1alpha1.HankoMeshServiceSpec{
			TenantRef: "acme", IdentityRef: name + "-identity", ResourceServerRef: name + "-api",
			ServiceRef: name, WorkloadServiceAccountRef: name,
		},
		Status: hankoshv1alpha1.HankoMeshServiceStatus{
			Phase: "Ready", ObservedGeneration: 2, TenantID: "ten_acme", ClusterID: "cluster-a",
			WorkloadID: workloadID, Audience: audience, Realm: "acme",
			ServiceUID:                "11111111-1111-1111-1111-111111111111",
			WorkloadServiceAccountUID: "22222222-2222-2222-2222-222222222222",
			SelectorSHA256:            strings.Repeat("a", 64),
			ReceiverNodeUIDs:          []string{},
			ResolvedPorts:             []hankoshv1alpha1.MeshServicePort{{Protocol: "TCP", Port: 8443}},
		},
	}
}

func TestTenantProjectsAndQuarantinesOpaqueMeshPolicy(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme", Namespace: "apps", UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		},
	}
	store := meshServiceClient(t, tenant)
	reconciler := &HankoTenantReconciler{
		Client: store, Scheme: meshServiceScheme(t), MeshPolicyConfigMapName: "hanko-mesh-policy",
	}
	envelope := []byte(`{"algorithm":"Ed25519","keyId":"opaque","payload":"opaque","signature":"opaque"}`)
	if err := reconciler.projectMeshPolicy(context.Background(), tenant, "ten_acme", "cluster-a", envelope); err != nil {
		t.Fatal(err)
	}
	var projected corev1.ConfigMap
	key := types.NamespacedName{Namespace: "apps", Name: "hanko-mesh-policy"}
	if err := store.Get(context.Background(), key, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Data["policy.json"] != string(envelope) ||
		projected.Annotations["mesh.hanko.io/mode"] != "audit-only" ||
		projected.Annotations["mesh.hanko.io/state"] != "current" ||
		!metav1.IsControlledBy(&projected, tenant) {
		t.Fatalf("unexpected projection: %#v", projected)
	}
	if len(projected.Labels["mesh.hanko.io/tenant-sha256"]) != 43 ||
		len(projected.Labels["mesh.hanko.io/cluster-sha256"]) != 43 {
		t.Fatalf("raw trust-context identifiers leaked into labels: %#v", projected.Labels)
	}
	for key, value := range projected.Labels {
		if problems := validation.IsValidLabelValue(value); len(problems) != 0 {
			t.Fatalf("projection label %q is invalid: %v", key, problems)
		}
	}

	reconciler.quarantineMeshPolicyProjection(context.Background(), tenant)
	if err := store.Get(context.Background(), key, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Data["policy.json"] != "{}" || projected.Annotations["mesh.hanko.io/state"] != "quarantined" {
		t.Fatalf("projection was not quarantined: %#v", projected)
	}
}

func TestTenantProjectsOnlyIntoPreauthorizedCrossNamespaceConfigMap(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme", Namespace: "apps", UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		},
	}
	projection := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hanko-mesh-policy", Namespace: "continuum-system",
			Labels: map[string]string{"app.kubernetes.io/managed-by": "Helm"},
			Annotations: map[string]string{
				"mesh.hanko.io/projection":         "hanko-operator",
				"mesh.hanko.io/operator-namespace": "apps",
				"mesh.hanko.io/tenant-name":        "acme",
			},
		},
		Data: map[string]string{"policy.json": "{}"},
	}
	store := meshServiceClient(t, tenant, projection)
	reconciler := &HankoTenantReconciler{
		Client: store, Scheme: meshServiceScheme(t),
		MeshPolicyConfigMapName: "hanko-mesh-policy", MeshPolicyConfigMapNamespace: "continuum-system",
		MeshPolicyProjectionClient: store,
	}
	envelope := []byte(`{"algorithm":"Ed25519","keyId":"opaque","payload":"opaque","signature":"opaque"}`)
	if err := reconciler.projectMeshPolicy(context.Background(), tenant, "ten_acme", "cluster-a", envelope); err != nil {
		t.Fatal(err)
	}
	var projected corev1.ConfigMap
	key := types.NamespacedName{Namespace: "continuum-system", Name: "hanko-mesh-policy"}
	if err := store.Get(context.Background(), key, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Data["policy.json"] != string(envelope) ||
		projected.Annotations["mesh.hanko.io/state"] != "current" ||
		projected.Labels["app.kubernetes.io/managed-by"] != "Helm" ||
		len(projected.OwnerReferences) != 0 {
		t.Fatalf("unexpected cross-namespace projection: %#v", projected)
	}

	reconciler.quarantineMeshPolicyProjection(context.Background(), tenant)
	if err := store.Get(context.Background(), key, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Data["policy.json"] != "{}" || projected.Annotations["mesh.hanko.io/state"] != "quarantined" {
		t.Fatalf("cross-namespace projection was not quarantined: %#v", projected)
	}

	projected.Annotations["mesh.hanko.io/tenant-name"] = "another-tenant"
	if err := store.Update(context.Background(), &projected); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.projectMeshPolicy(context.Background(), tenant, "ten_acme", "cluster-a", envelope); err == nil {
		t.Fatal("foreign cross-namespace projection was accepted")
	}
}

func TestTenantRefusesToCreateCrossNamespaceProjection(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps"}}
	store := meshServiceClient(t, tenant)
	reconciler := &HankoTenantReconciler{
		Client: store, Scheme: meshServiceScheme(t),
		MeshPolicyConfigMapName: "hanko-mesh-policy", MeshPolicyConfigMapNamespace: "continuum-system",
		MeshPolicyProjectionClient: store,
	}
	if err := reconciler.projectMeshPolicy(
		context.Background(), tenant, "ten_acme", "cluster-a", []byte(`{"algorithm":"Ed25519"}`),
	); err == nil || !strings.Contains(err.Error(), "must be pre-provisioned") {
		t.Fatalf("missing cross-namespace projection error = %v", err)
	}
}

func TestTenantCollectsOnlyCurrentReadyMeshRegistrations(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps"}}
	ready := readyMeshRegistration("orders", "orders-api", "https://orders.internal")
	stale := readyMeshRegistration("stale", "stale-api", "https://stale.internal")
	stale.Generation = 3
	other := readyMeshRegistration("other", "other-api", "https://other.internal")
	other.Spec.TenantRef = "other"
	store := meshServiceClient(t, []client.Object{tenant, ready, stale, other}...)
	reconciler := &HankoTenantReconciler{Client: store}

	registrations, err := reconciler.collectMeshRegistrations(context.Background(), tenant, "ten_acme", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || registrations[0].Name != "orders" || registrations[0].Realm != "acme" || registrations[0].WorkloadID != "orders-api" || registrations[0].Ports[0].Port != 8443 || registrations[0].ReceiverNodeUIDs == nil {
		t.Fatalf("unexpected mesh registrations: %#v", registrations)
	}
}

func TestTenantSkipsLegacyReadyMeshRegistrationWithoutReceiverNodeSnapshot(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps"}}
	legacy := readyMeshRegistration("orders", "orders-api", "https://orders.internal")
	legacy.Status.ReceiverNodeUIDs = nil
	store := meshServiceClient(t, tenant, legacy)
	reconciler := &HankoTenantReconciler{Client: store}

	registrations, err := reconciler.collectMeshRegistrations(context.Background(), tenant, "ten_acme", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 0 {
		t.Fatalf("legacy status without receiver-node attestation was reported: %#v", registrations)
	}
}

func TestTenantRejectsDuplicateResolvedMeshIdentity(t *testing.T) {
	tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps"}}
	left := readyMeshRegistration("orders", "shared-api", "https://orders.internal")
	right := readyMeshRegistration("checkout", "shared-api", "https://checkout.internal")
	store := meshServiceClient(t, []client.Object{tenant, left, right}...)
	reconciler := &HankoTenantReconciler{Client: store}
	if _, err := reconciler.collectMeshRegistrations(context.Background(), tenant, "ten_acme", "cluster-a"); err == nil {
		t.Fatal("duplicate mesh workload identity was accepted")
	}
}

func TestTenantErrorHeartbeatRevokesMeshRegistrations(t *testing.T) {
	var reported hub.OperatorStatus
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/operators/status" || request.Header.Get("Authorization") != "Bearer operator-token" {
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&reported); err != nil {
			http.Error(response, "invalid body", http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps", Generation: 2},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubTenantID: "ten_acme", HubTransport: "continuum",
		},
		Status: hankoshv1alpha1.HankoTenantStatus{Phase: "Synced", BundleVersion: "v1"},
	}
	reconciler := &HankoTenantReconciler{Client: meshServiceClient(t, tenant)}
	result, reconcileErr := reconciler.setError(
		context.Background(), hub.New(server.URL, "ten_acme", "operator-token"), tenant,
		client.MergeFrom(tenant.DeepCopy()), "MeshRegistrationInvalid", errors.New("invalid registration"),
	)
	assertBoundedErrorRequeue(t, result, reconcileErr)
	if reported.MeshRegistrations == nil || len(*reported.MeshRegistrations) != 0 {
		t.Fatalf("error heartbeat did not revoke mesh registrations: %#v", reported.MeshRegistrations)
	}
}

// The Hub only serves the mesh policy to an operator whose last heartbeat was
// Synced and healthy, and mesh policy failures happen after that heartbeat.
// If they seeded the sticky degraded state or reported an Error phase, a
// recovering operator could never obtain the policy again: every cycle would
// re-report Error, the Hub would answer 503, and the failure would re-seed
// itself. Audit-only mesh policy reasons must therefore stay local.
func TestMeshPolicyFailureDoesNotPoisonHeartbeat(t *testing.T) {
	statusReports := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/operators/status" {
			statusReports++
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps", Generation: 2},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubTenantID: "ten_acme", HubTransport: "continuum",
		},
		Status: hankoshv1alpha1.HankoTenantStatus{Phase: "Synced", BundleVersion: "v1"},
	}
	reconciler := &HankoTenantReconciler{Client: meshServiceClient(t, tenant)}
	for _, reason := range []string{
		"MeshPolicyStatusReportFailed", "MeshPolicyFetchFailed", "MeshPolicyProjectionFailed",
	} {
		result, reconcileErr := reconciler.setError(
			context.Background(), hub.New(server.URL, "ten_acme", "operator-token"), tenant,
			client.MergeFrom(tenant.DeepCopy()), reason, errors.New("policy unavailable"),
		)
		assertBoundedErrorRequeue(t, result, reconcileErr)
		if detail, blocked := reconciler.degradedReason(tenant); blocked {
			t.Fatalf("%s seeded the sticky degraded state %q: the next heartbeat would deadlock the mesh policy fetch", reason, detail)
		}
	}
	if statusReports != 0 {
		t.Fatalf("mesh policy failures sent %d degraded reports to the hub, want 0", statusReports)
	}
	if tenant.Status.Phase != "Error" {
		t.Fatalf("local phase = %q, want Error so the condition stays visible on the cluster", tenant.Status.Phase)
	}
}
