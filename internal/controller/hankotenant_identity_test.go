package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func enrollmentNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("kubernetes-cluster-uid")}}
}

type namespaceIdentityReader struct {
	client.Reader
	get func(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error
}

func (r namespaceIdentityReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	return r.get(ctx, key, object, options...)
}

func TestEnrollmentIdentityUsesExactNamespaceReadAndNormalizesName(t *testing.T) {
	calls := 0
	reconciler := &HankoTenantReconciler{ClusterIdentityReader: namespaceIdentityReader{get: func(_ context.Context, key client.ObjectKey, object client.Object, _ ...client.GetOption) error {
		calls++
		if key.Name != "kube-system" || key.Namespace != "" {
			t.Fatalf("identity read targets %v, want kube-system Namespace only", key)
		}
		namespace, ok := object.(*corev1.Namespace)
		if !ok {
			t.Fatalf("identity read object = %T", object)
		}
		*namespace = *enrollmentNamespace()
		return nil
	}}}
	identity, err := reconciler.enrollmentIdentity(context.Background(), "  Équipe   Paris_1.prod-ouest  ")
	if err != nil || identity.ClusterName != "Équipe Paris_1.prod-ouest" || identity.ClusterUID != "kubernetes-cluster-uid" || calls != 1 {
		t.Fatalf("identity = %+v, calls = %d, error = %v", identity, calls, err)
	}
}

func TestEnrollmentIdentityNameValidationPrecedesNamespaceRead(t *testing.T) {
	for _, name := range []string{"  ", "cluster/a", "cluster@example", strings.Repeat("é", 81)} {
		t.Run(name, func(t *testing.T) {
			reconciler := &HankoTenantReconciler{ClusterIdentityReader: namespaceIdentityReader{get: func(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
				t.Fatal("invalid name must not read the cluster or spend the enrollment token")
				return nil
			}}}
			if _, err := reconciler.enrollmentIdentity(context.Background(), name); err == nil || !strings.Contains(err.Error(), "clusterName") {
				t.Fatalf("expected actionable clusterName validation error, got %v", err)
			}
		})
	}
	reader := controllerTestClient(controllerTestScheme(t), enrollmentNamespace())
	for _, name := range []string{"", strings.Repeat("é", 80)} {
		if _, err := (&HankoTenantReconciler{ClusterIdentityReader: reader}).enrollmentIdentity(context.Background(), name); err != nil {
			t.Fatalf("optional or 80-character Unicode name rejected: %v", err)
		}
	}
}

func identityEnrollmentTenant(endpoint string) *hankoshv1alpha1.HankoTenant {
	return &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint: endpoint, ClusterName: "  Production  Paris ", IsolationMode: "realm",
			HubTokenSecretRef:  corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef: &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
}

func identityEnrollmentSecret() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"}, Data: map[string][]byte{"enroll_token": []byte("enrollment-fixture")}}
}

func assertTenantIdentityError(t *testing.T, k8sClient client.Client, tenant *hankoshv1alpha1.HankoTenant, reason string) hankoshv1alpha1.HankoTenant {
	t.Helper()
	var actual hankoshv1alpha1.HankoTenant
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(tenant), &actual); err != nil {
		t.Fatal(err)
	}
	for _, condition := range actual.Status.Conditions {
		if actual.Status.Phase == "Error" && condition.Type == "Synced" && condition.Status == metav1.ConditionFalse && condition.Reason == reason {
			return actual
		}
	}
	t.Fatalf("expected error %s, got %+v", reason, actual.Status)
	return actual
}

func assertBoundedErrorRequeue(t *testing.T, result ctrl.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("error paths must requeue with a bounded delay instead of returning an error, got %v", err)
	}
	if result.RequeueAfter != requeueOnError {
		t.Fatalf("requeue = %+v, want RequeueAfter %s", result, requeueOnError)
	}
}

func syncedConditionMessage(tenant hankoshv1alpha1.HankoTenant) string {
	for _, condition := range tenant.Status.Conditions {
		if condition.Type == "Synced" {
			return condition.Message
		}
	}
	return ""
}

func TestEnrollmentWithoutClusterUIDNeverCallsHub(t *testing.T) {
	for _, scenario := range []string{"reader-missing", "namespace-missing", "forbidden", "empty-uid", "invalid-uid", "oversized-uid"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				http.Error(w, "unexpected enrollment", http.StatusInternalServerError)
			}))
			defer server.Close()
			scheme := controllerTestScheme(t)
			tenant := identityEnrollmentTenant(server.URL)
			k8sClient := controllerTestClient(scheme, tenant, identityEnrollmentSecret())
			reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme}
			switch scenario {
			case "namespace-missing":
				reconciler.ClusterIdentityReader = controllerTestClient(scheme)
			case "forbidden":
				reconciler.ClusterIdentityReader = namespaceIdentityReader{get: func(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "kube-system", errors.New("not permitted"))
				}}
			case "empty-uid", "invalid-uid", "oversized-uid":
				namespace := enrollmentNamespace()
				namespace.UID = types.UID(map[string]string{"empty-uid": "", "invalid-uid": "not a uid", "oversized-uid": strings.Repeat("a", 129)}[scenario])
				reconciler.ClusterIdentityReader = controllerTestClient(scheme, namespace)
			}
			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
			assertBoundedErrorRequeue(t, result, err)
			actual := assertTenantIdentityError(t, k8sClient, tenant, "HubEnrollFailed")
			if !strings.Contains(syncedConditionMessage(actual), "kube-system") {
				t.Fatalf("expected clear UID read detail, got %q", syncedConditionMessage(actual))
			}
			if calls != 0 {
				t.Fatalf("Hub calls = %d, want 0", calls)
			}
			if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: "hub-token"}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
				t.Fatalf("credential Secret must remain absent, got %v", err)
			}
		})
	}
}

func TestMissingCredentialSecretWithKnownIdentityRequiresRecovery(t *testing.T) {
	tenant := identityEnrollmentTenant("https://must-not-contact.invalid")
	tenant.Status = hankoshv1alpha1.HankoTenantStatus{ClusterID: "existing-cluster", TenantID: "existing-tenant"}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, tenant, identityEnrollmentSecret())
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, ClusterIdentityReader: namespaceIdentityReader{get: func(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
		t.Fatal("known identity must not start enrollment")
		return nil
	}}}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	assertBoundedErrorRequeue(t, result, err)
	actual := assertTenantIdentityError(t, k8sClient, tenant, "HubIdentityRecoveryRequired")
	if !strings.Contains(syncedConditionMessage(actual), "recover credentials") {
		t.Fatalf("expected identity recovery guidance, got %q", syncedConditionMessage(actual))
	}
	if actual.Status.ClusterID != "existing-cluster" || actual.Status.TenantID != "existing-tenant" {
		t.Fatalf("known identity changed: %+v", actual.Status)
	}
}

func TestEnrollmentIdentitySurvivesFailedInitialSyncAndSecretLoss(t *testing.T) {
	enrollCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/operators/enroll" {
			enrollCalls++
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode enrollment: %v", err)
			}
			if body["clusterName"] != "Production Paris" || body["clusterUID"] != "kubernetes-cluster-uid" {
				t.Errorf("missing or incorrect identity metadata: name = %q, UID = %q", body["clusterName"], body["clusterUID"])
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"tenantID": "tenant-1", "clusterID": "cluster-1", "token": "bounded-fixture", "expiresAt": time.Now().Add(24 * time.Hour)})
			return
		}
		http.Error(w, "synchronization unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx := context.Background()
	tenant := identityEnrollmentTenant(server.URL)
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, tenant, identityEnrollmentSecret())
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace())}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}
	firstResult, firstErr := reconciler.Reconcile(ctx, request)
	assertBoundedErrorRequeue(t, firstResult, firstErr)
	actual := assertTenantIdentityError(t, k8sClient, tenant, "BundleFetchFailed")
	if actual.Status.ClusterID != "cluster-1" || actual.Status.TenantID != "tenant-1" {
		t.Fatalf("enrollment identity was lost on failed initial sync: %+v", actual.Status)
	}
	if err := k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"}}); err != nil {
		t.Fatal(err)
	}
	secondResult, secondErr := reconciler.Reconcile(ctx, request)
	assertBoundedErrorRequeue(t, secondResult, secondErr)
	assertTenantIdentityError(t, k8sClient, tenant, "HubIdentityRecoveryRequired")
	if enrollCalls != 1 {
		t.Fatalf("enrollment calls = %d, want initial exchange only", enrollCalls)
	}
}

func TestReplacementCredentialsCannotChangeKnownIdentity(t *testing.T) {
	for _, mismatch := range []string{"cluster", "tenant", "missing-cluster"} {
		t.Run(mismatch, func(t *testing.T) {
			tenant := identityEnrollmentTenant("https://must-not-contact.invalid")
			tenant.Status = hankoshv1alpha1.HankoTenantStatus{ClusterID: "cluster-1", TenantID: "tenant-1"}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"}, Data: map[string][]byte{
				"hub_token": []byte("fixture"), "tenant_id": []byte("tenant-1"), "cluster_id": []byte("cluster-1"),
			}}
			switch mismatch {
			case "cluster":
				secret.Data["cluster_id"] = []byte("other-cluster")
			case "tenant":
				secret.Data["tenant_id"] = []byte("other-tenant")
			case "missing-cluster":
				delete(secret.Data, "cluster_id")
			}
			scheme := controllerTestScheme(t)
			k8sClient := controllerTestClient(scheme, tenant, secret)
			reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme}
			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
			assertBoundedErrorRequeue(t, result, err)
			actual := assertTenantIdentityError(t, k8sClient, tenant, "HubIdentityMismatch")
			if actual.Status.ClusterID != "cluster-1" || actual.Status.TenantID != "tenant-1" {
				t.Fatalf("known identity changed: %+v", actual.Status)
			}
		})
	}
}

type identitySecretWriteFailure struct{ client.Client }

func (c identitySecretWriteFailure) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	if secret, ok := object.(*corev1.Secret); ok && secret.Name == "hub-token" {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, secret.Name, errors.New("fixture write denied"))
	}
	return c.Client.Create(ctx, object, options...)
}

func TestEnrollmentSecretWriteFailureRemembersIdentity(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path != "/api/v1/operators/enroll" {
			t.Error("Secret write failure must not proceed with synchronization")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"tenantID": "tenant-1", "clusterID": "cluster-1", "token": "bounded-fixture", "expiresAt": time.Now().Add(24 * time.Hour)})
	}))
	defer server.Close()
	tenant := identityEnrollmentTenant(server.URL)
	scheme := controllerTestScheme(t)
	base := controllerTestClient(scheme, tenant, identityEnrollmentSecret())
	reconciler := &HankoTenantReconciler{Client: identitySecretWriteFailure{Client: base}, Scheme: scheme, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace())}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}
	firstResult, firstErr := reconciler.Reconcile(context.Background(), request)
	assertBoundedErrorRequeue(t, firstResult, firstErr)
	actual := assertTenantIdentityError(t, base, tenant, "HubEnrollFailed")
	if actual.Status.ClusterID != "cluster-1" || actual.Status.TenantID != "tenant-1" {
		t.Fatalf("successful exchange lost its identity on Secret write failure: %+v", actual.Status)
	}
	secondResult, secondErr := reconciler.Reconcile(context.Background(), request)
	assertBoundedErrorRequeue(t, secondResult, secondErr)
	assertTenantIdentityError(t, base, tenant, "HubIdentityRecoveryRequired")
	if calls != 1 {
		t.Fatalf("enrollment calls = %d, want one exchange", calls)
	}
}
