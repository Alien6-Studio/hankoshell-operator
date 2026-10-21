package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// enrollTestHub fakes the three Hub endpoints an enrolling operator touches:
// token exchange, bundle fetch and status report.
func enrollTestHub(t *testing.T, enrollToken, permanentToken, tenantID, clusterID string) *httptest.Server {
	t.Helper()
	signed := signedTenantBundle(t, permanentToken, hub.Bundle{Version: "v1", TenantID: tenantID})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/enroll":
			var body struct {
				EnrollToken string `json:"enrollToken"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.EnrollToken != enrollToken {
				http.Error(w, "invalid, expired or already used enrollment token", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clusterID": clusterID, "tenantID": tenantID, "token": permanentToken,
				"expiresAt": time.Now().UTC().Add(12 * time.Hour),
			})
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/bundles/latest":
			if request.Header.Get("Authorization") != "Bearer "+permanentToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(signed)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/status":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestTenantSelfEnrollment(t *testing.T) {
	const (
		enrollToken    = "enr_test"
		permanentToken = "permanent-token"
		tenantID       = "ten_42"
		clusterID      = "cluster-42"
	)
	server := enrollTestHub(t, enrollToken, permanentToken, tenantID, clusterID)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef:  corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef: &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
	enrollSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"},
		Data:       map[string][]byte{"enroll_token": []byte(enrollToken)},
	}
	k8sClient := controllerTestClient(scheme, tenant, enrollSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace()), Scheme: scheme, Pool: keycloak.NewPool(nil)}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
		t.Fatalf("reconcile enrolling tenant: %v", err)
	}

	var credentials corev1.Secret
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "test", Name: "hub-token"}, &credentials); err != nil {
		t.Fatalf("hub credentials secret was not created: %v", err)
	}
	for key, want := range map[string]string{
		"hub_token": permanentToken, "tenant_id": tenantID, "cluster_id": clusterID,
	} {
		if got := string(credentials.Data[key]); got != want {
			t.Fatalf("credentials secret %s = %q, want %q", key, got, want)
		}
	}
	if expiresAt, err := time.Parse(time.RFC3339Nano, string(credentials.Data["expires_at"])); err != nil || time.Until(expiresAt) <= credentialRotationLeadTime {
		t.Fatalf("credentials secret expires_at is not a valid future rotation deadline: %q (%v)", credentials.Data["expires_at"], err)
	}

	var actual hankoshv1alpha1.HankoTenant
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Synced" || actual.Status.BundleVersion != "v1" {
		t.Fatalf("unexpected status after enrollment: %+v", actual.Status)
	}
}

func TestTenantEnrollmentUsesPublicEndpointAndSyncUsesPrivateEndpoint(t *testing.T) {
	const (
		enrollToken    = "enr_test"
		permanentToken = "permanent-token"
		tenantID       = "ten_42"
		clusterID      = "cluster-42"
	)

	publicCalls := 0
	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		publicCalls++
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/operators/enroll" {
			http.Error(w, "bootstrap endpoint only", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"clusterID": clusterID, "tenantID": tenantID, "token": permanentToken,
			"expiresAt": time.Now().UTC().Add(12 * time.Hour),
		})
	}))
	t.Cleanup(publicServer.Close)

	syncCalls := 0
	signed := signedTenantBundle(t, permanentToken, hub.Bundle{Version: "v1", TenantID: tenantID})
	privateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		syncCalls++
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/bundles/latest":
			_ = json.NewEncoder(w).Encode(signed)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/status":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "private synchronization endpoint only", http.StatusNotFound)
		}
	}))
	t.Cleanup(privateServer.Close)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint:           privateServer.URL,
			HubEnrollmentEndpoint: publicServer.URL,
			IsolationMode:         "realm",
			HubTokenSecretRef:     corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef:    &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
	enrollSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"},
		Data:       map[string][]byte{"enroll_token": []byte(enrollToken)},
	}
	k8sClient := controllerTestClient(scheme, tenant, enrollSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace()), Scheme: scheme, Pool: keycloak.NewPool(nil)}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
		t.Fatalf("reconcile enrolling tenant over split endpoints: %v", err)
	}
	if publicCalls != 1 {
		t.Fatalf("public endpoint calls = %d, want enrollment only", publicCalls)
	}
	if syncCalls != 2 {
		t.Fatalf("private endpoint calls = %d, want bundle and status", syncCalls)
	}
}

func TestTenantEnrollmentRejected(t *testing.T) {
	server := enrollTestHub(t, "enr_valid", "permanent-token", "ten_42", "cluster-42")

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef:  corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef: &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
	enrollSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"},
		Data:       map[string][]byte{"enroll_token": []byte("enr_burned")},
	}
	k8sClient := controllerTestClient(scheme, tenant, enrollSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace()), Scheme: scheme, Pool: keycloak.NewPool(nil)}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	assertBoundedErrorRequeue(t, result, err)

	var actual hankoshv1alpha1.HankoTenant
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Error" {
		t.Fatalf("phase = %q, want Error", actual.Status.Phase)
	}
	found := false
	for _, condition := range actual.Status.Conditions {
		if condition.Type == "Synced" && condition.Reason == "HubEnrollFailed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing HubEnrollFailed condition: %+v", actual.Status.Conditions)
	}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "test", Name: "hub-token"}, &corev1.Secret{}); err == nil {
		t.Fatal("no credentials secret must exist after a rejected enrollment")
	}
}

func TestTenantEnrollmentTenantMismatch(t *testing.T) {
	enrollCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		enrollCalls++
		if request.URL.Path != "/api/v1/operators/enroll" {
			t.Error("wrong-tenant enrollment must not proceed to synchronization")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(hub.EnrollResult{
			TenantID: "ten_42", ClusterID: "cluster-42", Token: "permanent-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		})
	}))
	t.Cleanup(server.Close)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubTenantID: "ten_other", HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef:  corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef: &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
	enrollSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"},
		Data:       map[string][]byte{"enroll_token": []byte("enr_test")},
	}
	k8sClient := controllerTestClient(scheme, tenant, enrollSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, ClusterIdentityReader: controllerTestClient(scheme, enrollmentNamespace()), Scheme: scheme, Pool: keycloak.NewPool(nil)}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	assertBoundedErrorRequeue(t, result, err)
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "test", Name: "hub-token"}, &corev1.Secret{}); err == nil {
		t.Fatal("no credentials secret must exist after a tenant mismatch")
	}
	actual := assertTenantIdentityError(t, k8sClient, tenant, "HubEnrollFailed")
	if actual.Status.ClusterID != "cluster-42" || actual.Status.TenantID != "ten_42" {
		t.Fatalf("successful exchange lost its identity on tenant mismatch: %+v", actual.Status)
	}
	secondResult, secondErr := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	assertBoundedErrorRequeue(t, secondResult, secondErr)
	assertTenantIdentityError(t, k8sClient, tenant, "HubIdentityRecoveryRequired")
	if enrollCalls != 1 {
		t.Fatalf("enrollment calls = %d, want initial exchange only", enrollCalls)
	}
}

func TestTenantCredentialRotationUsesTwoPhaseCommit(t *testing.T) {
	const (
		oldToken  = "old-bounded-token"
		newToken  = "new-bounded-token"
		tenantID  = "ten_rotate"
		clusterID = "cluster-rotate"
	)
	prepareCalls := 0
	confirmCalls := 0
	reported := false
	signed := signedTenantBundle(t, newToken, hub.Bundle{Version: "v-rotated", TenantID: tenantID})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/token/rotate":
			prepareCalls++
			if request.Header.Get("Authorization") != "Bearer "+oldToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var body struct {
				RotationID string `json:"rotationID"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.RotationID == "" {
				http.Error(w, "rotation ID required", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clusterID": clusterID, "tenantID": tenantID, "token": newToken,
				"expiresAt": time.Now().UTC().Add(24 * time.Hour),
			})
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/token/confirm":
			confirmCalls++
			if request.Header.Get("Authorization") != "Bearer "+newToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/bundles/latest":
			if request.Header.Get("Authorization") != "Bearer "+newToken || confirmCalls == 0 {
				http.Error(w, "rotation not confirmed", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(signed)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/status":
			reported = request.Header.Get("Authorization") == "Bearer "+newToken
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubTenantID: tenantID, HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"},
		},
	}
	credentialSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"},
		Data: map[string][]byte{
			"hub_token": []byte(oldToken), "tenant_id": []byte(tenantID), "cluster_id": []byte(clusterID),
			"expires_at": []byte(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)),
		},
	}
	k8sClient := controllerTestClient(scheme, tenant, credentialSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(nil)}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
		t.Fatalf("reconcile rotating tenant: %v", err)
	}
	if prepareCalls != 1 || confirmCalls != 1 || !reported {
		t.Fatalf("rotation sequence prepare=%d confirm=%d reported=%v", prepareCalls, confirmCalls, reported)
	}
	var stored corev1.Secret
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(credentialSecret), &stored); err != nil {
		t.Fatal(err)
	}
	if string(stored.Data["hub_token"]) != newToken || len(stored.Data["rotation_id"]) != 0 || len(stored.Data["rotation_pending"]) != 0 {
		t.Fatalf("unexpected committed credential state: %#v", stored.Data)
	}
}

func TestTenantCredentialRotationResumesConfirmationAfterCrash(t *testing.T) {
	const (
		token     = "pending-token"
		tenantID  = "ten_resume"
		clusterID = "cluster-resume"
	)
	confirmCalls := 0
	signed := signedTenantBundle(t, token, hub.Bundle{Version: "v-resumed", TenantID: tenantID})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/api/v1/operators/token/confirm":
			confirmCalls++
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/api/v1/bundles/latest":
			_ = json.NewEncoder(w).Encode(signed)
		case "/api/v1/operators/status":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubTenantID: tenantID, HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"},
		},
	}
	credentialSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"},
		Data: map[string][]byte{
			"hub_token": []byte(token), "tenant_id": []byte(tenantID), "cluster_id": []byte(clusterID),
			"expires_at":  []byte(time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)),
			"rotation_id": []byte("rot_resume"), "rotation_pending": []byte("true"),
		},
	}
	k8sClient := controllerTestClient(scheme, tenant, credentialSecret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(nil)}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
		t.Fatalf("resume confirmation: %v", err)
	}
	if confirmCalls != 1 {
		t.Fatalf("confirmation calls = %d, want 1", confirmCalls)
	}
	var stored corev1.Secret
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(credentialSecret), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Data["rotation_id"]) != 0 || len(stored.Data["rotation_pending"]) != 0 {
		t.Fatal("resumed confirmation must clear transaction markers")
	}
}

func TestMalformedCredentialSecretNeverConsumesEnrollment(t *testing.T) {
	enrollmentCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		enrollmentCalls++
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint: server.URL, HubEnrollmentEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef:  corev1.LocalObjectReference{Name: "hub-token"},
			HubEnrollSecretRef: &corev1.LocalObjectReference{Name: "hub-enroll"},
		},
	}
	malformed := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"}, Data: map[string][]byte{"tenant_id": []byte("ten_test")}}
	enroll := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-enroll", Namespace: "test"}, Data: map[string][]byte{"enroll_token": []byte("enr_do_not_burn")}}
	k8sClient := controllerTestClient(scheme, tenant, malformed, enroll)
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(nil)}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	assertBoundedErrorRequeue(t, result, err)
	if enrollmentCalls != 0 {
		t.Fatalf("malformed credential Secret consumed enrollment path %d times", enrollmentCalls)
	}
}
