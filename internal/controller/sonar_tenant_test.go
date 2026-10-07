package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

func signedTenantBundle(t *testing.T, token string, bundle hub.Bundle) hub.SignedBundle {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	return hub.SignedBundle{Bundle: bundle, Signature: hex.EncodeToString(mac.Sum(nil))}
}

func TestTenantReconcileSignedBundle(t *testing.T) {
	const token = "tenant-token"
	bundle := hub.Bundle{Version: "v42", TenantID: "tenant-id"}
	signed := signedTenantBundle(t, token, bundle)
	reported := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("X-Tenant-ID") != bundle.TenantID {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/bundles/latest":
			_ = json.NewEncoder(w).Encode(signed)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operators/status":
			reported = true
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
			HubTenantID: bundle.TenantID, HubEndpoint: server.URL, IsolationMode: "realm",
			HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "test"},
		Data: map[string][]byte{
			"hub_token":  []byte(token),
			"expires_at": []byte(time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339Nano)),
		},
	}
	k8sClient := controllerTestClient(scheme, tenant, secret)
	reconciler := &HankoTenantReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(nil)}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
	if err != nil {
		t.Fatalf("reconcile tenant: %v", err)
	}
	if result.RequeueAfter != requeueInterval || !reported {
		t.Fatalf("unexpected reconcile result=%v reported=%v", result, reported)
	}
	var actual hankoshv1alpha1.HankoTenant
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Synced" || actual.Status.BundleVersion != bundle.Version {
		t.Fatalf("unexpected tenant status: %#v", actual.Status)
	}
}

func TestTenantRegistersDedicatedKeycloakAndRejectsMissingReference(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: "test"},
		Data: map[string][]byte{
			"HANKO_KEYCLOAK_URL": []byte("https://keycloak.example.com"),
			"HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("secret"),
		},
	}
	pool := keycloak.NewPool(nil)
	reconciler := &HankoTenantReconciler{Client: controllerTestClient(scheme, secret), Scheme: scheme, Pool: pool}
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoTenantSpec{IsolationMode: "keycloak"},
	}
	if reason, err := reconciler.registerTenantKeycloak(ctx, tenant); err == nil || reason != "KeycloakSecretRefMissing" {
		t.Fatalf("missing reference: reason=%q err=%v", reason, err)
	}
	tenant.Spec.KeycloakSecretRef = &corev1.LocalObjectReference{Name: secret.Name}
	if reason, err := reconciler.registerTenantKeycloak(ctx, tenant); err != nil || reason != "" {
		t.Fatalf("register dedicated client: reason=%q err=%v", reason, err)
	}
	if pool.Get("test/tenant") == nil {
		t.Fatal("dedicated Keycloak client was not registered")
	}
}

func TestTenantInvalidBundleObjectFailsBeforeApply(t *testing.T) {
	reconciler := &HankoTenantReconciler{Client: controllerTestClient(controllerTestScheme(t))}
	tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}
	counts, err := reconciler.applyBundle(context.Background(), tenant, &hub.Bundle{Realms: []json.RawMessage{json.RawMessage(`{"metadata":`)}})
	if err == nil || counts["realms"] != 0 {
		t.Fatalf("invalid bundle should fail before apply: counts=%v err=%v", counts, err)
	}
}
