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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

func TestTenantBundleApplyPreservesExplicitValuesAndTenantBoundary(t *testing.T) {
	for _, typeMeta := range []string{`"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm",`, ""} {
		t.Run(typeMeta, func(t *testing.T) {
			var applied unstructured.Unstructured
			var applyOptions client.ApplyOptions
			k8sClient := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
				Apply: func(_ context.Context, _ client.WithWatch, configuration runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					payload, err := json.Marshal(configuration)
					if err != nil {
						return err
					}
					applyOptions.ApplyOptions(opts)
					return json.Unmarshal(payload, &applied)
				},
			}).Build()
			reconciler := &HankoTenantReconciler{Client: k8sClient}
			tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}
			raw := json.RawMessage(`{` + typeMeta + `"metadata":{"name":"realm","namespace":"other","labels":{"hanko.sh/tenant":"other","team":"auth"}},"spec":{"otpRequired":false,"securityProfile":{"passwordExpiryDays":0}}}`)
			counts, err := reconciler.applyBundle(context.Background(), tenant, &hub.Bundle{Realms: []json.RawMessage{raw}})
			if err != nil || counts["realms"] != 1 {
				t.Fatalf("apply bundle: counts=%v err=%v", counts, err)
			}
			if applied.GetAPIVersion() != "hanko.sh/v1alpha1" || applied.GetKind() != "HankoRealm" || applied.GetNamespace() != "test" || applied.GetLabels()["hanko.sh/tenant"] != "tenant" || applied.GetLabels()["team"] != "auth" {
				t.Fatalf("unexpected apply identity: %#v", applied.Object)
			}
			if value, found, err := unstructured.NestedBool(applied.Object, "spec", "otpRequired"); err != nil || !found || value {
				t.Fatalf("explicit false lost: value=%v found=%v err=%v", value, found, err)
			}
			if value, found, err := unstructured.NestedInt64(applied.Object, "spec", "securityProfile", "passwordExpiryDays"); err != nil || !found || value != 0 {
				t.Fatalf("explicit zero lost: value=%v found=%v err=%v", value, found, err)
			}
			if applyOptions.FieldManager != hankoOperatorFieldManager || applyOptions.Force == nil || !*applyOptions.Force {
				t.Fatalf("unexpected apply ownership: %#v", applyOptions)
			}
		})
	}
}

func TestTenantBundleRejectsUnexpectedResourceBeforeApply(t *testing.T) {
	for name, raw := range map[string]string{
		"wrong kind":    `{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoApplication","metadata":{"name":"realm"}}`,
		"wrong group":   `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"realm"}}`,
		"wrong version": `{"apiVersion":"hanko.sh/v1beta1","kind":"HankoRealm","metadata":{"name":"realm"}}`,
		"invalid spec":  `{"metadata":{"name":"realm"},"spec":{"otpRequired":"false"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			applied := false
			k8sClient := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
				Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
					applied = true
					return nil
				},
			}).Build()
			reconciler := &HankoTenantReconciler{Client: k8sClient}
			tenant := &hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}
			counts, err := reconciler.applyBundle(context.Background(), tenant, &hub.Bundle{Realms: []json.RawMessage{json.RawMessage(raw)}})
			if err == nil || counts["realms"] != 0 || applied {
				t.Fatalf("unexpected resource reached apply: counts=%v applied=%v err=%v", counts, applied, err)
			}
		})
	}
}
