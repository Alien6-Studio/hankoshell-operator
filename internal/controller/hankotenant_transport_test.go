package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestHubTransportFailsClosedToDirect(t *testing.T) {
	for value, want := range map[string]string{
		"":          "direct",
		"direct":    "direct",
		"continuum": "continuum",
		"sidecar":   "direct",
	} {
		if got := hubTransport(value); got != want {
			t.Errorf("hubTransport(%q) = %q, want %q", value, got, want)
		}
	}
}

type enterpriseSecretReader struct {
	client.Client
	reads int
}

func (c *enterpriseSecretReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if _, secret := object.(*corev1.Secret); secret {
		c.reads++
	}
	return c.Client.Get(ctx, key, object, options...)
}

func TestEnterpriseTenantRejectsPublicOrDirectTransportBeforeReadingCredentials(t *testing.T) {
	const endpoint = "https://hub.mesh.example:9443"
	policy, err := hub.NewContinuumPolicy(endpoint, "10.250.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, endpoint, transport string }{
		{"public", "https://public.example", "continuum"},
		{"direct", endpoint, "direct"},
		{"legacy", endpoint, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			tenant := &hankoshv1alpha1.HankoTenant{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"},
				Spec: hankoshv1alpha1.HankoTenantSpec{HubEndpoint: test.endpoint, HubTransport: test.transport,
					HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"}},
			}
			store := &enterpriseSecretReader{Client: fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).
				WithStatusSubresource(&hankoshv1alpha1.HankoTenant{}).WithObjects(tenant).Build()}
			reconciler := HankoTenantReconciler{Client: store, HubTransportPolicy: policy}
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "acme", Namespace: "auth"}}); err != nil {
				t.Fatal(err)
			}
			if store.reads != 0 {
				t.Fatal("unapproved CRD read Hub credentials")
			}
			var observed hankoshv1alpha1.HankoTenant
			if err := store.Get(context.Background(), client.ObjectKeyFromObject(tenant), &observed); err != nil {
				t.Fatal(err)
			}
			if observed.Status.Phase != "Error" || observed.Status.Conditions[0].Reason != "EnterpriseTransportRequired" {
				t.Fatalf("transport violation was not visible: %#v", observed.Status)
			}
		})
	}
}

func TestEnterpriseTenantRejectsIncompleteOrExpiredIdentity(t *testing.T) {
	const endpoint = "https://hub.mesh.example:9443"
	policy, err := hub.NewContinuumPolicy(endpoint, "10.250.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"tenant_id", "cluster_id", "expires_at", "expired"} {
		t.Run(missing, func(t *testing.T) {
			tenant := &hankoshv1alpha1.HankoTenant{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"},
				Spec: hankoshv1alpha1.HankoTenantSpec{HubEndpoint: endpoint, HubTransport: "continuum",
					HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"}},
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: "auth"},
				Data: map[string][]byte{"hub_token": []byte("fixture"), "tenant_id": []byte("tenant-acme"),
					"cluster_id": []byte("cluster-acme"), "expires_at": []byte(time.Now().Add(24 * time.Hour).Format(time.RFC3339Nano))}}
			if missing == "expired" {
				secret.Data["expires_at"] = []byte(time.Now().Add(-time.Minute).Format(time.RFC3339Nano))
			} else {
				delete(secret.Data, missing)
			}
			store := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).
				WithStatusSubresource(&hankoshv1alpha1.HankoTenant{}).WithObjects(tenant, secret).Build()
			reconciler := HankoTenantReconciler{Client: store, HubTransportPolicy: policy}
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
				t.Fatal(err)
			}
			var observed hankoshv1alpha1.HankoTenant
			if err := store.Get(context.Background(), client.ObjectKeyFromObject(tenant), &observed); err != nil {
				t.Fatal(err)
			}
			if observed.Status.Phase != "Error" {
				t.Fatalf("unidentified or expired credential accepted: %#v", observed.Status)
			}
		})
	}
}

func TestEnterpriseInstanceClientRejectsHTTPAdminSecret(t *testing.T) {
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "iam", Namespace: "auth"},
		Spec:       hankoshv1alpha1.HankoKeycloakInstanceSpec{AdminRef: corev1.LocalObjectReference{Name: "iam-admin"}},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "iam-admin", Namespace: "auth"},
		Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte("http://iam.auth.svc"),
			"HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("fixture")}}
	store := controllerTestClient(controllerTestScheme(t), secret)
	if _, err := buildKCClientForInstance(context.Background(), store, instance, true); err == nil {
		t.Fatal("enterprise instance accepted an HTTP credential endpoint")
	}
	if _, err := buildKCClientForInstance(context.Background(), store, instance, false); err == nil {
		t.Fatal("standard instance implicitly accepted HTTP")
	}
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	if _, err := buildKCClientForInstance(context.Background(), store, instance, false); err != nil {
		t.Fatalf("explicit standard HTTP opt-in rejected: %v", err)
	}
	if _, err := buildKCClientForInstance(context.Background(), store, instance, true); err == nil {
		t.Fatal("compatibility flag weakened enterprise instance transport")
	}
}

func TestDedicatedTenantKeycloakTransportPolicy(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, profile, flag string
		valid                         bool
	}{
		{"HTTPS default", "https://iam.example.com", "standard", "", true},
		{"HTTP default", "http://iam.auth.svc", "standard", "", false},
		{"HTTP acknowledged", "http://iam.auth.svc", "standard", "true", true},
		{"enterprise HTTP acknowledged", "http://iam.auth.svc", "enterprise", "true", false},
		{"enterprise HTTPS", "https://iam.example.com", "enterprise", "true", true},
		{"URL credentials", "https://hidden-user:hidden-password@iam.example.com", "standard", "true", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HANKO_SECURITY_PROFILE", test.profile)
			t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", test.flag)
			tenant := &hankoshv1alpha1.HankoTenant{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"},
				Spec:       hankoshv1alpha1.HankoTenantSpec{IsolationMode: "keycloak", KeycloakSecretRef: &corev1.LocalObjectReference{Name: "iam-admin"}},
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "iam-admin", Namespace: "auth"},
				Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(test.endpoint), "HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("fixture")}}
			pool := keycloak.NewPool(nil)
			reconciler := HankoTenantReconciler{Client: controllerTestClient(controllerTestScheme(t), secret), Pool: pool}
			_, err := reconciler.registerTenantKeycloak(context.Background(), tenant)
			if (err == nil) != test.valid || (pool.Get("auth/acme") != nil) != test.valid {
				t.Fatalf("dedicated endpoint acceptance or registration violated policy: %v", err)
			}
		})
	}
}

func TestInstanceEmptyPrivateCADoesNotFallBackToSystemTrust(t *testing.T) {
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "iam", Namespace: "auth"},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			AdminRef: corev1.LocalObjectReference{Name: "iam-admin"}, TLSCARef: "iam-ca",
		},
	}
	admin := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "iam-admin", Namespace: "auth"},
		Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte("https://iam.example.com"),
			"HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("fixture")}}
	for _, data := range []map[string][]byte{nil, {"ca.crt": nil}, {"ca.crt": {}}, {"ca.crt": []byte("invalid PEM")}} {
		ca := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "iam-ca", Namespace: "auth"}, Data: data}
		store := controllerTestClient(controllerTestScheme(t), admin, ca)
		if _, err := buildKCClientForInstance(context.Background(), store, instance, false); err == nil {
			t.Fatal("invalid configured private CA silently used system trust")
		}
	}
}
