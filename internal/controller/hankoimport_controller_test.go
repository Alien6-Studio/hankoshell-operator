package controller_test

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func newImportReconciler(c client.Client, kc *keycloak.Client) *controller.HankoImportReconciler {
	return &controller.HankoImportReconciler{
		Client: c,
		Pool:   keycloak.NewPool(kc),
	}
}

func getImport(t *testing.T, c client.Client, name string) *hankoshv1alpha1.HankoImport {
	t.Helper()
	var hi hankoshv1alpha1.HankoImport
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &hi); err != nil {
		t.Fatalf("get HankoImport %q: %v", name, err)
	}
	return &hi
}

// (a) A client already governed by an explicit HankoApplication (any Kubernetes name)
// must be skipped on import — no duplicate object is created.
func TestHankoImport_SkipsAlreadyDeclaredClient(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.realms = []keycloak.Realm{{ID: "myrealm-id", RealmName: "myrealm", Enabled: true}}
	kc.appsByRealm["myrealm"] = []keycloak.App{
		{ClientID: "myclient", PublicClient: false},
	}

	existing := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "hand-authored-app", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
			Mode:     controller.ExportModeManage,
		},
	}
	hi := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "import-1", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoImportSpec{SourceRef: "kc-instance"},
	}

	c := newFakeClient(t, existing, hi)
	r := newImportReconciler(c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "import-1", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var apps hankoshv1alpha1.HankoApplicationList
	if err := c.List(context.Background(), &apps, client.InNamespace("default")); err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if len(apps.Items) != 1 {
		t.Fatalf("expected exactly 1 HankoApplication (no duplicate created), got %d", len(apps.Items))
	}

	gotImport := getImport(t, c, "import-1")
	if gotImport.Status.Skipped.Applications != 1 {
		t.Errorf("Skipped.Applications: got %d, want 1", gotImport.Status.Skipped.Applications)
	}
	if gotImport.Status.Applied.Applications != 0 {
		t.Errorf("Applied.Applications: got %d, want 0", gotImport.Status.Applied.Applications)
	}
}

// (b) Importing a genuinely new client creates a HankoApplication in Observe mode.
func TestHankoImport_NewClient_CreatedInObserveMode(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.realms = []keycloak.Realm{{ID: "myrealm-id", RealmName: "myrealm", Enabled: true}}
	kc.appsByRealm["myrealm"] = []keycloak.App{
		{ClientID: "brandnew", PublicClient: true},
	}

	hi := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "import-1", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoImportSpec{SourceRef: "kc-instance"},
	}

	c := newFakeClient(t, hi)
	r := newImportReconciler(c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "import-1", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var apps hankoshv1alpha1.HankoApplicationList
	if err := c.List(context.Background(), &apps, client.InNamespace("default")); err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if len(apps.Items) != 1 {
		t.Fatalf("expected 1 created HankoApplication, got %d", len(apps.Items))
	}
	created := apps.Items[0]
	if created.Spec.Mode != controller.ExportModeObserve {
		t.Errorf("Mode: got %q, want Observe", created.Spec.Mode)
	}
	if created.Labels[controller.ImportedByLabel] != "import-1" {
		t.Errorf("imported-by label: got %q, want %q", created.Labels[controller.ImportedByLabel], "import-1")
	}

	gotImport := getImport(t, c, "import-1")
	if gotImport.Status.Applied.Applications != 1 {
		t.Errorf("Applied.Applications: got %d, want 1", gotImport.Status.Applied.Applications)
	}
}

func TestHankoImport_CapturesIdentityProvidersAndSanitizesSecrets(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.realms = []keycloak.Realm{{ID: "alien6-id", RealmName: "alien6", DisplayName: "Alien6", Enabled: true}}
	kc.addIdentityProvider("alien6", keycloak.IdentityProvider{
		Alias: "entra", DisplayName: "Microsoft Entra ID", ProviderID: "oidc", Enabled: true, TrustEmail: true,
		Config: map[string]string{
			"clientId": "public-client-id", "clientSecret": "must-not-leak",
			"issuer": "https://login.microsoftonline.com/tenant/v2.0", "privateKeySignatureAlgorithm": "RS256",
		},
	})
	for index, name := range []string{"email", "username", "platform-admin-role"} {
		kc.addIdentityMapper("alien6", "entra", keycloak.IdentityProviderMapper{
			ID: fmt.Sprintf("mapper-%d", index), Name: name, IdentityProviderAlias: "entra",
			IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
			Config:                 map[string]string{"claim": name, "credentialSecret": "must-not-leak"},
		})
	}
	hi := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "import-idps", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoImportSpec{SourceRef: "kc-instance"},
	}
	c := newFakeClient(t, hi)
	r := newImportReconciler(c, kc.client())

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: hi.Name, Namespace: hi.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var realm hankoshv1alpha1.HankoRealm
	if err := c.Get(context.Background(), types.NamespacedName{Name: "alien6", Namespace: "default"}, &realm); err != nil {
		t.Fatalf("get imported realm: %v", err)
	}
	if realm.Labels[controller.ImportedByLabel] != hi.Name || len(realm.Spec.IdentityProviders) != 1 {
		t.Fatalf("imported realm identity providers = %+v", realm.Spec.IdentityProviders)
	}
	provider := realm.Spec.IdentityProviders[0]
	if provider.Config["clientId"] != "public-client-id" || provider.Config["privateKeySignatureAlgorithm"] != "RS256" ||
		provider.Config["clientSecret"] != "" || provider.ClientSecretRef != nil {
		t.Fatalf("sanitized provider config = %+v secretRef=%+v", provider.Config, provider.ClientSecretRef)
	}
	if len(provider.Mappers) != 3 {
		t.Fatalf("imported mappers = %+v", provider.Mappers)
	}
	for _, mapper := range provider.Mappers {
		if mapper.Config["credentialSecret"] != "" {
			t.Fatalf("mapper %q leaked secret config", mapper.Name)
		}
	}
	gotImport := getImport(t, c, hi.Name)
	if gotImport.Status.Discovered.IdentityProviders != 1 || gotImport.Status.Discovered.IdentityProviderMappers != 3 ||
		gotImport.Status.Applied.IdentityProviders != 1 || gotImport.Status.Applied.IdentityProviderMappers != 3 {
		t.Fatalf("identity-provider counts discovered=%+v applied=%+v", gotImport.Status.Discovered, gotImport.Status.Applied)
	}
}
