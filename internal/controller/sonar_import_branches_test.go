package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestImportDryRunDiscoversSelectedRealmWithoutMutation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms":
			_ = json.NewEncoder(w).Encode([]keycloak.Realm{
				{ID: "master", RealmName: "master"}, {ID: "acme-uuid", RealmName: "acme", DisplayName: "Acme", Enabled: true},
			})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]keycloak.App{
				{ClientID: "realm-management"},
				{ClientID: "portal", Name: "Portal", PublicClient: true},
				{ClientID: "automation", Name: "Automation", ServiceAccountsEnabled: true},
			})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	includeProviders := false
	operation := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "preview", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoImportSpec{
			SourceRef: "source", DryRun: true, Realms: []string{"acme"}, IncludeIdentityProviders: &includeProviders,
		},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, operation)
	reconciler := &HankoImportReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(keycloak.New(server.URL, "operator", "secret"))}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil {
		t.Fatalf("dry-run import: %v", err)
	}
	var actual hankoshv1alpha1.HankoImport
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(operation), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Done" || actual.Status.Discovered.Realms != 1 || actual.Status.Discovered.Applications != 1 || actual.Status.Discovered.ServiceAccounts != 1 {
		t.Fatalf("unexpected dry-run discovery: %#v", actual.Status)
	}
	var realms hankoshv1alpha1.HankoRealmList
	if err := k8sClient.List(context.Background(), &realms); err != nil || len(realms.Items) != 0 {
		t.Fatalf("dry run created realms: realms=%#v err=%v", realms.Items, err)
	}
}

func TestImportFailureAndTerminalPathsAreCheckpointed(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	t.Run("missing source", func(t *testing.T) {
		operation := &hankoshv1alpha1.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "test"}, Spec: hankoshv1alpha1.HankoImportSpec{SourceRef: "absent"}}
		k8sClient := controllerTestClient(scheme, operation)
		reconciler := &HankoImportReconciler{Client: k8sClient, Scheme: scheme}
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil {
			t.Fatalf("missing source is a status failure, not a reconcile error: %v", err)
		}
		var actual hankoshv1alpha1.HankoImport
		_ = k8sClient.Get(ctx, client.ObjectKeyFromObject(operation), &actual)
		if actual.Status.Phase != "Failed" || conditionReason(actual.Status.Conditions, "ImportReady") != "SourceNotFound" {
			t.Fatalf("missing source status: %#v", actual.Status)
		}
	})

	t.Run("list realms failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/realms/master/protocol/openid-connect/token" {
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
				return
			}
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
		}))
		t.Cleanup(server.Close)
		operation := &hankoshv1alpha1.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "failure", Namespace: "test"}}
		k8sClient := controllerTestClient(scheme, operation)
		reconciler := &HankoImportReconciler{Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(keycloak.New(server.URL, "operator", "secret"))}
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil {
			t.Fatalf("provider discovery failure must be recorded in status: %v", err)
		}
		var actual hankoshv1alpha1.HankoImport
		_ = k8sClient.Get(ctx, client.ObjectKeyFromObject(operation), &actual)
		if actual.Status.Phase != "Failed" || conditionReason(actual.Status.Conditions, "ImportReady") != "ListRealmsError" {
			t.Fatalf("list realms failure status: %#v", actual.Status)
		}
	})

	for _, phase := range []string{"Done", "Failed"} {
		t.Run("terminal "+phase, func(t *testing.T) {
			operation := &hankoshv1alpha1.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(phase), Namespace: "test"}, Status: hankoshv1alpha1.HankoImportStatus{Phase: phase}}
			reconciler := &HankoImportReconciler{Client: controllerTestClient(scheme, operation), Scheme: scheme}
			if result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil || !result.IsZero() {
				t.Fatalf("terminal import result=%v err=%v", result, err)
			}
		})
	}
}

func TestImportDiscoveryErrorsKeepActionableContext(t *testing.T) {
	cause := errors.New("denied")
	providerError := &identityProviderDiscoveryError{realm: "acme", provider: "entra", cause: cause}
	if reason := importIdentityProviderErrorReason(providerError); reason != "ListIdentityProviderMappersError" {
		t.Fatalf("provider mapper reason = %q", reason)
	}
	if message := importIdentityProviderErrorMessage(providerError); !strings.Contains(message, "entra") || !strings.Contains(message, "acme") {
		t.Fatalf("provider mapper message = %q", message)
	}
	listError := &identityProviderDiscoveryError{realm: "acme", cause: cause}
	if reason := importIdentityProviderErrorReason(listError); reason != "ListIdentityProvidersError" {
		t.Fatalf("provider list reason = %q", reason)
	}
	if message := importIdentityProviderErrorMessage(listError); !strings.Contains(message, "acme") {
		t.Fatalf("provider list message = %q", message)
	}
	if message := importIdentityProviderErrorMessage(cause); message != cause.Error() {
		t.Fatalf("generic discovery message = %q", message)
	}
	if got := (&importDiscoveryError{cause: cause}).Error(); got != cause.Error() {
		t.Fatalf("discovery error = %q", got)
	}
}

func TestImportServiceAccountApplyIsObserveOnlyAndIdempotent(t *testing.T) {
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme)
	reconciler := &HankoImportReconciler{Client: k8sClient, Scheme: scheme}
	operation := &hankoshv1alpha1.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "test"}}
	application := keycloak.App{ClientID: "automation", Name: "Automation", ServiceAccountsEnabled: true}

	if err := reconciler.applyServiceAccount(context.Background(), operation, "acme", application); err != nil {
		t.Fatalf("create observed service account: %v", err)
	}
	if operation.Status.Applied.ServiceAccounts != 1 {
		t.Fatalf("applied counters = %#v", operation.Status.Applied)
	}
	var actual hankoshv1alpha1.HankoServiceAccount
	key := client.ObjectKey{Namespace: "test", Name: importResourceName("acme", "automation")}
	if err := k8sClient.Get(context.Background(), key, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Spec.RealmRef != "acme" || actual.Spec.ClientID != "automation" || actual.Labels[importedByLabel] != operation.Name {
		t.Fatalf("unsafe imported service account: %#v", actual)
	}

	if err := reconciler.applyServiceAccount(context.Background(), operation, "acme", application); err != nil {
		t.Fatalf("repeat observed service-account import: %v", err)
	}
	if operation.Status.Applied.ServiceAccounts != 1 || operation.Status.Skipped.ServiceAccounts != 1 {
		t.Fatalf("idempotent counters applied=%#v skipped=%#v", operation.Status.Applied, operation.Status.Skipped)
	}
}

func TestImportServiceAccountSkipsProtectedAndApplicationOwnedClients(t *testing.T) {
	scheme := controllerTestScheme(t)
	tests := []struct {
		name        string
		realm       string
		clientID    string
		application *hankoshv1alpha1.HankoApplication
	}{
		{name: "protected client", realm: "alien6", clientID: "hanko-dashboard"},
		{
			name:     "application-owned client",
			realm:    "acme",
			clientID: "shared-client",
			application: &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-application", Namespace: "test"},
				Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "shared-client", Type: "web"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := make([]client.Object, 0, 1)
			if test.application != nil {
				objects = append(objects, test.application)
			}
			k8sClient := controllerTestClient(scheme, objects...)
			reconciler := &HankoImportReconciler{
				Client: k8sClient, Scheme: scheme, ProtectedClientIDs: []string{"hanko-dashboard"}, ProtectedRealm: "alien6",
			}
			operation := &hankoshv1alpha1.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "test"}}

			if err := reconciler.applyServiceAccount(context.Background(), operation, test.realm, keycloak.App{ClientID: test.clientID, ServiceAccountsEnabled: true}); err != nil {
				t.Fatalf("applyServiceAccount: %v", err)
			}
			if operation.Status.Applied.ServiceAccounts != 0 || operation.Status.Skipped.ServiceAccounts != 1 {
				t.Fatalf("counters applied=%#v skipped=%#v", operation.Status.Applied, operation.Status.Skipped)
			}
			var accounts hankoshv1alpha1.HankoServiceAccountList
			if err := k8sClient.List(context.Background(), &accounts, client.InNamespace("test")); err != nil {
				t.Fatal(err)
			}
			if len(accounts.Items) != 0 {
				t.Fatalf("created conflicting service accounts: %#v", accounts.Items)
			}
		})
	}
}

func conditionReason(conditions []metav1.Condition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Reason
		}
	}
	return ""
}
