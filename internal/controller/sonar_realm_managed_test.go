package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

var managedRealmRoleNames = []string{
	"create-client", "impersonation", "manage-authorization", "manage-clients",
	"manage-events", "manage-identity-providers", "manage-realm", "manage-users",
	"query-clients", "query-groups", "query-realms", "query-users",
	"view-authorization", "view-clients", "view-events", "view-identity-providers",
	"view-realm", "view-users",
}

type managedRealmAPIFixture struct {
	t                  *testing.T
	realmPayload       map[string]any
	eventsPayload      map[string]any
	adminPayload       map[string]any
	identityPayload    map[string]any
	requiredAction     map[string]any
	managementMappings []keycloak.RealmRole
}

func newManagedRealmAPIFixture(t *testing.T) (*managedRealmAPIFixture, *keycloak.Client) {
	t.Helper()
	fixture := &managedRealmAPIFixture{t: t}
	for _, name := range managedRealmRoleNames {
		fixture.managementMappings = append(fixture.managementMappings, keycloak.RealmRole{ID: "role-" + name, Name: name})
	}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	return fixture, keycloak.New(server.URL, "operator", "secret")
}

func (fixture *managedRealmAPIFixture) serveHTTP(w http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme":
		_ = json.NewEncoder(w).Encode(keycloak.Realm{
			ID: "realm-uuid", RealmName: "acme", Enabled: true,
			Attributes: map[string]string{"unmanaged": "preserved"},
		})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme":
		fixture.decode(request, &fixture.realmPayload)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients":
		switch request.URL.Query().Get("clientId") {
		case "acme-realm":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "proxy-uuid", "clientId": "acme-realm"}})
		case "operator":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "operator-uuid", "clientId": "operator"}})
		default:
			fixture.unexpected(w, request)
		}
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/proxy-uuid":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "proxy-uuid", "clientId": "acme-realm", "enabled": true,
			"bearerOnly": true, "publicClient": false, "serviceAccountsEnabled": false,
			"fullScopeAllowed": false, "protocol": "openid-connect",
			"attributes": map[string]string{"realm_client": "true"},
		})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/proxy-uuid/roles":
		_ = json.NewEncoder(w).Encode(fixture.managementMappings)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/operator-uuid/service-account-user":
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "service-account-uuid"})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users/service-account-uuid/role-mappings/clients/proxy-uuid":
		_ = json.NewEncoder(w).Encode(fixture.managementMappings)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/roles/auditor":
		_ = json.NewEncoder(w).Encode(keycloak.RealmRole{ID: "auditor-uuid", Name: "auditor", Description: "Audit access"})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/authentication/required-actions/CONFIGURE_TOTP":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"alias": "CONFIGURE_TOTP", "providerId": "CONFIGURE_TOTP", "enabled": false, "defaultAction": false,
		})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/authentication/required-actions/CONFIGURE_TOTP":
		fixture.decode(request, &fixture.requiredAction)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/events/config":
		fixture.decode(request, &fixture.eventsPayload)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients" && request.URL.Query().Get("clientId") == "security-admin-console":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "console-uuid", "clientId": "security-admin-console"}})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/console-uuid":
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "console-uuid", "clientId": "security-admin-console", "enabled": true})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/clients/console-uuid":
		fixture.decode(request, &fixture.adminPayload)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/identity-provider/instances":
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"alias": "entra", "providerId": "oidc", "trustEmail": true,
			"config": map[string]any{"validateSignature": "false", "clientId": "preserved"},
		}})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra":
		fixture.decode(request, &fixture.identityPayload)
		w.WriteHeader(http.StatusNoContent)
	default:
		fixture.unexpected(w, request)
	}
}

func (fixture *managedRealmAPIFixture) decode(request *http.Request, target any) {
	fixture.t.Helper()
	if request.Header.Get("Authorization") != "Bearer token" {
		fixture.t.Errorf("missing bearer authentication for %s", request.URL.Path)
	}
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		fixture.t.Fatalf("decode %s: %v", request.URL.Path, err)
	}
}

func (fixture *managedRealmAPIFixture) unexpected(w http.ResponseWriter, request *http.Request) {
	fixture.t.Errorf("unexpected managed realm request: %s %s", request.Method, request.URL.String())
	http.NotFound(w, request)
}

func TestManagedRealmReconcileAppliesSecurityBaselineEndToEnd(t *testing.T) {
	fixture, keycloakClient := newManagedRealmAPIFixture(t)
	enabled, disabled, requireSignature := true, false, true
	retention, history, rotation := 30, 5, 90
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test", Generation: 4},
		Spec: hankoshv1alpha1.HankoRealmSpec{
			DisplayName: "Acme", FrontendURL: "https://login.acme.example", LoginTheme: "base",
			Roles: []hankoshv1alpha1.RealmRole{{Name: "auditor", Description: "Audit access"}},
			SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
				MFAPolicy: "required", PasswordMinLength: 14, PasswordExpiryDays: 60, PasswordHistory: &history,
				PasswordRequireSpecial: &enabled, PasswordDisallowEmail: &enabled,
				BruteForce:      &hankoshv1alpha1.BruteForcePolicy{Enabled: true, MaxFailures: 4, WaitIncrements: "2m"},
				SessionLifetime: "8h", SessionIdleTimeout: "30m", SSLRequired: "all",
				RevokeRefreshToken: true, OTPAlgorithm: "HmacSHA256", OTPDigits: 8, OTPPeriodSeconds: 45,
				EmailVerificationRequired: &enabled, RememberMeEnabled: &disabled, UserRegistrationEnabled: &disabled,
				UserEventsEnabled: &enabled, AdminEventsEnabled: &enabled, AuditRetentionDays: &retention,
				AuditExportEnabled: &enabled, ClientSecretRotationDays: &rotation, AdminConsoleExposure: "disabled",
				IDPBrokerRequireSignature: &requireSignature, IDPBrokerTrustEmail: &disabled,
			},
		},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, realm)
	reconciler := &HankoRealmReconciler{
		Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(keycloakClient),
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)})
	if err != nil {
		t.Fatalf("reconcile managed realm: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("managed realm must schedule drift detection")
	}
	var actual hankoshv1alpha1.HankoRealm
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(realm), &actual); err != nil {
		t.Fatalf("get reconciled realm: %v", err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.KeycloakRealmID != "realm-uuid" || actual.Status.ObservedGeneration != 4 {
		t.Fatalf("unexpected managed realm status: %#v", actual.Status)
	}
	if fixture.realmPayload["sslRequired"] != "all" || fixture.realmPayload["bruteForceProtected"] != true {
		t.Fatalf("realm security baseline not applied: %#v", fixture.realmPayload)
	}
	attributes, _ := fixture.realmPayload["attributes"].(map[string]any)
	if attributes["unmanaged"] != "preserved" || attributes["frontendUrl"] != realm.Spec.FrontendURL {
		t.Fatalf("realm attributes were not merged safely: %#v", attributes)
	}
	if fixture.eventsPayload["eventsExpiration"] != float64(retention*24*60*60) {
		t.Fatalf("unexpected event retention: %#v", fixture.eventsPayload)
	}
	if fixture.adminPayload["enabled"] != false {
		t.Fatalf("admin console was not disabled: %#v", fixture.adminPayload)
	}
	identityConfig, _ := fixture.identityPayload["config"].(map[string]any)
	if fixture.identityPayload["trustEmail"] != false || identityConfig["validateSignature"] != "true" || identityConfig["clientId"] != "preserved" {
		t.Fatalf("identity-provider trust was not hardened safely: %#v", fixture.identityPayload)
	}
	if fixture.requiredAction["enabled"] != true || fixture.requiredAction["defaultAction"] != true {
		t.Fatalf("required MFA action was not enabled: %#v", fixture.requiredAction)
	}
}

func TestManagedRealmDeletionRemovesOnlyValidatedRealmResources(t *testing.T) {
	deletedRealm, deletedProxy := false, false
	roles := make([]keycloak.RealmRole, 0, len(managedRealmRoleNames))
	for _, name := range managedRealmRoleNames {
		roles = append(roles, keycloak.RealmRole{ID: "role-" + name, Name: name})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme":
			_ = json.NewEncoder(w).Encode(keycloak.Realm{ID: "realm-uuid", RealmName: "acme"})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme":
			deletedRealm = true
			w.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients":
			switch request.URL.Query().Get("clientId") {
			case "acme-realm":
				_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "proxy-uuid", "clientId": "acme-realm"}})
			case "operator":
				_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "operator-uuid", "clientId": "operator"}})
			default:
				http.NotFound(w, request)
			}
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/proxy-uuid":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "proxy-uuid", "clientId": "acme-realm", "enabled": true, "bearerOnly": true,
				"publicClient": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false,
				"protocol": "openid-connect", "attributes": map[string]string{"realm_client": "true"},
			})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/proxy-uuid/roles":
			_ = json.NewEncoder(w).Encode(roles)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/operator-uuid/service-account-user":
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "service-account-uuid"})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users/service-account-uuid/role-mappings/clients/proxy-uuid":
			_ = json.NewEncoder(w).Encode(roles)
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/master/clients/proxy-uuid":
			deletedProxy = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	now := metav1.Now()
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme", Namespace: "test", Finalizers: []string{realmFinalizerName}, DeletionTimestamp: &now,
		},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, realm)
	reconciler := &HankoRealmReconciler{
		Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(keycloak.New(server.URL, "operator", "secret")),
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
		t.Fatalf("delete managed realm: %v", err)
	}
	if !deletedRealm || !deletedProxy {
		t.Fatalf("Keycloak cleanup incomplete: realm=%t proxy=%t", deletedRealm, deletedProxy)
	}
}

func TestRealmDependencyWatchMappingIsScoped(t *testing.T) {
	managed := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{LoginTheme: "brand"},
	}
	imported := managed.DeepCopy()
	imported.Name = "imported"
	imported.Labels = map[string]string{ImportedByLabel: "migration"}
	unrelated := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "test"}}
	reconciler := &HankoRealmReconciler{Client: controllerTestClient(controllerTestScheme(t), managed, imported, unrelated)}
	ctx := context.Background()

	themeRequests := reconciler.realmRequestsForTheme(ctx, &hankoshv1alpha1.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "brand", Namespace: "test"}})
	if len(themeRequests) != 2 {
		t.Fatalf("theme requests = %#v", themeRequests)
	}
	if requests := reconciler.realmRequestsForTheme(ctx, &corev1.ConfigMap{}); requests != nil {
		t.Fatalf("non-theme event produced requests: %#v", requests)
	}
	if got := durationSeconds("invalid"); got != 0 {
		t.Fatalf("invalid duration = %d", got)
	}
	if copied := copyStringMap(nil); copied != nil {
		t.Fatalf("nil map copy = %#v", copied)
	}
}
