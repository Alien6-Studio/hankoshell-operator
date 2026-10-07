package keycloak_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestIsNotFound_Nil(t *testing.T) {
	if keycloak.IsNotFound(nil) {
		t.Error("IsNotFound(nil) must be false")
	}
}

func TestIsNotFound_404(t *testing.T) {
	err := fmt.Errorf("keycloak /admin/realms/x 404: realm not found")
	if !keycloak.IsNotFound(err) {
		t.Errorf("IsNotFound(%v) must be true for a 404 error", err)
	}
}

func TestIsNotFound_500(t *testing.T) {
	err := fmt.Errorf("keycloak /admin/realms/x 500: internal error")
	if keycloak.IsNotFound(err) {
		t.Errorf("IsNotFound(%v) must be false for a 500 error", err)
	}
}

func TestIsForbidden(t *testing.T) {
	if !keycloak.IsForbidden(fmt.Errorf("keycloak /admin/realms/x 403: forbidden")) {
		t.Error("IsForbidden must recognize Keycloak 403 responses")
	}
	if keycloak.IsForbidden(fmt.Errorf("keycloak /admin/realms/x 404: not found")) {
		t.Error("IsForbidden must reject non-403 responses")
	}
	if keycloak.IsForbidden(nil) {
		t.Error("IsForbidden(nil) must be false")
	}
}

func TestOperationalSecurityControls(t *testing.T) {
	var eventsPayload map[string]any
	var consolePayload map[string]any
	var brokerPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/regulated/events/config":
			if err := json.NewDecoder(r.Body).Decode(&eventsPayload); err != nil {
				t.Fatalf("decode events payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/regulated/clients" && r.URL.Query().Get("clientId") == "security-admin-console":
			_, _ = w.Write([]byte(`[{"id":"console-uuid","clientId":"security-admin-console"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/regulated/clients/console-uuid":
			_, _ = w.Write([]byte(`{"id":"console-uuid","clientId":"security-admin-console","enabled":true}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/regulated/clients/console-uuid":
			if err := json.NewDecoder(r.Body).Decode(&consolePayload); err != nil {
				t.Fatalf("decode console payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/regulated/identity-provider/instances":
			_, _ = w.Write([]byte(`[{"alias":"entra","providerId":"oidc","enabled":true,"trustEmail":true,"config":{"clientId":"kept","validateSignature":"false"}}]`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/regulated/identity-provider/instances/entra":
			if err := json.NewDecoder(r.Body).Decode(&brokerPayload); err != nil {
				t.Fatalf("decode broker payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	retention := 365
	enabled := true
	disabled := false
	spec := keycloak.RealmSpec{
		EventsEnabled: &enabled, AdminEventsEnabled: &enabled,
		AuditRetentionDays: &retention, AuditExportEnabled: &enabled,
	}
	if err := client.ConfigureRealmEvents(context.Background(), "regulated", spec); err != nil {
		t.Fatalf("ConfigureRealmEvents: %v", err)
	}
	if eventsPayload["eventsExpiration"] != float64(365*24*60*60) {
		t.Fatalf("events payload = %#v", eventsPayload)
	}
	listeners, _ := eventsPayload["eventsListeners"].([]any)
	if len(listeners) != 1 || listeners[0] != "jboss-logging" {
		t.Fatalf("event listeners = %#v", listeners)
	}
	if err := client.ConfigureAdminConsoleExposure(context.Background(), "regulated", "disabled"); err != nil {
		t.Fatalf("ConfigureAdminConsoleExposure: %v", err)
	}
	if consolePayload["enabled"] != false {
		t.Fatalf("console payload = %#v", consolePayload)
	}
	if err := client.ConfigureIdentityProviderTrust(context.Background(), "regulated", &enabled, &disabled); err != nil {
		t.Fatalf("ConfigureIdentityProviderTrust: %v", err)
	}
	config, _ := brokerPayload["config"].(map[string]any)
	if brokerPayload["trustEmail"] != false || config["validateSignature"] != "true" || config["clientId"] != "kept" {
		t.Fatalf("broker payload = %#v", brokerPayload)
	}
}

func TestRealmManagementAccessNeverGrantsAuthority(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/realms/master/protocol/openid-connect/token":
					_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
				case "/admin/realms/recipe":
					if r.Method != http.MethodGet {
						t.Error("access check mutated realm")
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"realm":"recipe"}`))
				default:
					t.Errorf("access check attempted unprovisioned authority: %s %s", r.Method, r.URL.Path)
					http.Error(w, "forbidden", http.StatusForbidden)
				}
			}))
			defer server.Close()
			client := keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP())
			err := client.EnsureRealmManagementAccess(context.Background(), "recipe")
			if (err == nil) != (status == http.StatusOK) {
				t.Fatalf("access check: %v", err)
			}
			err = client.EnsureRealmDeletionAccess(context.Background(), "recipe")
			if (err == nil) != (status != http.StatusForbidden) {
				t.Fatalf("deletion access check: %v", err)
			}
		})
	}
}

func TestRealmDeletionAccessSkipsProxyForMissingRealm(t *testing.T) {
	clientLookups := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/missing":
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/master/clients"):
			clientLookups++
			http.Error(w, "unexpected proxy operation", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected Keycloak request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "keycloak-ops", "secret", keycloak.WithInsecureHTTP())
	if err := client.EnsureRealmDeletionAccess(context.Background(), "missing"); err != nil {
		t.Fatalf("EnsureRealmDeletionAccess for missing realm: %v", err)
	}
	if clientLookups != 0 {
		t.Fatalf("missing realm triggered %d proxy operation(s)", clientLookups)
	}
}

func TestRealmManagementAccessProtectsMasterRealm(t *testing.T) {
	client := keycloak.New("http://unused.invalid", "keycloak-ops", "secret")
	for _, realm := range []string{"master", "", "unsafe/path"} {
		if err := client.EnsureRealmManagementAccess(context.Background(), realm); err == nil {
			t.Fatal("unsafe realm accepted")
		}
		if err := client.EnsureRealmDeletionAccess(context.Background(), realm); err == nil {
			t.Fatal("unsafe deletion accepted")
		}
	}
}

func TestJoinURIs(t *testing.T) {
	got := keycloak.JoinURIs([]string{"a", "b"})
	if got != "a##b" {
		t.Errorf("JoinURIs([a, b]) = %q, want %q", got, "a##b")
	}
}

func TestJoinURIs_Single(t *testing.T) {
	got := keycloak.JoinURIs([]string{"https://example.com/callback"})
	if got != "https://example.com/callback" {
		t.Errorf("JoinURIs single = %q", got)
	}
}

func TestJoinURIs_Empty(t *testing.T) {
	got := keycloak.JoinURIs([]string{})
	if got != "" {
		t.Errorf("JoinURIs([]) = %q, want empty string", got)
	}
}

func TestUpdateRealmPreservesAttributesWhenSettingFrontendURL(t *testing.T) {
	var updated map[string]any
	var requiredAction map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"realm":"alien6","attributes":{"hanko.managed":"true","darkMode":"true"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/authentication/required-actions/CONFIGURE_TOTP":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP","enabled":false,"defaultAction":false,"priority":10,"config":{"lifespan":"300"}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/alien6":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("Authorization = %q, want bearer token", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/alien6/authentication/required-actions/CONFIGURE_TOTP":
			if err := json.NewDecoder(r.Body).Decode(&requiredAction); err != nil {
				t.Fatalf("decode required action payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	enabled := true
	disabled := false
	if err := client.UpdateRealm(context.Background(), "alien6", keycloak.RealmSpec{
		FrontendURL:           "https://auth.hanko.sh",
		SSOSessionIdleTimeout: 900,
		OTPDigits:             8,
		OTPPeriod:             45,
		VerifyEmail:           &enabled,
		RememberMe:            &disabled,
		RegistrationAllowed:   &disabled,
		EventsEnabled:         &enabled,
		AdminEventsEnabled:    &enabled,
		MFAPolicy:             "required",
		BruteForceProtected:   true,
		FailureFactor:         5,
		WaitIncrementSeconds:  1800,
	}); err != nil {
		t.Fatalf("UpdateRealm: %v", err)
	}

	attributes, ok := updated["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes missing from payload: %#v", updated)
	}
	for key, want := range map[string]string{
		"frontendUrl":   "https://auth.hanko.sh",
		"hanko.managed": "true",
		"darkMode":      "true",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("attributes[%q] = %#v, want %q", key, got, want)
		}
	}
	for key, want := range map[string]any{
		"ssoSessionIdleTimeout": float64(900),
		"otpPolicyDigits":       float64(8),
		"otpPolicyPeriod":       float64(45),
		"verifyEmail":           true,
		"rememberMe":            false,
		"registrationAllowed":   false,
		"eventsEnabled":         true,
		"adminEventsEnabled":    true,
		"bruteForceProtected":   true,
		"failureFactor":         float64(5),
		"waitIncrementSeconds":  float64(1800),
		"maxFailureWaitSeconds": float64(1800),
	} {
		if got := updated[key]; got != want {
			t.Errorf("payload[%q] = %#v, want %#v", key, got, want)
		}
	}
	if _, invalid := updated["defaultRequiredActions"]; invalid {
		t.Errorf("realm payload contains unsupported defaultRequiredActions: %#v", updated)
	}
	if requiredAction["defaultAction"] != true || requiredAction["enabled"] != true || requiredAction["name"] != "Configure OTP" {
		t.Errorf("required action = %#v, want enabled default action with provider fields preserved", requiredAction)
	}
	config, ok := requiredAction["config"].(map[string]any)
	if !ok || config["lifespan"] != "300" {
		t.Errorf("required action config = %#v, want preserved lifespan", requiredAction["config"])
	}
}

func TestUpdateRealmNeverManagesSMTP(t *testing.T) {
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/acme":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode realm update: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.UpdateRealm(context.Background(), "acme", keycloak.RealmSpec{DisplayName: "Acme"}); err != nil {
		t.Fatalf("UpdateRealm: %v", err)
	}
	if _, managed := updated["smtpServer"]; managed {
		t.Fatalf("Hanko realm update must not manage Keycloak SMTP: %#v", updated)
	}
}

func TestUpdateRealmRemovesOnlyManagedMFARequiredAction(t *testing.T) {
	var updated map[string]any
	var requiredAction map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/authentication/required-actions/CONFIGURE_TOTP":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP","enabled":true,"defaultAction":true,"priority":10}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/alien6":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/alien6/authentication/required-actions/CONFIGURE_TOTP":
			if err := json.NewDecoder(r.Body).Decode(&requiredAction); err != nil {
				t.Fatalf("decode required action payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.UpdateRealm(context.Background(), "alien6", keycloak.RealmSpec{MFAPolicy: "none"}); err != nil {
		t.Fatalf("UpdateRealm: %v", err)
	}
	if _, invalid := updated["defaultRequiredActions"]; invalid {
		t.Errorf("realm payload contains unsupported defaultRequiredActions: %#v", updated)
	}
	if requiredAction["defaultAction"] != false || requiredAction["enabled"] != true {
		t.Errorf("required action = %#v, want non-default provider left enabled", requiredAction)
	}
}

func TestUpdateRealmLeavesAttributesUnmanagedWithoutFrontendURL(t *testing.T) {
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/gifen":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.UpdateRealm(context.Background(), "gifen", keycloak.RealmSpec{}); err != nil {
		t.Fatalf("UpdateRealm: %v", err)
	}
	if _, managed := updated["attributes"]; managed {
		t.Fatalf("attributes must remain unmanaged when FrontendURL is empty: %#v", updated)
	}
}

func TestSyncClientAttributesPreservesPrivilegeBearingFields(t *testing.T) {
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/master/clients" && r.URL.Query().Get("clientId") == "keycloak-ops":
			_, _ = w.Write([]byte(`[{"id":"client-uuid","clientId":"keycloak-ops"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/master/clients/client-uuid":
			_, _ = w.Write([]byte(`{
				"id":"client-uuid",
				"clientId":"keycloak-ops",
				"serviceAccountsEnabled":true,
				"fullScopeAllowed":true,
				"clientAuthenticatorType":"client-secret",
				"attributes":{"login_theme":"operations","stale":"remove"}
			}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/master/clients/client-uuid":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode client update: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.SyncClientAttributes(context.Background(), "master", "keycloak-ops", map[string]string{
		"owner":       "platform",
		"login_theme": "must-not-override",
	}); err != nil {
		t.Fatalf("SyncClientAttributes: %v", err)
	}

	for key, want := range map[string]any{
		"fullScopeAllowed":        true,
		"serviceAccountsEnabled":  true,
		"clientAuthenticatorType": "client-secret",
	} {
		if got := updated[key]; got != want {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	attributes, ok := updated["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes missing from update: %#v", updated)
	}
	if got := attributes["login_theme"]; got != "operations" {
		t.Errorf("reserved login_theme = %#v, want operations", got)
	}
	if got := attributes["owner"]; got != "platform" {
		t.Errorf("owner = %#v, want platform", got)
	}
	if _, exists := attributes["stale"]; exists {
		t.Errorf("stale unmanaged attribute was not removed: %#v", attributes)
	}
}

func TestApplicationOwnershipMarkersCannotBeSpoofed(t *testing.T) {
	var created map[string]any
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/acme/clients":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/clients" && r.URL.Query().Get("clientId") == "worker":
			_, _ = w.Write([]byte(`[{"id":"worker-uuid","clientId":"worker"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/clients/worker-uuid":
			_, _ = w.Write([]byte(`{"id":"worker-uuid","clientId":"worker","authorizationServicesEnabled":true}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/acme/clients/worker-uuid":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode update: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected Keycloak request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "keycloak-ops", "secret", keycloak.WithInsecureHTTP())
	spoofed := map[string]string{"hanko.app": "false", "hanko.service": "true"}
	if _, err := client.CreateApp(context.Background(), "acme", keycloak.CreateAppSpec{
		ClientID: "web", Type: "spa", Attributes: spoofed,
	}); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if err := client.UpdateApp(context.Background(), "acme", keycloak.CreateAppSpec{
		ClientID: "worker", Type: "m2m", Attributes: spoofed,
	}); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}

	createdAttrs := created["attributes"].(map[string]any)
	if createdAttrs["hanko.app"] != "true" || createdAttrs["hanko.service"] != nil {
		t.Fatalf("created ownership attributes = %#v", createdAttrs)
	}
	updatedAttrs := updated["attributes"].(map[string]any)
	if updatedAttrs["hanko.service"] != "true" || updatedAttrs["hanko.app"] != nil {
		t.Fatalf("updated ownership attributes = %#v", updatedAttrs)
	}
	if updated["authorizationServicesEnabled"] != true {
		t.Fatalf("UpdateApp cleared sibling-owned authorization setting: %#v", updated)
	}
}

func TestEnsureRealmRoleCreatesMissingRole(t *testing.T) {
	var created keycloak.RealmRole
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/HANKO_PLATFORM":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/alien6/roles":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode role: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.EnsureRealmRole(context.Background(), "alien6", "HANKO_PLATFORM", "hankoShell administrator"); err != nil {
		t.Fatalf("EnsureRealmRole: %v", err)
	}
	if created.Name != "HANKO_PLATFORM" || created.Description != "hankoShell administrator" {
		t.Fatalf("created role = %+v", created)
	}
}

func TestEnsureRealmRoleLeavesOmittedDescriptionUnmanaged(t *testing.T) {
	putCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/A6_TRUNX_PLATFORM":
			_, _ = w.Write([]byte(`{"id":"existing-id","name":"A6_TRUNX_PLATFORM","description":"Managed by Alien6"}`))
		case r.Method == http.MethodPut:
			putCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.EnsureRealmRole(context.Background(), "alien6", "A6_TRUNX_PLATFORM", ""); err != nil {
		t.Fatalf("EnsureRealmRole: %v", err)
	}
	if putCalls != 0 {
		t.Fatalf("existing description was overwritten: %d PUT request(s)", putCalls)
	}
}

func TestEnsureRealmRoleCompositesAddsOnlyMissingRoles(t *testing.T) {
	var added []keycloak.RealmRole
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/A6_TRUNX_PLATFORM":
			_, _ = w.Write([]byte(`{"id":"parent-id","name":"A6_TRUNX_PLATFORM"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/A6_EXISTING":
			_, _ = w.Write([]byte(`{"id":"existing-id","name":"A6_EXISTING"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/HANKO_PLATFORM":
			_, _ = w.Write([]byte(`{"id":"hanko-id","name":"HANKO_PLATFORM"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/A6_TRUNX_PLATFORM/composites/realm":
			_, _ = w.Write([]byte(`[{"id":"existing-id","name":"A6_EXISTING"}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/alien6/roles/A6_TRUNX_PLATFORM/composites":
			if err := json.NewDecoder(r.Body).Decode(&added); err != nil {
				t.Fatalf("decode composites: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	err := client.EnsureRealmRoleComposites(context.Background(), "alien6", "A6_TRUNX_PLATFORM", []string{
		"A6_EXISTING",
		"HANKO_PLATFORM",
	})
	if err != nil {
		t.Fatalf("EnsureRealmRoleComposites: %v", err)
	}
	if len(added) != 1 || added[0].ID != "hanko-id" || added[0].Name != "HANKO_PLATFORM" {
		t.Fatalf("added composites = %+v", added)
	}
}

func TestReconcileClientRealmRoleScopesAddsAndRemovesDrift(t *testing.T) {
	var added, removed []keycloak.RealmRole
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/clients":
			_, _ = w.Write([]byte(`[{"id":"client-uuid","clientId":"hanko-dashboard"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/clients/client-uuid/scope-mappings/realm":
			_, _ = w.Write([]byte(`[{"id":"old-id","name":"OLD_ROLE"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/roles/HANKO_PLATFORM":
			_, _ = w.Write([]byte(`{"id":"hanko-id","name":"HANKO_PLATFORM"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/alien6/clients/client-uuid/scope-mappings/realm":
			if err := json.NewDecoder(r.Body).Decode(&added); err != nil {
				t.Fatalf("decode added mappings: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/admin/realms/alien6/clients/client-uuid/scope-mappings/realm":
			if err := json.NewDecoder(r.Body).Decode(&removed); err != nil {
				t.Fatalf("decode removed mappings: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())
	if err := client.ReconcileClientRealmRoleScopes(context.Background(), "alien6", "hanko-dashboard", []string{"HANKO_PLATFORM"}); err != nil {
		t.Fatalf("ReconcileClientRealmRoleScopes: %v", err)
	}
	if len(added) != 1 || added[0].ID != "hanko-id" || added[0].Name != "HANKO_PLATFORM" {
		t.Fatalf("added mappings = %+v", added)
	}
	if len(removed) != 1 || removed[0].ID != "old-id" || removed[0].Name != "OLD_ROLE" {
		t.Fatalf("removed mappings = %+v", removed)
	}
}

func TestUpdateRealmOptionalMFAReconcilesOTP(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		digits, period, wantDigits, wantPeriod int
	}{
		{"configured", 8, 45, 8, 45},
		{"defaults", 0, 0, 6, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var realm, action map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
					_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
				case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/qa":
					if err := json.NewDecoder(r.Body).Decode(&realm); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/qa/authentication/required-actions/CONFIGURE_TOTP":
					_, _ = w.Write([]byte(`{"alias":"CONFIGURE_TOTP","providerId":"CONFIGURE_TOTP","enabled":true,"defaultAction":true}`))
				case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/qa/authentication/required-actions/CONFIGURE_TOTP":
					if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := keycloak.New(server.URL, "test-client", "test-secret", keycloak.WithInsecureHTTP())
			err := client.UpdateRealm(context.Background(), "qa", keycloak.RealmSpec{
				MFAPolicy: "optional", OTPAlgorithm: "HmacSHA256", OTPDigits: tc.digits, OTPPeriod: tc.period,
			})
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]any{
				"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256",
				"otpPolicyDigits": float64(tc.wantDigits), "otpPolicyPeriod": float64(tc.wantPeriod),
			} {
				if got := realm[key]; got != want {
					t.Errorf("realm[%q] = %v, want %v", key, got, want)
				}
			}
			if action["enabled"] != true || action["defaultAction"] != false {
				t.Errorf("optional MFA must remain available without forced enrollment: %#v", action)
			}
		})
	}
}
