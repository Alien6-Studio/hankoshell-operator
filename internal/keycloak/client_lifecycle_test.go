package keycloak

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewWithTLSUsesProvidedCAAndTLS12Minimum(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case "/admin/serverinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.1.0"}})
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewWithTLS(server.URL, "operator", "secret", caPEM)
	if err != nil {
		t.Fatalf("create TLS client: %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unsafe TLS transport: %#v", client.httpClient.Transport)
	}
	version, err := client.ServerVersion(context.Background())
	if err != nil || version != "26.1.0" {
		t.Fatalf("probe with custom CA: version=%q err=%v", version, err)
	}
	if _, err := NewWithTLS(server.URL, "operator", "secret", []byte("not a certificate")); err == nil {
		t.Fatal("invalid CA bundle must be rejected")
	}
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HANKO_KEYCLOAK_URL", server.URL)
	t.Setenv("HANKO_KC_CLIENT_ID", "operator")
	t.Setenv("HANKO_KC_CLIENT_SECRET", "secret")
	t.Setenv("HANKO_KEYCLOAK_CA_FILE", caFile)
	envClient, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if version, err := envClient.ServerVersion(context.Background()); err != nil || version != "26.1.0" {
		t.Fatalf("environment client with private CA: version=%q err=%v", version, err)
	}
	if err := os.WriteFile(caFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("an empty configured CA file must not fall back to system trust")
	}
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HANKO_KEYCLOAK_URL", "http://keycloak.example.com")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("a CA must not silently allow plaintext HTTP")
	}
	t.Setenv("HANKO_KEYCLOAK_URL", server.URL)
	t.Setenv("HANKO_KEYCLOAK_CA_FILE", filepath.Join(t.TempDir(), "missing.crt"))
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("a missing CA must not fall back to another trust store")
	}
}

func TestNewFromEnvValidatesCredentials(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_CA_FILE", "")
	t.Setenv("HANKO_KEYCLOAK_URL", "")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("missing Keycloak URL must be rejected")
	}
	t.Setenv("HANKO_KEYCLOAK_URL", "https://keycloak.example.com/")
	t.Setenv("HANKO_KC_CLIENT_ID", "")
	t.Setenv("HANKO_KC_CLIENT_SECRET", "")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("missing client credentials must be rejected")
	}
	t.Setenv("HANKO_KC_CLIENT_ID", "operator")
	t.Setenv("HANKO_KC_CLIENT_SECRET", "secret")
	client, err := NewFromEnv()
	if err != nil || client.BaseURL() != "https://keycloak.example.com" {
		t.Fatalf("valid environment client: baseURL=%q err=%v", client.BaseURL(), err)
	}
	if got := (Realm{ID: "uuid", RealmName: "acme"}).URLName(); got != "acme" {
		t.Fatalf("realm URL name = %q", got)
	}
	if got := (Realm{ID: "master"}).URLName(); got != "master" {
		t.Fatalf("realm ID fallback = %q", got)
	}
}

func TestCAFileAcceptsSecretProjectionAndRejectsDirectoryEscape(t *testing.T) {
	directory := t.TempDir()
	projection := filepath.Join(directory, "..version")
	if err := os.Mkdir(projection, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projection, "ca.crt"), []byte("projected CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..version", filepath.Join(directory, "..data")); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(directory, "ca.crt")
	if err := os.Symlink("..data/ca.crt", caFile); err != nil {
		t.Fatal(err)
	}
	if data, err := readCAFile(caFile); err != nil || string(data) != "projected CA" {
		t.Fatalf("Kubernetes Secret projection must remain readable: data=%q err=%v", data, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.crt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(directory, "escape.crt")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{escape, "relative.crt", directory + "/../escape.crt"} {
		if _, err := readCAFile(path); err == nil {
			t.Fatalf("unsafe CA path must be rejected: %q", path)
		}
	}
}

type clientLifecycleFixture struct {
	t                  *testing.T
	createdRealm       map[string]any
	hardenedMaster     map[string]any
	updatedClient      map[string]any
	createdClientRoles int
	deleted            map[string]bool
}

func newClientLifecycleFixture(t *testing.T) (*clientLifecycleFixture, *Client) {
	t.Helper()
	fixture := &clientLifecycleFixture{t: t, deleted: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	return fixture, New(server.URL, "operator", "secret", WithInsecureHTTP())
}

func (fixture *clientLifecycleFixture) serveHTTP(w http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms":
		_ = json.NewEncoder(w).Encode([]Realm{{ID: "realm-uuid", RealmName: "acme", Enabled: true}})
	case request.Method == http.MethodPost && request.URL.Path == "/admin/realms":
		fixture.decode(request, &fixture.createdRealm)
		w.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/master":
		fixture.decode(request, &fixture.hardenedMaster)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme":
		_ = json.NewEncoder(w).Encode(Realm{ID: "realm-uuid", RealmName: "acme", Enabled: true})
	case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme":
		fixture.deleted["realm"] = true
		w.WriteHeader(http.StatusNotFound)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients" && request.URL.RawQuery == "":
		_ = json.NewEncoder(w).Encode([]App{{ClientID: "web", Name: "Web", Enabled: true}})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
		clientID := request.URL.Query().Get("clientId")
		if clientID == "web" || clientID == "service" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": clientID + "-uuid", "clientId": clientID}})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/clients":
		var payload map[string]any
		fixture.decode(request, &payload)
		w.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/web-uuid":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "web-uuid", "clientId": "web", "enabled": true, "fullScopeAllowed": false,
			"attributes": map[string]any{"hanko.app": "true", "unmanaged": "old"},
		})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/clients/web-uuid":
		fixture.decode(request, &fixture.updatedClient)
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/clients/web-uuid":
		fixture.deleted["client"] = true
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/web-uuid/client-secret":
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "current-secret"})
	case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/clients/web-uuid/client-secret":
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "rotated-secret"})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/web-uuid/roles":
		_ = json.NewEncoder(w).Encode([]ClientRole{{Name: "reader", Description: "Read"}})
	case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/clients/web-uuid/roles":
		fixture.createdClientRoles++
		w.WriteHeader(http.StatusConflict)
	case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/clients/web-uuid/roles/reader":
		fixture.deleted["client-role"] = true
		w.WriteHeader(http.StatusNotFound)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/roles/auditor":
		_ = json.NewEncoder(w).Encode(RealmRole{ID: "auditor-uuid", Name: "auditor", Description: "old", ContainerID: "acme"})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/roles/auditor":
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/roles/auditor":
		fixture.deleted["realm-role"] = true
		w.WriteHeader(http.StatusNoContent)
	default:
		fixture.t.Errorf("unexpected client lifecycle request: %s %s", request.Method, request.URL.String())
		http.NotFound(w, request)
	}
}

func (fixture *clientLifecycleFixture) decode(request *http.Request, target any) {
	fixture.t.Helper()
	if request.Header.Get(authorizationHeader) != bearerPrefix+"token" || request.Header.Get(forwardedProtoHeader) != httpsScheme {
		fixture.t.Errorf("security headers missing for %s", request.URL.Path)
	}
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		fixture.t.Fatalf("decode lifecycle payload: %v", err)
	}
}

func TestClientRealmAndApplicationLifecycle(t *testing.T) {
	fixture, client := newClientLifecycleFixture(t)
	ctx := context.Background()
	enabled := true
	if realms, err := client.ListRealms(ctx); err != nil || len(realms) != 1 || realms[0].URLName() != "acme" {
		t.Fatalf("list realms: realms=%#v err=%v", realms, err)
	}
	if err := client.CreateRealm(ctx, RealmSpec{
		ID: "acme", DisplayName: "Acme", FrontendURL: "https://login.acme.example", LoginTheme: "base", Enabled: true,
		BruteForceProtected: true, FailureFactor: 4, WaitIncrementSeconds: 60,
		PasswordPolicy: "length(14)", MFAPolicy: "optional", VerifyEmail: &enabled,
	}); err != nil {
		t.Fatalf("create realm: %v", err)
	}
	if fixture.createdRealm["sslRequired"] != "external" || fixture.createdRealm["bruteForceProtected"] != true {
		t.Fatalf("unsafe realm payload: %#v", fixture.createdRealm)
	}
	if err := client.HardenMasterRealm(ctx); err != nil {
		t.Fatalf("harden master realm: %v", err)
	}
	if fixture.hardenedMaster["sslRequired"] != "external" ||
		fixture.hardenedMaster["bruteForceProtected"] != true ||
		fixture.hardenedMaster["registrationAllowed"] != false ||
		fixture.hardenedMaster["refreshTokenMaxReuse"] != float64(0) {
		t.Fatalf("unsafe master realm baseline: %#v", fixture.hardenedMaster)
	}
	if err := client.DeleteRealm(ctx, "acme"); err != nil || !fixture.deleted["realm"] {
		t.Fatalf("idempotent realm deletion: deleted=%t err=%v", fixture.deleted["realm"], err)
	}

	exists, err := client.ClientExists(ctx, "acme", "web")
	if err != nil || !exists {
		t.Fatalf("existing client lookup: exists=%t err=%v", exists, err)
	}
	exists, err = client.ClientExists(ctx, "acme", "missing")
	if err != nil || exists {
		t.Fatalf("missing client lookup: exists=%t err=%v", exists, err)
	}
	if apps, err := client.ListApps(ctx, "acme"); err != nil || len(apps) != 1 {
		t.Fatalf("list apps: apps=%#v err=%v", apps, err)
	}
	secret, err := client.CreateApp(ctx, "acme", CreateAppSpec{
		ClientID: "web", Name: "Web", Type: "web", RedirectURIs: []string{"https://app.example/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example"}, Theme: "brand",
	})
	if err != nil || secret != "current-secret" {
		t.Fatalf("create confidential app: secret=%q err=%v", secret, err)
	}
	if err := client.UpdateAppAttributes(ctx, "acme", "web", map[string]string{"department": "security"}); err != nil {
		t.Fatalf("update app attributes: %v", err)
	}
	attributes, _ := fixture.updatedClient["attributes"].(map[string]any)
	if attributes["hanko.app"] != "true" || attributes["department"] != "security" {
		t.Fatalf("managed attributes were not merged safely: %#v", attributes)
	}
	if current, err := client.GetClientSecret(ctx, "acme", "web"); err != nil || current != "current-secret" {
		t.Fatalf("get client secret: secret=%q err=%v", current, err)
	}
	if rotated, err := client.RotateClientSecret(ctx, "acme", "web"); err != nil || rotated != "rotated-secret" {
		t.Fatalf("rotate client secret: secret=%q err=%v", rotated, err)
	}
	if err := client.SetClientSecret(ctx, "acme", "web", "caller-generated-secret-with-32-chars"); err != nil {
		t.Fatalf("set recoverable client secret: %v", err)
	}
	if fixture.updatedClient["secret"] != "caller-generated-secret-with-32-chars" || fixture.updatedClient["clientId"] != "web" {
		t.Fatalf("secret replacement did not preserve the client representation: %#v", fixture.updatedClient)
	}
	if err := client.DeleteApp(ctx, "acme", "web"); err != nil || !fixture.deleted["client"] {
		t.Fatalf("delete app: deleted=%t err=%v", fixture.deleted["client"], err)
	}
}

func TestClientAndRealmRoleLifecycle(t *testing.T) {
	fixture, client := newClientLifecycleFixture(t)
	ctx := context.Background()
	roles, err := client.ListClientRoles(ctx, "acme", "web")
	if err != nil || len(roles) != 1 || roles[0].Name != "reader" {
		t.Fatalf("list client roles: roles=%#v err=%v", roles, err)
	}
	if err := client.CreateClientRole(ctx, "acme", "web", "writer", "Write"); err != nil || fixture.createdClientRoles != 1 {
		t.Fatalf("create client role: calls=%d err=%v", fixture.createdClientRoles, err)
	}
	if err := client.DeleteClientRole(ctx, "acme", "web", "reader"); err != nil || !fixture.deleted["client-role"] {
		t.Fatalf("delete client role: deleted=%t err=%v", fixture.deleted["client-role"], err)
	}
	if err := client.SyncRealmRole(ctx, "acme", RealmRole{Name: "auditor", Description: "new"}); err != nil {
		t.Fatalf("sync realm role: %v", err)
	}
	if err := client.DeleteRealmRole(ctx, "acme", "auditor"); err != nil || !fixture.deleted["realm-role"] {
		t.Fatalf("delete realm role: deleted=%t err=%v", fixture.deleted["realm-role"], err)
	}
}
