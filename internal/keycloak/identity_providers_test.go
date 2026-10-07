package keycloak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestEnsureIdentityProviderIsIdempotentAndCorrectsDeclaredDrift(t *testing.T) {
	providers := []keycloak.IdentityProvider{}
	creates := 0
	updates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/alien6/identity-provider/instances":
			_ = json.NewEncoder(w).Encode(providers)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/alien6/identity-provider/instances":
			var provider keycloak.IdentityProvider
			if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			providers = append(providers, provider)
			creates++
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/alien6/identity-provider/instances/entra":
			if err := json.NewDecoder(r.Body).Decode(&providers[0]); err != nil {
				t.Fatalf("decode update: %v", err)
			}
			updates++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret")
	desired := keycloak.IdentityProvider{
		Alias: "entra", DisplayName: "Microsoft Entra ID", ProviderID: "oidc", Enabled: true, TrustEmail: true,
		Config: map[string]string{"clientId": "hanko", "issuer": "https://login.microsoftonline.com/tenant/v2.0"},
	}
	if _, err := client.EnsureIdentityProvider(context.Background(), "alien6", desired); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if _, err := client.EnsureIdentityProvider(context.Background(), "alien6", desired); err != nil {
		t.Fatalf("idempotent ensure: %v", err)
	}
	if creates != 1 || updates != 0 {
		t.Fatalf("after stable ensure creates=%d updates=%d, want 1/0", creates, updates)
	}

	providers[0].Config["issuer"] = "https://drift.invalid"
	providers[0].Config["opaqueProviderDefault"] = "preserved"
	if _, err := client.EnsureIdentityProvider(context.Background(), "alien6", desired); err != nil {
		t.Fatalf("drift ensure: %v", err)
	}
	if updates != 1 || providers[0].Config["issuer"] != desired.Config["issuer"] || providers[0].Config["opaqueProviderDefault"] != "preserved" {
		t.Fatalf("drift update=%d provider=%+v", updates, providers[0])
	}
}

func TestDeleteIdentityProviderAcceptsMissingProvider(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
			return
		}
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/missing") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := keycloak.New(server.URL, "client", "secret")
	if err := client.DeleteIdentityProvider(context.Background(), "alien6", "entra"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if err := client.DeleteIdentityProvider(context.Background(), "alien6", "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("delete paths = %v", paths)
	}
}
