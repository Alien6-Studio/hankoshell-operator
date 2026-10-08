package keycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const orgProbeTokenPath = "/realms/master/protocol/openid-connect/token"

func TestEnsureOrganizationsEnabled(t *testing.T) {
	var putPayload map[string]any
	putCalls := 0
	enabled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme":
			_ = json.NewEncoder(w).Encode(map[string]any{"realm": "acme", "organizationsEnabled": enabled})
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/acme":
			putCalls++
			if err := json.NewDecoder(r.Body).Decode(&putPayload); err != nil {
				t.Fatalf("decode realm payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	if err := client.EnsureOrganizationsEnabled(context.Background(), "acme"); err != nil {
		t.Fatalf("EnsureOrganizationsEnabled: %v", err)
	}
	if putCalls != 1 || putPayload["organizationsEnabled"] != true {
		t.Fatalf("expected one PUT enabling organizations, got %d calls, payload %#v", putCalls, putPayload)
	}

	enabled = true
	if err := client.EnsureOrganizationsEnabled(context.Background(), "acme"); err != nil {
		t.Fatalf("EnsureOrganizationsEnabled (already on): %v", err)
	}
	if putCalls != 1 {
		t.Fatalf("an already-enabled realm must not be rewritten, got %d PUT calls", putCalls)
	}
}

func TestEnsureOrganizationCreates(t *testing.T) {
	var created Organization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/organizations":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/acme/organizations":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode organization payload: %v", err)
			}
			w.Header().Set("Location", "http://"+r.Host+"/admin/realms/acme/organizations/org-uuid")
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	id, err := client.EnsureOrganization(context.Background(), "acme", OrganizationSpec{
		Alias: "alien6", Name: "Alien6", Domains: []string{"alien6.com"},
	})
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if id != "org-uuid" {
		t.Fatalf("id = %q, want org-uuid", id)
	}
	if created.Alias != "alien6" || created.Name != "Alien6" || !created.Enabled {
		t.Fatalf("created organization = %#v", created)
	}
	if len(created.Domains) != 1 || created.Domains[0].Name != "alien6.com" {
		t.Fatalf("created domains = %#v", created.Domains)
	}
}

func TestEnsureOrganizationAdoptsAndRealignsDrift(t *testing.T) {
	var updated Organization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/organizations":
			_, _ = w.Write([]byte(`[{"id":"org-uuid","name":"Old Name","alias":"alien6","enabled":true,"domains":[{"name":"old.com","verified":true}]}]`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/acme/organizations/org-uuid":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	id, err := client.EnsureOrganization(context.Background(), "acme", OrganizationSpec{
		Alias: "alien6", Name: "Alien6", Domains: []string{"alien6.com"},
	})
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if id != "org-uuid" {
		t.Fatalf("id = %q, want org-uuid", id)
	}
	if updated.ID != "org-uuid" || updated.Name != "Alien6" {
		t.Fatalf("updated organization = %#v", updated)
	}
	if len(updated.Domains) != 1 || updated.Domains[0].Name != "alien6.com" {
		t.Fatalf("updated domains = %#v", updated.Domains)
	}
}

func TestEnsureOrganizationConflictAdoptsWinner(t *testing.T) {
	listCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/organizations":
			listCalls++
			if listCalls == 1 {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"winner-uuid","name":"Alien6","alias":"alien6","enabled":true}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/acme/organizations":
			w.WriteHeader(http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	id, err := client.EnsureOrganization(context.Background(), "acme", OrganizationSpec{Alias: "alien6", Name: "Alien6"})
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if id != "winner-uuid" {
		t.Fatalf("id = %q, want winner-uuid", id)
	}
}

func TestDeleteOrganizationMissingIsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	if err := client.DeleteOrganization(context.Background(), "acme", "gone-uuid"); err != nil {
		t.Fatalf("DeleteOrganization on a missing organization must succeed: %v", err)
	}
}

func TestOrganizationDrifted(t *testing.T) {
	base := Organization{Name: "Alien6", Enabled: true, Domains: []OrganizationDomain{{Name: "alien6.com", Verified: true}}}
	tests := []struct {
		name     string
		observed Organization
		spec     OrganizationSpec
		want     bool
	}{
		{
			name:     "aligned including verified domain",
			observed: base,
			spec:     OrganizationSpec{Alias: "alien6", Name: "Alien6", Domains: []string{"alien6.com"}},
			want:     false,
		},
		{
			name:     "renamed",
			observed: base,
			spec:     OrganizationSpec{Alias: "alien6", Name: "Alien6 SAS", Domains: []string{"alien6.com"}},
			want:     true,
		},
		{
			name:     "disabled must be re-enabled",
			observed: Organization{Name: "Alien6", Enabled: false, Domains: []OrganizationDomain{{Name: "alien6.com"}}},
			spec:     OrganizationSpec{Alias: "alien6", Name: "Alien6", Domains: []string{"alien6.com"}},
			want:     true,
		},
		{
			name:     "domain added",
			observed: base,
			spec:     OrganizationSpec{Alias: "alien6", Name: "Alien6", Domains: []string{"alien6.com", "alien6.io"}},
			want:     true,
		},
		{
			name:     "domain removed",
			observed: base,
			spec:     OrganizationSpec{Alias: "alien6", Name: "Alien6"},
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := organizationDrifted(tt.observed, tt.spec); got != tt.want {
				t.Errorf("organizationDrifted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureOrganizationIdentityProviderLinksAndPrunes(t *testing.T) {
	var linkedBody string
	linkCalls, unlinked := 0, ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/organizations/org-uuid/identity-providers":
			_, _ = w.Write([]byte(`[{"alias":"legacy-idp","providerId":"oidc"}]`))
		case r.Method == http.MethodDelete && r.URL.Path == "/admin/realms/acme/organizations/org-uuid/identity-providers/legacy-idp":
			unlinked = "legacy-idp"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/acme/organizations/org-uuid/identity-providers":
			linkCalls++
			body, _ := io.ReadAll(r.Body)
			linkedBody = string(body)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	if err := client.EnsureOrganizationIdentityProvider(context.Background(), "acme", "org-uuid", "entra"); err != nil {
		t.Fatalf("EnsureOrganizationIdentityProvider: %v", err)
	}
	if unlinked != "legacy-idp" {
		t.Fatalf("undeclared broker link must be pruned, unlinked = %q", unlinked)
	}
	if linkCalls != 1 || linkedBody != "entra" {
		t.Fatalf("expected one raw-alias link POST, got %d calls, body %q", linkCalls, linkedBody)
	}
}

func TestEnsureOrganizationIdentityProviderAlreadyLinkedIsNoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/organizations/org-uuid/identity-providers":
			_, _ = w.Write([]byte(`[{"alias":"entra","providerId":"oidc"}]`))
		case r.Method == http.MethodPost || r.Method == http.MethodDelete:
			t.Errorf("unexpected %s %s: an already-linked broker must not be rewritten", r.Method, r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	if err := client.EnsureOrganizationIdentityProvider(context.Background(), "acme", "org-uuid", "entra"); err != nil {
		t.Fatalf("EnsureOrganizationIdentityProvider: %v", err)
	}
}

func TestEnsureOrganizationIdentityProviderEmptyAliasIsUnmanaged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s: empty alias must leave links unmanaged", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret", WithInsecureHTTP())
	if err := client.EnsureOrganizationIdentityProvider(context.Background(), "acme", "org-uuid", ""); err != nil {
		t.Fatalf("EnsureOrganizationIdentityProvider with empty alias: %v", err)
	}
}
