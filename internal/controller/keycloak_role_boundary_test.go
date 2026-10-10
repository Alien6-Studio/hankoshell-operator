//go:build keycloak_integration

package controller_test

import (
	"net/http"
	"testing"
)

// These are captured requests from production HankoRole Manage and conservative
// deletion, not direct privilege probes. No request body or token is retained.
func qualifyRoleOperationInventory(t *testing.T, routes map[string]int, base, name string) {
	t.Helper()
	role := base + "/roles/" + name
	allowed := map[string]bool{
		http.MethodGet + " " + base:                                   true, // exact realm identity, read-only
		http.MethodGet + " " + role:                                   true,
		http.MethodGet + " " + role + "/composites":                   true,
		http.MethodGet + " " + role + "/composites/realm":             true,
		http.MethodGet + " " + role + "-foreign-composite":            true,
		http.MethodGet + " " + role + "-foreign-composite/composites": true,
		http.MethodGet + " " + role + "-desired-composite":            true,
		http.MethodGet + " " + role + "-desired-composite/composites": true,
		http.MethodPut + " " + role:                                   true,
		http.MethodPost + " " + role + "/composites":                  true,
	}
	for route := range routes {
		if !allowed[route] {
			t.Errorf("HankoRole issued an unqualified Admin API operation: %s", route)
		}
	}
	for _, required := range []string{http.MethodGet + " " + role, http.MethodPut + " " + role, http.MethodPost + " " + role + "/composites"} {
		if routes[required] == 0 {
			t.Errorf("HankoRole Manage did not exercise %s", required)
		}
	}
}

// Bootstrap reads the effective grant/scope configuration; direct probes check
// provider authority independently of controller ownership and request inventory.
func qualifyRoleWriterScope(t *testing.T, f *keycloakFixture, secret string) {
	t.Helper()
	writer := f.client("master", "ownership-role-writer")
	fixtureEqual(t, "role writer Full Scope Allowed disabled", writer["fullScopeAllowed"], false)
	proxy := f.client("master", "managed-realm")
	var scopes []map[string]any
	f.admin(http.MethodGet, "/admin/realms/master/clients/"+writer["id"].(string)+"/scope-mappings/clients/"+proxy["id"].(string), nil, &scopes)
	fixtureEqual(t, "exact permitted target-realm role scope", len(scopes), 1)
	fixtureEqual(t, "only target manage-realm scope", scopes[0]["name"], "manage-realm")
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "role-unrelated", "enabled": true}, nil)
	identity := adoptionProbe{f, "ownership-role-writer", secret}
	for _, realm := range []string{"master", "role-unrelated"} {
		path := "/admin/realms/" + realm
		fixtureEqual(t, "no unrelated realm security authority", identity.request(http.MethodPut, path, map[string]any{"bruteForceProtected": true}, nil), http.StatusForbidden)
		fixtureEqual(t, "no unrelated realm deletion authority", identity.request(http.MethodDelete, path, nil, nil), http.StatusForbidden)
		fixtureEqual(t, "no unrelated realm role authority", identity.request(http.MethodPost, path+"/roles", map[string]any{"name": "denied-role"}, nil), http.StatusForbidden)
	}
}
