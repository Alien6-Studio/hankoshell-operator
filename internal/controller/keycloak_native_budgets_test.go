//go:build keycloak_integration

package controller_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestRealKeycloakPublicStorageBudgets checks the actual provider columns rather
// than inferring native acceptance from successful Kubernetes admission. The
// official migration history supplies the ceiling; API tests refuse max+1 and
// compiler tests refuse it before provider I/O. Larger CLOB-backed metadata is
// intentionally exercised separately from native VARCHAR/NVARCHAR(255) fields.
func TestRealKeycloakPublicStorageBudgets(t *testing.T) {
	f := newKeycloakFixture(t)
	uri := "https://native-budget.example/" + strings.Repeat("a", 255-len("https://native-budget.example/"))
	text := strings.Repeat("é", 255)
	clientID := strings.Repeat("c", 255)
	create := func(path string, payload any) {
		f.t.Helper()
		if status := f.admin(http.MethodPost, path, payload, nil); status != http.StatusCreated {
			f.t.Fatalf("native budget fixture create returned HTTP %d", status)
		}
	}
	f.run("OIDC redirect and client ID maximum with larger NCLOB metadata", func(t *testing.T) {
		create("/admin/realms/managed/clients", map[string]any{"clientId": clientID, "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "redirectUris": []string{uri}, "attributes": map[string]string{
			"public-note": strings.Repeat("é", 4096), "post.logout.redirect.uris": "https://logout.example/" + strings.Repeat("a", 2048-len("https://logout.example/"))}})
		got := f.client("managed", clientID)
		fixtureEqual(t, "255-character OIDC redirect", got["redirectUris"], []any{uri})
		fixtureEqual(t, "4096-character NCLOB attribute", got["attributes"].(map[string]any)["public-note"], strings.Repeat("é", 4096))
		fixtureEqual(t, "2048-character NCLOB logout redirect", got["attributes"].(map[string]any)["post.logout.redirect.uris"], "https://logout.example/"+strings.Repeat("a", 2048-len("https://logout.example/")))
	})
	f.run("SAML ACS uses the same redirect column", func(t *testing.T) {
		create("/admin/realms/managed/clients", map[string]any{"clientId": "urn:native-budget:saml", "protocol": "saml", "enabled": true, "redirectUris": []string{uri}, "attributes": map[string]string{"saml_assertion_consumer_url_post": uri}})
		fixtureEqual(t, "255-character SAML ACS", f.client("managed", "urn:native-budget:saml")["redirectUris"], []any{uri})
	})
	f.run("realm role description and native role attribute", func(t *testing.T) {
		create("/admin/realms/managed/roles", map[string]any{"name": "native-budget-role", "description": text, "attributes": map[string][]string{"public-note": {text}}})
		var role map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/roles/native-budget-role", nil, &role)
		fixtureEqual(t, "255-character role description", role["description"], text)
		fixtureEqual(t, "255-character role attribute", role["attributes"].(map[string]any)["public-note"], []any{text})
	})
	app := f.client("managed", clientID)
	clientPath := "/admin/realms/managed/clients/" + app["id"].(string)
	f.run("client role description", func(t *testing.T) {
		create(clientPath+"/roles", map[string]any{"name": "native-budget-client-role", "description": text})
		var role map[string]any
		f.admin(http.MethodGet, clientPath+"/roles/native-budget-client-role", nil, &role)
		fixtureEqual(t, "255-character client role description", role["description"], text)
	})
	f.run("protocol mapper retains its larger CLOB budget", func(t *testing.T) {
		value := strings.Repeat("é", 16384)
		create(clientPath+"/protocol-mappers/models", map[string]any{"name": "native-budget-claim", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": map[string]string{"claim.name": "public-budget", "claim.value": value, "jsonType.label": "String", "access.token.claim": "true"}})
		var mappers []map[string]any
		f.admin(http.MethodGet, clientPath+"/protocol-mappers/models", nil, &mappers)
		found := false
		for _, mapper := range mappers {
			if mapper["name"] == "native-budget-claim" {
				fixtureEqual(t, "16384-character mapper CLOB", mapper["config"].(map[string]any)["claim.value"], value)
				found = true
			}
		}
		if !found {
			t.Fatal("native mapper missing")
		}
	})
	create("/admin/realms/managed/clients", map[string]any{"clientId": "native-budget-resource-server", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": true})
	server := f.client("managed", "native-budget-resource-server")
	authz := fmt.Sprintf("/admin/realms/managed/clients/%s/authz/resource-server", server["id"])
	f.run("scope display name", func(t *testing.T) {
		create(authz+"/scope", map[string]any{"name": "native-budget-read", "displayName": text})
		var scopes []map[string]any
		f.admin(http.MethodGet, authz+"/scope", nil, &scopes)
		found := false
		for _, scope := range scopes {
			if scope["name"] == "native-budget-read" {
				fixtureEqual(t, "255-character scope description", scope["displayName"], text)
				found = true
			}
		}
		if !found {
			t.Fatal("native scope missing")
		}
	})
	f.run("resource URI", func(t *testing.T) {
		path := "/" + strings.Repeat("a", 254)
		create(authz+"/resource", map[string]any{"name": "native-budget-resource", "uris": []string{path}})
		var resources []map[string]any
		f.admin(http.MethodGet, authz+"/resource?name=native-budget-resource&exactName=true&deep=true", nil, &resources)
		if len(resources) != 1 {
			t.Fatal("native resource missing or ambiguous")
		}
		fixtureEqual(t, "255-character resource URI", resources[0]["uris"], []any{path})
	})
}
