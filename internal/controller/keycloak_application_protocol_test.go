//go:build keycloak_integration

package controller_test

import (
	"net/http"
	"testing"
)

// The native fixture establishes the actual representation before testing the
// portable adapter. Setup is bootstrap-only; product operations use the scoped
// service account in the application qualification below.
func TestRealKeycloakNativeSAMLRepresentation(t *testing.T) {
	f := newKeycloakFixture(t)
	entity := "https://sp.example.test/saml"
	acs := "https://sp.example.test/saml/acs"
	attributes := map[string]string{
		"saml.server.signature": "true", "saml.assertion.signature": "true",
		"saml.client.signature": "false", "saml.signature.algorithm": "RSA_SHA256",
		"saml_name_id_format": "persistent", "saml_force_name_id_format": "true",
		"saml.force.post.binding": "true", "saml.authnstatement": "true",
		"saml.encrypt": "false", "saml.artifact.binding": "false",
		"saml_assertion_consumer_url_post": acs,
	}
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{
		"clientId": entity, "protocol": "saml", "enabled": true,
		"redirectUris": []string{acs}, "attributes": attributes,
		"fullScopeAllowed": false, "standardFlowEnabled": true,
		"publicClient": false, "serviceAccountsEnabled": false,
		"directAccessGrantsEnabled": false,
	}, nil)
	got := f.client("managed", entity)
	fixtureEqual(t, "SAML provider protocol", got["protocol"], "saml")
	fixtureEqual(t, "SP entity is clientId", got["clientId"], entity)
	fixtureEqual(t, "exact ACS list", got["redirectUris"], []any{acs})
	for key, value := range attributes {
		fixtureEqual(t, "native attribute "+key, got["attributes"].(map[string]any)[key], value)
	}
	id := got["id"].(string)
	f.admin(http.MethodPut, "/admin/realms/managed/clients/"+id, got, nil)
	fixtureEqual(t, "native SAML PUT idempotence", f.client("managed", entity), got)
	// Keycloak accepts conversion while retaining the UUID and SAML attributes.
	// The operator must refuse this operation: acceptance is not safe migration.
	got["protocol"] = "openid-connect"
	f.admin(http.MethodPut, "/admin/realms/managed/clients/"+id, got, nil)
	converted := f.client("managed", entity)
	fixtureEqual(t, "provider accepts protocol conversion", converted["protocol"], "openid-connect")
	fixtureEqual(t, "conversion retains UUID", converted["id"], id)
	fixtureEqual(t, "conversion retains protocol-specific attributes", converted["attributes"], got["attributes"])
	t.Logf("Keycloak %s: SAML clientId=SP entity, exact ACS/signing/NameID mapping and idempotent PUT; raw conversion retains stale attributes", f.version)
}
