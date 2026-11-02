//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// TestRealKeycloakServiceAccountOAuthScopes qualifies actual token issuance,
// not merely successful Admin REST responses. Realm scope definitions are
// administrator prerequisites; the operator owns only client attachments.
func TestRealKeycloakServiceAccountOAuthScopes(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	const scope = "registry:oci:artifacts:read"
	f.admin(http.MethodPost, "/admin/realms/managed/client-scopes", map[string]any{
		"name": scope, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"},
	}, nil)
	secret, err := f.kc.CreateApp(ctx, "managed", keycloak.CreateAppSpec{ClientID: "artifact-reader", Name: "artifact-reader", Type: "m2m", ServiceAccountOwnerUID: "scope-owner"})
	f.requireNoError(err)
	f.secrets = append(f.secrets, secret)
	_, err = f.kc.EnsureClientProtocolMapper(ctx, "managed", "artifact-reader", keycloak.ProtocolMapper{
		Name: "artifact-audience", Protocol: "openid-connect", ProtocolMapper: "oidc-audience-mapper",
		Config: map[string]string{"included.custom.audience": "artifact-api", "access.token.claim": "true", "id.token.claim": "false"},
	})
	f.requireNoError(err)
	verify := func(context.Context) error { return nil }
	wanted := []string{"basic", "service_account", scope}
	f.requireNoError(f.kc.ReconcileServiceAccountScopes(ctx, "managed", "artifact-reader", "scope-owner", wanted, verify))
	f.requireNoError(f.kc.ReconcileServiceAccountScopes(ctx, "managed", "artifact-reader", "scope-owner", wanted, verify))
	issuer := f.baseURL + "/realms/managed"
	request := func(requested string, status int) []byte {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"artifact-reader"}, "client_secret": {secret}}
		if requested != "" {
			form.Set("scope", requested)
		}
		got, _, body := protocolHTTP(f, f.http, http.MethodPost, issuer+"/protocol/openid-connect/token", form)
		fixtureEqual(t, "client credentials status", got, status)
		return body
	}
	for _, requested := range []string{"", scope} {
		var result struct {
			AccessToken string `json:"access_token"`
		}
		f.requireNoError(json.Unmarshal(request(requested, http.StatusOK), &result))
		claims := fixtureVerifyJWT(f, result.AccessToken, issuer, "artifact-api")
		grants, _ := claims["scope"].(string)
		id, _ := claims["jti"].(string)
		if !slices.Contains(strings.Fields(grants), scope) || id == "" || claims["azp"] != "artifact-reader" {
			t.Fatal("native token is missing the declared scope or attributable machine identity")
		}
	}
	request("registry:oci:other:read", http.StatusBadRequest)
	// Revocation affects new issuance; this does not claim previously issued JWTs
	// become invalid before expiry.
	f.requireNoError(f.kc.ReconcileServiceAccountScopes(ctx, "managed", "artifact-reader", "scope-owner", wanted[:2], verify))
	request(scope, http.StatusBadRequest)
	var result struct {
		AccessToken string `json:"access_token"`
	}
	f.requireNoError(json.Unmarshal(request("", http.StatusOK), &result))
	claims := fixtureVerifyJWT(f, result.AccessToken, issuer, "artifact-api")
	grants, _ := claims["scope"].(string)
	if slices.Contains(strings.Fields(grants), scope) {
		t.Fatal("removed scope survived token issuance")
	}
	// View-only native credentials must not be able to grant a scope.
	reader, _ := f.serviceClient("scope-observer")
	f.grantClientRoles("scope-observer", "managed", []string{"view-clients"})
	if reader.ReconcileServiceAccountScopes(ctx, "managed", "artifact-reader", "scope-owner", wanted, verify) == nil {
		t.Fatal("view-only native identity changed OAuth scope grants")
	}
	f.requireNoError(f.kc.ReconcileServiceAccountScopes(ctx, "managed", "artifact-reader", "scope-owner", []string{}, verify))
	request(scope, http.StatusBadRequest)
	var definitions []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/client-scopes", nil, &definitions)
	if !slices.ContainsFunc(definitions, func(d map[string]any) bool { return d["name"] == scope }) {
		t.Fatal("client grant cleanup deleted the shared realm scope")
	}
}
