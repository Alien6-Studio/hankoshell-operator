//go:build keycloak_integration

package controller_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	exchangeGrant       = "urn:ietf:params:oauth:grant-type:token-exchange"
	exchangeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// These tests characterize provider behavior, including successful requests that
// are unsafe as delegation. A passing test does not qualify delegated authority.
func TestRealKeycloakStandardTokenExchange(t *testing.T) {
	f := newKeycloakFixture(t)
	e := newExchangeExperiment(f)
	f.run("configuration uses scoped client administration", func(t *testing.T) {
		e.characterizePermissions()
	})
	subject := e.credentials(e.subject, e.actor.name)
	actor := e.credentials(e.actor, e.api.name)

	f.run("authenticated exchange preserves subject and filters audience", func(t *testing.T) {
		result := e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}})
		claims := e.success(result, e.api.name)
		fixtureEqual(t, "subject retained", claims["sub"] == subject.claims["sub"], true)
		fixtureEqual(t, "requesting client", claims["azp"], e.actor.name)
		exchangeAudience(f, claims, e.api.name)
		exchangeNoActor(f, claims)
		fixtureEqual(t, "issued token type", result.issuedType, exchangeAccessToken)
		fixtureEqual(t, "no refresh token", result.refresh == "", true)
	})

	f.run("optional scope can exceed subject and actor tokens", func(t *testing.T) {
		fixtureEqual(t, "subject lacks write", exchangeHasScope(subject.claims, "fixture-write"), false)
		fixtureEqual(t, "actor lacks write", exchangeHasScope(actor.claims, "fixture-write"), false)
		result := e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}, "scope": {"fixture-write"}})
		claims := e.success(result, e.api.name)
		fixtureEqual(t, "provider allows additional optional scope", exchangeHasScope(claims, "fixture-write"), true)
	})

	f.run("composite roles can exceed subject token and actor authority", func(t *testing.T) {
		e.characterizeRoleExpansion()
	})

	f.run("resource parameter does not constrain output", func(t *testing.T) {
		claims := e.success(e.exchange(e.actor, subject.token, url.Values{
			"audience": {e.api.name}, "resource": {"https://unconfigured.example.test/private"},
		}), e.api.name)
		exchangeAudience(f, claims, e.api.name)
	})

	f.run("actor token is ignored when delegation feature is disabled", func(t *testing.T) {
		for _, token := range []string{actor.token, "invalid-actor-token"} {
			claims := e.success(e.exchange(e.actor, subject.token, url.Values{
				"audience": {e.api.name}, "actor_token": {token}, "actor_token_type": {exchangeAccessToken},
			}), e.api.name)
			exchangeNoActor(f, claims)
		}
	})

	f.run("subject replay is accepted", func(t *testing.T) {
		for range 2 {
			e.success(e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}}), e.api.name)
		}
	})

	f.run("repeated exchange has no declared depth bound", func(t *testing.T) {
		token := subject.token
		for range 5 {
			result := e.exchange(e.actor, token, url.Values{"audience": {e.api.name}})
			claims := e.success(result, e.api.name)
			exchangeNoActor(f, claims)
			token = result.token
		}
	})

	f.run("invalid and unauthorized requests are rejected", func(t *testing.T) {
		other := e.client("other", false, e.api.name)
		disabled := e.client("exchange-disabled", false, e.api.name)
		public := e.client("public", true, e.api.name)
		f.admin(http.MethodPut, public.path(), map[string]any{"publicClient": true, "serviceAccountsEnabled": false}, nil)
		for _, tc := range []struct {
			name   string
			client exchangeClient
			extra  url.Values
			status int
			code   string
		}{
			{"unknown audience", e.actor, url.Values{"audience": {"missing-api"}}, 400, "invalid_client"},
			{"unavailable audience", e.actor, url.Values{"audience": {other.name}}, 400, "invalid_request"},
			{"unavailable scope", e.actor, url.Values{"scope": {"unconfigured-scope"}}, 400, "invalid_scope"},
			{"exchange disabled", disabled, nil, 400, "invalid_request"},
			{"public requester", exchangeClient{name: public.name}, nil, 400, "invalid_client"},
			{"malformed subject", e.actor, url.Values{"subject_token": {"invalid-subject-token"}}, 400, "invalid_request"},
			{"foreign realm subject", e.actor, url.Values{"subject_token": {f.token(f.adminForm)}}, 400, "invalid_request"},
			{"unsupported subject type", e.actor, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}}, 400, "invalid_request"},
			{"human impersonation", e.actor, url.Values{"requested_subject": {"fixture-human"}}, 400, "invalid_request"},
			{"external issuer", e.actor, url.Values{"requested_issuer": {"other-realm"}}, 400, "invalid_request"},
			{"refresh from transient session", e.actor, url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}}, 400, "invalid_request"},
		} {
			f.run(tc.name, func(t *testing.T) {
				e.denied(e.exchange(tc.client, subject.token, tc.extra), tc.status, tc.code)
			})
		}
		outside := e.client("outside-audience", true, e.api.name)
		e.denied(e.exchange(outside, subject.token, nil), 403, "access_denied")
		f.admin(http.MethodPut, e.api.path(), map[string]any{"enabled": false}, nil)
		e.denied(e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}}), 400, "invalid_client")
		f.admin(http.MethodPut, e.api.path(), map[string]any{"enabled": true}, nil)
	})

	f.run("subject expiry does not bound exchanged token expiry", func(t *testing.T) {
		short := e.client("short-subject", false, e.actor.name)
		// Leave room for bounded HTTPS requests on a contended CI runner.
		f.admin(http.MethodPut, short.path(), map[string]any{"attributes": map[string]string{"access.token.lifespan": "20"}}, nil)
		input := e.credentials(short, e.actor.name)
		result := e.exchange(e.actor, input.token, url.Values{"audience": {e.api.name}})
		claims := e.success(result, e.api.name)
		expires, err := input.claims.GetExpirationTime()
		f.requireNoError(err)
		outputExpires, err := claims.GetExpirationTime()
		f.requireNoError(err)
		if !outputExpires.After(expires.Time) {
			t.Fatal("expected native exchange lifespan to exceed short subject lifespan")
		}
		time.Sleep(time.Until(expires.Add(time.Second)))
		e.denied(e.exchange(e.actor, input.token, nil), 400, "invalid_request")
		e.success(result, e.api.name) // Offline signature/expiry validation still succeeds.
	})

	f.run("disabling exchange stops issuance but leaves signed token valid", func(t *testing.T) {
		result := e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}})
		e.success(result, e.api.name)
		f.admin(http.MethodPut, e.actor.path(), map[string]any{"attributes": map[string]string{"standard.token.exchange.enabled": "false"}}, nil)
		e.denied(e.exchange(e.actor, subject.token, nil), 400, "invalid_request")
		e.success(result, e.api.name)
	})
}

type exchangeClient struct{ name, id, secret string }

func (c exchangeClient) path() string { return "/admin/realms/managed/clients/" + c.id }

type exchangeResult struct {
	status                           int
	token, refresh, issuedType, code string
	claims                           jwt.MapClaims
}

type exchangeExperiment struct {
	f                   *keycloakFixture
	issuer              string
	subject, actor, api exchangeClient
}

func newExchangeExperiment(f *keycloakFixture) *exchangeExperiment {
	e := &exchangeExperiment{f: f, issuer: f.baseURL + "/realms/managed"}
	e.api = e.client("resource-api", false)
	e.actor = e.client("actor", true, e.api.name)
	e.subject = e.client("subject", false, e.actor.name)
	e.optionalScope(e.actor, "fixture-write")
	return e
}

func (e *exchangeExperiment) client(name string, enabled bool, audiences ...string) exchangeClient {
	f := e.f
	c := exchangeClient{name: "exchange-" + name, secret: fixtureSecret(f.t)}
	f.secrets = append(f.secrets, c.secret)
	var mappers []map[string]any
	for _, audience := range audiences {
		mappers = append(mappers, map[string]any{"name": "audience-" + audience, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{"included.client.audience": audience, "access.token.claim": "true", "id.token.claim": "false"}})
	}
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{
		"clientId": c.name, "protocol": "openid-connect", "enabled": true, "publicClient": false,
		"secret": c.secret, "serviceAccountsEnabled": true, "standardFlowEnabled": false,
		"directAccessGrantsEnabled": false, "fullScopeAllowed": false, "defaultClientScopes": []string{"basic", "roles"},
		"optionalClientScopes": []string{}, "protocolMappers": mappers,
		"attributes": map[string]string{"standard.token.exchange.enabled": map[bool]string{true: "true", false: "false"}[enabled], "access.token.lifespan": "120"},
	}, nil)
	c.id = f.client("managed", c.name)["id"].(string)
	return c
}

func (e *exchangeExperiment) optionalScope(c exchangeClient, name string) {
	f := e.f
	f.admin(http.MethodPost, "/admin/realms/managed/client-scopes", map[string]any{
		"name": name, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"},
	}, nil)
	var scopes []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/client-scopes", nil, &scopes)
	for _, scope := range scopes {
		if scope["name"] == name {
			f.admin(http.MethodPut, c.path()+"/optional-client-scopes/"+scope["id"].(string), nil, nil)
			return
		}
	}
	f.t.Fatal("fixture client scope missing")
}

func (e *exchangeExperiment) request(c exchangeClient, form url.Values) exchangeResult {
	f := e.f
	form.Set("client_id", c.name)
	if c.secret != "" {
		form.Set("client_secret", c.secret)
	}
	status, _, data := protocolHTTP(f, f.http, http.MethodPost, e.issuer+"/protocol/openid-connect/token", form)
	var body struct {
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		IssuedTokenType string `json:"issued_token_type"`
		Error           string `json:"error"`
	}
	// Never include the response body in errors or qualification evidence.
	if json.Unmarshal(data, &body) != nil {
		f.t.Fatal("invalid token endpoint JSON (body withheld)")
	}
	f.secrets = append(f.secrets, body.AccessToken, body.RefreshToken)
	return exchangeResult{status: status, token: body.AccessToken, refresh: body.RefreshToken, issuedType: body.IssuedTokenType, code: body.Error}
}

func (e *exchangeExperiment) credentials(c exchangeClient, audience string) exchangeResult {
	result := e.request(c, url.Values{"grant_type": {"client_credentials"}})
	result.claims = e.success(result, audience)
	return result
}

func (e *exchangeExperiment) exchange(c exchangeClient, subject string, extra url.Values) exchangeResult {
	form := url.Values{"grant_type": {exchangeGrant}, "subject_token": {subject}, "subject_token_type": {exchangeAccessToken}, "requested_token_type": {exchangeAccessToken}}
	for key, values := range extra {
		form[key] = values
	}
	return e.request(c, form)
}

func (e *exchangeExperiment) success(result exchangeResult, audience string) jwt.MapClaims {
	e.f.t.Helper()
	fixtureEqual(e.f.t, "token endpoint status", result.status, http.StatusOK)
	if result.token == "" || result.code != "" {
		e.f.t.Fatal("token endpoint returned no usable access token (body withheld)")
	}
	claims := fixtureVerifyJWT(e.f, result.token, e.issuer, audience)
	if subject, ok := claims["sub"].(string); !ok || subject == "" {
		e.f.t.Fatal("verified token has no subject")
	}
	return claims
}

func (e *exchangeExperiment) denied(result exchangeResult, status int, code string) {
	e.f.t.Helper()
	fixtureEqual(e.f.t, "denied token endpoint status", result.status, status)
	fixtureEqual(e.f.t, "OAuth error code", result.code, code)
	fixtureEqual(e.f.t, "denial issued no credentials", result.token == "" && result.refresh == "", true)
}

func exchangeAudience(f *keycloakFixture, claims jwt.MapClaims, want ...string) {
	f.t.Helper()
	audiences, err := claims.GetAudience()
	f.requireNoError(err)
	slices.Sort(audiences)
	slices.Sort(want)
	fixtureEqual(f.t, "exact audience", []string(audiences), want)
}

func exchangeNoActor(f *keycloakFixture, claims jwt.MapClaims) {
	f.t.Helper()
	fixtureEqual(f.t, "no actor claim", claims["act"] == nil && claims["may_act"] == nil, true)
}

func exchangeHasScope(claims jwt.MapClaims, scope string) bool {
	value, _ := claims["scope"].(string)
	return slices.Contains(strings.Fields(value), scope)
}

func (e *exchangeExperiment) characterizeRoleExpansion() {
	f := e.f
	requester := e.client("role-actor", true, e.api.name)
	origin := e.client("role-subject", false, requester.name)
	roles := map[string]map[string]any{}
	for _, name := range []string{"read", "write", "bundle"} {
		f.admin(http.MethodPost, e.api.path()+"/roles", map[string]any{"name": name}, nil)
		var role map[string]any
		f.admin(http.MethodGet, e.api.path()+"/roles/"+name, nil, &role)
		roles[name] = role
	}
	f.admin(http.MethodPost, e.api.path()+"/roles/bundle/composites", []any{roles["read"], roles["write"]}, nil)
	var user map[string]any
	f.admin(http.MethodGet, origin.path()+"/service-account-user", nil, &user)
	f.admin(http.MethodPost, "/admin/realms/managed/users/"+user["id"].(string)+"/role-mappings/clients/"+e.api.id, []any{roles["bundle"]}, nil)
	f.admin(http.MethodPost, origin.path()+"/scope-mappings/clients/"+e.api.id, []any{roles["read"]}, nil)
	f.admin(http.MethodPost, requester.path()+"/scope-mappings/clients/"+e.api.id, []any{roles["bundle"]}, nil)
	subject := e.credentials(origin, requester.name)
	actor := e.credentials(requester, e.api.name)
	fixtureEqual(f.t, "subject has read", exchangeHasRole(subject.claims, e.api.name, "read"), true)
	fixtureEqual(f.t, "subject lacks write", exchangeHasRole(subject.claims, e.api.name, "write"), false)
	fixtureEqual(f.t, "actor lacks read", exchangeHasRole(actor.claims, e.api.name, "read"), false)
	fixtureEqual(f.t, "actor lacks write", exchangeHasRole(actor.claims, e.api.name, "write"), false)
	result := e.exchange(requester, subject.token, url.Values{"audience": {e.api.name}, "actor_token": {actor.token}, "actor_token_type": {exchangeAccessToken}})
	claims := e.success(result, e.api.name)
	fixtureEqual(f.t, "exchange expands composite read", exchangeHasRole(claims, e.api.name, "read"), true)
	fixtureEqual(f.t, "exchange expands composite write", exchangeHasRole(claims, e.api.name, "write"), true)
}

func exchangeHasRole(claims jwt.MapClaims, audience, role string) bool {
	access, _ := claims["resource_access"].(map[string]any)
	resource, _ := access[audience].(map[string]any)
	roles, _ := resource["roles"].([]any)
	return slices.Contains(roles, any(role))
}

func (e *exchangeExperiment) characterizePermissions() {
	f := e.f
	_, writer := f.serviceClient("exchange-config-writer")
	f.grantClientRoles("exchange-config-writer", "managed", []string{"manage-clients"})
	_, reader := f.serviceClient("exchange-config-reader")
	f.grantClientRoles("exchange-config-reader", "managed", []string{"view-clients"})
	_, denied := f.serviceClient("exchange-config-denied")
	for _, identity := range []struct {
		name, secret string
		writeStatus  int
	}{
		{"exchange-config-writer", writer, http.StatusNoContent},
		{"exchange-config-reader", reader, http.StatusForbidden},
		{"exchange-config-denied", denied, http.StatusForbidden},
	} {
		fixtureEqual(f.t, "configure standard exchange", f.identityStatus(identity.name, identity.secret, http.MethodPut, e.actor.path(),
			map[string]any{"attributes": map[string]string{"standard.token.exchange.enabled": "true", "access.token.lifespan": "120"}}), identity.writeStatus)
	}
	mapperPath := e.actor.path() + "/protocol-mappers/models"
	mapper := map[string]any{"name": "permission-probe", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{"included.client.audience": e.api.name, "access.token.claim": "true"}}
	fixtureEqual(f.t, "writer creates mapper", f.identityStatus("exchange-config-writer", writer, http.MethodPost, mapperPath, mapper), http.StatusCreated)
	var mappers []map[string]any
	f.admin(http.MethodGet, mapperPath, nil, &mappers)
	deletedMappers := 0
	for _, item := range mappers {
		if item["name"] == "permission-probe" {
			path := mapperPath + "/" + item["id"].(string)
			fixtureEqual(f.t, "reader cannot delete mapper", f.identityStatus("exchange-config-reader", reader, http.MethodDelete, path, nil), http.StatusForbidden)
			fixtureEqual(f.t, "writer deletes mapper", f.identityStatus("exchange-config-writer", writer, http.MethodDelete, path, nil), http.StatusNoContent)
			deletedMappers++
		}
	}
	fixtureEqual(f.t, "mapper permission checks exercised", deletedMappers, 1)
	scopePath := "/admin/realms/managed/client-scopes"
	fixtureEqual(f.t, "writer creates client scope", f.identityStatus("exchange-config-writer", writer, http.MethodPost, scopePath,
		map[string]any{"name": "permission-probe", "protocol": "openid-connect"}), http.StatusCreated)
	var scopes []map[string]any
	f.admin(http.MethodGet, scopePath, nil, &scopes)
	deletedScopes := 0
	for _, scope := range scopes {
		if scope["name"] == "permission-probe" {
			id := scope["id"].(string)
			fixtureEqual(f.t, "writer assigns optional scope", f.identityStatus("exchange-config-writer", writer, http.MethodPut, e.actor.path()+"/optional-client-scopes/"+id, nil), http.StatusNoContent)
			fixtureEqual(f.t, "writer removes optional scope", f.identityStatus("exchange-config-writer", writer, http.MethodDelete, e.actor.path()+"/optional-client-scopes/"+id, nil), http.StatusNoContent)
			fixtureEqual(f.t, "writer deletes client scope", f.identityStatus("exchange-config-writer", writer, http.MethodDelete, scopePath+"/"+id, nil), http.StatusNoContent)
			deletedScopes++
		}
	}
	fixtureEqual(f.t, "scope permission checks exercised", deletedScopes, 1)
	for _, path := range []string{"/admin/realms/managed", "/admin/realms/master"} {
		fixtureEqual(f.t, "writer cannot alter realm security", f.identityStatus("exchange-config-writer", writer, http.MethodPut, path, map[string]any{"displayName": "forbidden"}), http.StatusForbidden)
	}
	fixtureEqual(f.t, "writer cannot manage people", f.identityStatus("exchange-config-writer", writer, http.MethodPost, "/admin/realms/managed/users", map[string]any{"username": "forbidden"}), http.StatusForbidden)
	var user map[string]any
	f.admin(http.MethodGet, e.subject.path()+"/service-account-user", nil, &user)
	fixtureEqual(f.t, "writer cannot impersonate", f.identityStatus("exchange-config-writer", writer, http.MethodPost, "/admin/realms/managed/users/"+user["id"].(string)+"/impersonation", nil), http.StatusForbidden)
}
