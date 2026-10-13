//go:build keycloak_integration

package controller_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Preview is deliberately opt-in in a separate disposable server. Neither the
// managed fixture nor the operator enables these experimental server features.
func TestRealKeycloakDelegationPreview(t *testing.T) {
	if os.Getenv("KEYCLOAK_VERSION") == "26.7.5" {
		t.Skip("Keycloak 26.7.5 has no token-exchange-delegation provider; standard behavior is tested separately")
	}
	f := newKeycloakFixtureWithTransportAndDiscovery(t, false, false, false, "token-exchange-delegation", "parameterized-scopes")
	e := newExchangeExperiment(f)
	username, password := fixtureProtocolUser(f)
	human := e.client("human", false, e.actor.name)
	f.admin(http.MethodPut, human.path(), map[string]any{
		"serviceAccountsEnabled": false, "standardFlowEnabled": true, "consentRequired": true,
		"redirectUris": []string{"https://delegation.example.test/callback"},
	}, nil)
	var scopes []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/client-scopes", nil, &scopes)
	found := false
	for _, scope := range scopes {
		if scope["name"] == "delegation:client" {
			f.admin(http.MethodPut, human.path()+"/optional-client-scopes/"+scope["id"].(string), nil, nil)
			found = true
		}
	}
	if !found {
		t.Fatal("preview native delegation scope missing")
	}
	f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"adminPermissionsEnabled": true}, nil)
	permissionsClient := f.client("managed", "admin-permissions")
	permissionsPath := "/admin/realms/managed/clients/" + permissionsClient["id"].(string) + "/authz/resource-server"
	f.admin(http.MethodPost, permissionsPath+"/policy/client", map[string]any{
		"name": "fixture-delegate-actor", "logic": "POSITIVE", "clients": []string{e.actor.id},
	}, nil)
	f.admin(http.MethodPost, permissionsPath+"/permission/scope", map[string]any{
		"name": "fixture-delegation", "resourceType": "Users", "scopes": []string{"delegate"}, "policies": []string{"fixture-delegate-actor"},
	}, nil)
	scope := "openid delegation:client:" + e.actor.name
	subject := e.login(human, username, password, scope, true)
	actor := e.credentials(e.actor, e.api.name)
	mayAct, ok := subject.claims["may_act"].(map[string]any)
	if !ok || mayAct["sub"] != actor.claims["sub"] || mayAct["client_id"] != e.actor.name {
		t.Fatal("native consent did not bind subject to the expected actor (claims withheld)")
	}
	params := func() url.Values {
		return url.Values{"actor_token": {actor.token}, "actor_token_type": {exchangeAccessToken}, "audience": {e.api.name}}
	}

	f.run("native consent and FGAP permit bound actor", func(t *testing.T) {
		result := e.exchange(e.actor, subject.token, params())
		claims := e.success(result, e.api.name)
		exchangeAudience(f, claims, e.api.name)
		fixtureEqual(t, "subject retained", claims["sub"] == subject.claims["sub"], true)
		fixtureEqual(t, "requesting client", claims["azp"], e.actor.name)
		act, ok := claims["act"].(map[string]any)
		if !ok || act["sub"] != actor.claims["sub"] || act["client_id"] != e.actor.name || claims["may_act"] != nil {
			t.Fatal("delegated actor claims differ (claims withheld)")
		}
		fixtureEqual(t, "no refresh token", result.refresh == "", true)
	})

	f.run("preview still permits optional scope expansion and replay", func(t *testing.T) {
		fixtureEqual(t, "subject lacks write", exchangeHasScope(subject.claims, "fixture-write"), false)
		fixtureEqual(t, "actor lacks write", exchangeHasScope(actor.claims, "fixture-write"), false)
		for range 2 {
			form := params()
			form.Set("scope", "fixture-write")
			claims := e.success(e.exchange(e.actor, subject.token, form), e.api.name)
			fixtureEqual(t, "delegation expands scope", exchangeHasScope(claims, "fixture-write"), true)
		}
	})

	f.run("invalid actor and missing delegation consent are rejected", func(t *testing.T) {
		for _, tc := range []struct{ name, key, value string }{
			{"malformed actor", "actor_token", "invalid-actor-token"},
			{"foreign realm actor", "actor_token", f.token(f.adminForm)},
			{"wrong actor type", "actor_token_type", "urn:ietf:params:oauth:token-type:id_token"},
			{"refresh token", "requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"},
			{"same actor and subject", "actor_token", subject.token},
		} {
			f.run(tc.name, func(t *testing.T) {
				form := params()
				form.Set(tc.key, tc.value)
				e.denied(e.exchange(e.actor, subject.token, form), 400, "invalid_request")
			})
		}
		// Removing actor_token cannot downgrade a delegation subject to standard exchange.
		e.denied(e.exchange(e.actor, subject.token, nil), 400, "invalid_request")
		plain := e.credentials(e.subject, e.actor.name)
		e.denied(e.exchange(e.actor, plain.token, params()), 400, "invalid_request")
		other := e.client("wrong-actor", true, e.api.name)
		otherToken := e.credentials(other, e.api.name)
		form := params()
		form.Set("actor_token", otherToken.token)
		e.denied(e.exchange(other, subject.token, form), 400, "invalid_request")
	})

	f.run("expired actor is rejected but issued token outlives actor", func(t *testing.T) {
		f.admin(http.MethodPut, e.actor.path(), map[string]any{"attributes": map[string]string{
			"standard.token.exchange.enabled": "true", "access.token.lifespan": "20",
		}}, nil)
		short := e.credentials(e.actor, e.api.name)
		f.admin(http.MethodPut, e.actor.path(), map[string]any{"attributes": map[string]string{
			"standard.token.exchange.enabled": "true", "access.token.lifespan": "120",
		}}, nil)
		form := params()
		form.Set("actor_token", short.token)
		result := e.exchange(e.actor, subject.token, form)
		claims := e.success(result, e.api.name)
		expires, err := short.claims.GetExpirationTime()
		f.requireNoError(err)
		outputExpires, err := claims.GetExpirationTime()
		f.requireNoError(err)
		if !outputExpires.After(expires.Time) {
			t.Fatal("expected exchange to outlive actor after client lifespan change")
		}
		time.Sleep(time.Until(expires.Add(time.Second)))
		e.denied(e.exchange(e.actor, subject.token, form), 400, "invalid_request")
		e.success(result, e.api.name)
	})

	f.run("withdrawing FGAP permission stops new consent but not existing grant", func(t *testing.T) {
		var permission map[string]any
		f.admin(http.MethodGet, permissionsPath+"/permission/scope/search?name=fixture-delegation", nil, &permission)
		f.admin(http.MethodDelete, permissionsPath+"/permission/scope/"+permission["id"].(string), nil, nil)
		fresh := e.login(human, username, password, scope, false)
		fixtureEqual(t, "withdrawn permission removes may_act", fresh.claims["may_act"] == nil, true)
		e.denied(e.exchange(e.actor, fresh.token, params()), 400, "invalid_request")
		e.success(e.exchange(e.actor, subject.token, params()), e.api.name)
	})

	f.run("client administration can mint delegation claims without FGAP or consent", func(t *testing.T) {
		_, writer := f.serviceClient("preview-claim-writer")
		f.grantClientRoles("preview-claim-writer", "managed", []string{"manage-clients"})
		// Permission above has been withdrawn. These are real signed tokens
		// issued via an administrative mapper, not proof of native consent.
		current := actor
		for depth := 1; depth <= 6; depth++ {
			client := e.client("chain-"+strings.Repeat("x", depth), false, e.actor.name)
			mayActJSON, err := json.Marshal(map[string]any{"sub": current.claims["sub"], "client_id": e.actor.name})
			f.requireNoError(err)
			fixtureEqual(t, "manage-clients can mint may_act", f.identityStatus("preview-claim-writer", writer, http.MethodPost, client.path()+"/protocol-mappers/models", map[string]any{
				"name": "fixture-may-act", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
				"config": map[string]string{"claim.name": "may_act", "claim.value": string(mayActJSON), "jsonType.label": "JSON", "access.token.claim": "true"},
			}), http.StatusCreated)
			next := e.credentials(client, e.actor.name)
			form := params()
			form.Set("actor_token", current.token)
			current = e.exchange(e.actor, next.token, form)
			current.claims = e.success(current, e.api.name)
			fixtureEqual(t, "native chain grows beyond depth one", exchangeActorDepth(current.claims), depth)
		}
	})
}

func exchangeActorDepth(claims jwt.MapClaims) int {
	depth := 0
	value := claims["act"]
	for value != nil {
		actor, ok := value.(map[string]any)
		if !ok {
			return -1
		}
		depth++
		value = actor["act"]
	}
	return depth
}

// login completes real authorization-code + PKCE and an explicit native consent
// form. Credentials and authorization codes never leave the verified TLS origin;
// the registered callback is inspected without issuing an HTTP request to it.
func (e *exchangeExperiment) login(c exchangeClient, username, password, scope string, requireConsent bool) exchangeResult {
	f := e.f
	callback := "https://delegation.example.test/callback"
	verifier, state := fixtureSecret(f.t), fixtureSecret(f.t)
	f.secrets = append(f.secrets, verifier)
	challenge := sha256.Sum256([]byte(verifier))
	form := url.Values{"client_id": {c.name}, "response_type": {"code"}, "scope": {scope}, "redirect_uri": {callback},
		"state": {state}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "prompt": {"consent"}}
	method, endpoint := http.MethodGet, e.issuer+"/protocol/openid-connect/auth?"+form.Encode()
	form = nil
	browser := protocolBrowser(f)
	consented := false
	for range 10 {
		status, headers, data := protocolHTTP(f, browser, method, endpoint, form)
		if status == http.StatusFound || status == http.StatusSeeOther {
			location, err := url.Parse(headers.Get("Location"))
			f.requireNoError(err)
			base, _ := url.Parse(endpoint)
			location = base.ResolveReference(location)
			query := location.Query()
			if location.Scheme+"://"+location.Host+location.Path == callback {
				if query.Get("state") != state || query.Get("code") == "" || (requireConsent && !consented) {
					f.t.Fatal("delegation login did not complete code/state/consent (response withheld)")
				}
				f.secrets = append(f.secrets, query.Get("code"))
				result := e.request(c, url.Values{"grant_type": {"authorization_code"}, "code": {query.Get("code")}, "redirect_uri": {callback}, "code_verifier": {verifier}})
				result.claims = e.success(result, e.actor.name)
				return result
			}
			if location.Scheme != base.Scheme || location.Host != base.Host {
				f.t.Fatal("foreign delegation login redirect")
			}
			method, endpoint, form = http.MethodGet, location.String(), nil
			continue
		}
		fixtureEqual(f.t, "delegation login form HTTP", status, http.StatusOK)
		action, values, login := protocolHTMLForm(data, "username")
		path := "/realms/managed/login-actions/authenticate"
		if login {
			values.Set("username", username)
			values.Set("password", password)
		} else {
			var consent bool
			// Both Keycloak themes carry a hidden code; v2 renders accept as
			// a button rather than an input, so select the form by that code.
			action, values, consent = protocolHTMLForm(data, "code")
			if !consent {
				f.t.Fatal("expected native delegation consent form (body withheld)")
			}
			values.Del("cancel")
			values.Set("accept", "Yes")
			path = "/realms/managed/login-actions/consent"
			consented = true
		}
		base, _ := url.Parse(endpoint)
		target, err := url.Parse(action)
		f.requireNoError(err)
		target = base.ResolveReference(target)
		if target.Scheme != base.Scheme || target.Host != base.Host || !strings.HasPrefix(target.Path, path) {
			f.t.Fatal("untrusted delegation form target")
		}
		method, endpoint, form = http.MethodPost, target.String(), values
	}
	f.t.Fatal("delegation login exceeded bounded redirects")
	return exchangeResult{claims: jwt.MapClaims{}}
}
