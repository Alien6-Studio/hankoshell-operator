//go:build keycloak_integration && keycloak_extension_integration

package controller_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	controller "github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This separate tag never turns the stock-provider characterization into a
// qualified extension test. Its runner must build and supply the matching JAR.
func TestRealKeycloakBoundedDelegationExtension(t *testing.T) {
	jar := os.Getenv("KEYCLOAK_EXTENSION_JAR")
	if jar == "" {
		t.Fatal("KEYCLOAK_EXTENSION_JAR is required; skipping is not qualification")
	}
	f := newKeycloakFixtureConfigured(t, false, false, false, jar)
	e := newExchangeExperiment(f)
	f.run("installation preserves unselected realms and ordinary native exchange", func(t *testing.T) {
		capability, err := f.kc.BoundedDelegationCapability(context.Background(), "managed")
		fixtureEqual(t, "profile not implicitly selected", errors.Is(err, keycloak.ErrBoundedDelegationUnsupported), true)
		fixtureEqual(t, "unselected profile disabled", capability.Enabled, false)
		subject := e.credentials(e.subject, e.actor.name)
		claims := e.success(e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}}), e.api.name)
		exchangeNoActor(f, claims)
	})
	// External realm-administrator prerequisite, separate from the delegation writer.
	f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"attributes": map[string]string{"oauth.bounded-delegation.profile": "software-v1"}}, nil)
	f.run("extension advertises only its nonsecret experimental profile", func(t *testing.T) {
		status, _, data := protocolHTTP(f, f.http, http.MethodGet, e.issuer+"/bounded-delegation", nil)
		if status != http.StatusOK {
			t.Fatalf("extension discovery HTTP %d", status)
		}
		var capability map[string]any
		f.requireNoError(json.Unmarshal(data, &capability))
		fixtureEqual(t, "exact profile", capability["contract"], "bounded-delegation/software-v1")
		fixtureEqual(t, "native version", capability["keycloakVersion"], f.version)
		fixtureEqual(t, "experimental classification", capability["experimental"], true)
		fixtureEqual(t, "enabled feature", capability["enabled"], true)
		fixtureEqual(t, "public metadata only", len(capability), 7)
	})
	setAttributes := func(c exchangeClient, values map[string]string) {
		t.Helper()
		current := f.client("managed", c.name)
		attributes, _ := current["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		for key, value := range values {
			attributes[key] = value
		}
		current["attributes"] = attributes
		f.admin(http.MethodPut, c.path(), current, nil)
	}
	for _, c := range []exchangeClient{e.api, e.actor, e.subject} {
		setAttributes(c, map[string]string{"fixture.owner": "uid-" + c.name, "hanko.sh/application-owner": "uid-" + c.name})
	}
	writer, writerSecret := f.serviceClient("delegation-writer")
	f.grantClientRoles("delegation-writer", "managed", []string{"view-realm", "view-users", "manage-clients"})
	model := keycloak.AuthorizationModel{
		OwnerUID: "extension-test", Name: "extension-test", Realm: "managed", Audience: e.api.name, ApplicationRef: e.api.name,
		Scopes:    []keycloak.AuthorizationScope{{Name: "read"}, {Name: "write"}},
		Resources: []keycloak.AuthorizationResource{{Name: "document", URIs: []string{"https://api.example.test/document"}, Scopes: []string{"read", "write"}}},
		Permissions: []keycloak.AuthorizationPermission{{Name: "base-access", Resources: []string{"document"}, Scopes: []string{"read", "write"},
			Principals: []keycloak.AuthorizationPrincipal{{Kind: "application", Ref: e.actor.name}, {Kind: "application", Ref: e.subject.name}}}},
	}
	state, err := f.kc.ReconcileAuthorization(context.Background(), model, keycloak.AuthorizationManagedObjects{})
	f.requireNoError(err)
	if len(state.ManagedObjects.Resources) != 1 {
		t.Fatal("fixture resource not created")
	}
	resourceID := state.ManagedObjects.Resources[0].ID
	var prepared keycloak.BoundedDelegationPreparation
	f.run("operator preparation proves the declared intersection without writes", func(t *testing.T) {
		principals := []keycloak.BoundedDelegationPrincipal{
			{Kind: "application", Ref: e.actor.name, UID: "uid-" + e.actor.name},
			{Kind: "application", Ref: e.subject.name, UID: "uid-" + e.subject.name},
		}
		permission := keycloak.BoundedDelegationPermission{Name: "delegate-read", Resources: []string{"document"}, Scopes: []string{"read"},
			Actor:      keycloak.BoundedDelegationIdentity{Kind: "application", ClientID: e.actor.name, UID: "uid-" + e.actor.name},
			Subject:    keycloak.BoundedDelegationIdentity{Kind: "application", ClientID: e.subject.name, UID: "uid-" + e.subject.name},
			Principals: principals, MaxDepth: 2, MaxTTLSeconds: 30}
		candidate, err := writer.PrepareBoundedDelegation(context.Background(), model, "uid-"+e.api.name,
			[]keycloak.BoundedDelegationPermission{permission}, map[string][]keycloak.BoundedDelegationPrincipal{"base-access": principals})
		f.requireNoError(err)
		prepared = candidate
		fixtureEqual(t, "nonsecret proof", len(prepared.Runtime), len("sha256:")+64)
		fixtureEqual(t, "not executable before commit", prepared.Document.Phase, "Prepared")
		current := f.client("managed", e.api.name)
		attributes, _ := current["attributes"].(map[string]any)
		fixtureEqual(t, "preparation created no grant", attributes["oauth.bounded-delegation.v1"] == nil, true)
		permission.Scopes = []string{"outside"}
		_, err = writer.PrepareBoundedDelegation(context.Background(), model, "uid-"+e.api.name,
			[]keycloak.BoundedDelegationPermission{permission}, map[string][]keycloak.BoundedDelegationPrincipal{"base-access": principals})
		if err == nil {
			t.Fatal("preparation accepted an undeclared authority scope")
		}
		permission.Scopes = []string{"read"}
		var realm struct {
			AccessTokenLifespan int32 `json:"accessTokenLifespan"`
		}
		f.admin(http.MethodGet, "/admin/realms/managed", nil, &realm)
		permission.MaxTTLSeconds = realm.AccessTokenLifespan + 1
		_, err = writer.PrepareBoundedDelegation(context.Background(), model, "uid-"+e.api.name,
			[]keycloak.BoundedDelegationPermission{permission}, map[string][]keycloak.BoundedDelegationPrincipal{"base-access": principals})
		fixtureEqual(t, "declared TTL cannot exceed actual realm lifespan", errors.Is(err, keycloak.ErrBoundedDelegationUnsupported), true)
		var unchanged struct {
			AccessTokenLifespan int32 `json:"accessTokenLifespan"`
		}
		f.admin(http.MethodGet, "/admin/realms/managed", nil, &unchanged)
		fixtureEqual(t, "native lifespan never raised", unchanged.AccessTokenLifespan, realm.AccessTokenLifespan)
	})
	f.run("journal survives restart without new permission writes or realm administration", func(t *testing.T) {
		revision := "sha256:" + strings.Repeat("a", 64)
		applied, err := writer.ApplyBoundedDelegation(context.Background(), model, prepared, state.ManagedObjects, revision)
		f.requireNoError(err)
		verified, _, err := writer.ObserveBoundedDelegation(context.Background(), model, prepared, applied.ManagedObjects, revision)
		f.requireNoError(err)
		fixtureEqual(t, "native transaction committed", verified, true)
		beforeAPI, beforeActor := f.client("managed", e.api.name), f.client("managed", e.actor.name)
		restarted, err := keycloak.NewWithTLS(f.baseURL, "delegation-writer", writerSecret, f.ca)
		f.requireNoError(err)
		_, err = restarted.ApplyBoundedDelegation(context.Background(), model, prepared, keycloak.AuthorizationManagedObjects{}, revision)
		f.requireNoError(err)
		fixtureEqual(t, "restart preserves aggregate", f.client("managed", e.api.name), beforeAPI)
		fixtureEqual(t, "restart preserves actor", f.client("managed", e.actor.name), beforeActor)
		fixtureEqual(t, "writer cannot update realm", f.identityStatus("delegation-writer", writerSecret, http.MethodPut,
			"/admin/realms/managed", map[string]any{"displayName": "forbidden"}), http.StatusForbidden)
		fixtureEqual(t, "writer cannot create users", f.identityStatus("delegation-writer", writerSecret, http.MethodPost,
			"/admin/realms/managed/users", map[string]any{"username": "forbidden"}), http.StatusForbidden)
	})
	f.run("resource-server controller applies observed delegation and survives restart", func(t *testing.T) {
		qualifyBoundedDelegationController(f, e, writer)
	})
	for _, phase := range []string{"Prepared", "Applied", "Verified", "Committed"} {
		f.run("lost native acknowledgement at "+phase, func(t *testing.T) {
			qualifyBoundedLostAcknowledgement(f, e, model, prepared, writerSecret, phase)
		})
	}
	var document map[string]any
	native := f.client("managed", e.api.name)
	attributes, _ := native["attributes"].(map[string]any)
	f.requireNoError(json.Unmarshal([]byte(attributes["oauth.bounded-delegation.v1"].(string)), &document))
	save := func() {
		t.Helper()
		data, err := json.Marshal(document)
		f.requireNoError(err)
		setAttributes(e.api, map[string]string{"oauth.bounded-delegation.v1": string(data)})
	}
	rpt := func(c exchangeClient, permissions ...string) exchangeResult {
		t.Helper()
		input := e.request(c, url.Values{"grant_type": {"client_credentials"}})
		fixtureEqual(t, "client credentials", input.status, http.StatusOK)
		status, data := organizationRequest(f, input.token, http.MethodPost, "/realms/managed/protocol/openid-connect/token", url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:uma-ticket"}, "audience": {e.api.name}, "permission": permissions,
		})
		var result struct {
			AccessToken string `json:"access_token"`
		}
		f.requireNoError(json.Unmarshal(data, &result))
		f.secrets = append(f.secrets, result.AccessToken)
		out := exchangeResult{status: status, token: result.AccessToken}
		out.claims = e.success(out, e.api.name)
		return out
	}
	subject := rpt(e.subject, "document#read", "document#write")
	exchange := func(subject string, actor exchangeResult) exchangeResult {
		return e.exchange(e.actor, subject, url.Values{"actor_token": {actor.token}, "actor_token_type": {exchangeAccessToken}, "audience": {e.api.name}})
	}
	f.run("provider enforces permission audience actor and expiration bounds", func(t *testing.T) {
		actor := rpt(e.actor, "document#read", "document#write")
		result := exchange(subject.token, actor)
		claims := e.success(result, e.api.name)
		exchangeAudience(f, claims, e.api.name)
		fixtureEqual(t, "subject retained", claims["sub"], subject.claims["sub"])
		fixtureEqual(t, "one actor", exchangeActorDepth(claims), 1)
		fixtureEqual(t, "no refresh token", result.refresh, "")
		permissions, _ := claims["authorization"].(map[string]any)
		entries, _ := permissions["permissions"].([]any)
		fixtureEqual(t, "one declared resource", len(entries), 1)
		entry, _ := entries[0].(map[string]any)
		fixtureEqual(t, "declared resource", entry["rsid"], resourceID)
		fixtureEqual(t, "read only", entry["scopes"], []any{"read"})
		outputExpiry, err := claims.GetExpirationTime()
		f.requireNoError(err)
		actorExpiry, err := actor.claims.GetExpirationTime()
		f.requireNoError(err)
		subjectExpiry, err := subject.claims.GetExpirationTime()
		f.requireNoError(err)
		if outputExpiry.After(actorExpiry.Time) || outputExpiry.After(subjectExpiry.Time) || outputExpiry.After(time.Now().Add(31*time.Second)) {
			t.Fatal("delegated token exceeds lifetime bounds")
		}
		e.denied(exchange(subject.token, actor), http.StatusBadRequest, "invalid_request")
		e.denied(e.exchange(e.actor, subject.token, url.Values{"audience": {e.api.name}}), http.StatusBadRequest, "invalid_request")
	})
	f.run("depth is enforced across genuinely issued chained exchanges", func(t *testing.T) {
		first := exchange(subject.token, rpt(e.actor, "document#read"))
		e.success(first, e.api.name)
		second := exchange(first.token, rpt(e.actor, "document#read"))
		fixtureEqual(t, "two native actor hops", exchangeActorDepth(e.success(second, e.api.name)), 2)
		e.denied(exchange(second.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
	})
	f.run("invalid actor widening scope and undeclared audience are refused", func(t *testing.T) {
		actor := rpt(e.actor, "document#read")
		for _, tc := range []struct{ key, value string }{{"actor_token", "invalid"}, {"scope", "fixture-write"}, {"audience", e.subject.name},
			{"resource", "https://foreign.example.test"}, {"requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"},
			{"actor_token", f.token(f.adminForm)}, {"subject_token", f.token(f.adminForm)}, {"requested_subject", "human"},
			{"audience", "missing-resource-server"}} {
			form := url.Values{"actor_token": {actor.token}, "actor_token_type": {exchangeAccessToken}, "audience": {e.api.name}}
			form.Set(tc.key, tc.value)
			e.denied(e.exchange(e.actor, subject.token, form), http.StatusBadRequest, "invalid_request")
		}
		e.denied(e.exchange(e.subject, subject.token, url.Values{"actor_token": {actor.token}, "actor_token_type": {exchangeAccessToken}, "audience": {e.api.name}}), http.StatusBadRequest, "invalid_request")
	})
	f.run("authority intersection cannot add permissions missing from the subject", func(t *testing.T) {
		narrow := rpt(e.subject, "document#read")
		grants := document["grants"].([]any)
		authority := grants[0].(map[string]any)["authority"].(map[string]any)
		authority["permissions"] = map[string]any{resourceID: []string{"read", "write"}}
		save()
		claims := e.success(exchange(narrow.token, rpt(e.actor, "document#read", "document#write")), e.api.name)
		entries := claims["authorization"].(map[string]any)["permissions"].([]any)
		fixtureEqual(t, "narrow subject remains read only", entries[0].(map[string]any)["scopes"], []any{"read"})
		e.denied(exchange(rpt(e.subject, "document#write").token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		authority["permissions"] = map[string]any{resourceID: []string{"read"}}
		save()
	})
	f.run("concurrent replay has exactly one successful native issuance", func(t *testing.T) {
		qualifyBoundedConcurrentReplay(f, e, subject.token, rpt(e.actor, "document#read").token)
	})
	f.run("live native authorization denies old input after subject policy withdrawal", func(t *testing.T) {
		fixtureEqual(t, "one ordinary client policy", len(state.ManagedObjects.Policies), 1)
		path := e.api.path() + "/authz/resource-server/policy/client/" + state.ManagedObjects.Policies[0].ID
		var policy map[string]any
		f.admin(http.MethodGet, path, nil, &policy)
		previous := policy["clients"]
		if previous == nil {
			t.Fatal("fixture client policy lacks its declared native identities")
		}
		policy["clients"] = []string{e.actor.id}
		f.admin(http.MethodPut, path, policy, nil)
		e.denied(exchange(subject.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		policy["clients"] = previous
		f.admin(http.MethodPut, path, policy, nil)
		e.success(exchange(subject.token, rpt(e.actor, "document#read")), e.api.name)
	})
	f.run("current native role and group membership constrain already issued inputs", func(t *testing.T) {
		qualifyBoundedLiveMemberships(f, e, writer, model, document, save, subject.token, rpt, exchange)
	})
	f.run("short inputs bound output and expired inputs cannot issue again", func(t *testing.T) {
		setAttributes(e.actor, map[string]string{"access.token.lifespan": "20"})
		setAttributes(e.subject, map[string]string{"access.token.lifespan": "20"})
		shortActor, unusedActor := rpt(e.actor, "document#read"), rpt(e.actor, "document#read")
		shortSubject := rpt(e.subject, "document#read")
		setAttributes(e.actor, map[string]string{"access.token.lifespan": "120"})
		setAttributes(e.subject, map[string]string{"access.token.lifespan": "120"})
		claims := e.success(exchange(shortSubject.token, shortActor), e.api.name)
		expiry, err := claims.GetExpirationTime()
		f.requireNoError(err)
		actorExpiry, err := unusedActor.claims.GetExpirationTime()
		f.requireNoError(err)
		subjectExpiry, err := shortSubject.claims.GetExpirationTime()
		f.requireNoError(err)
		if expiry.After(actorExpiry.Time) || expiry.After(subjectExpiry.Time) || expiry.After(time.Now().Add(21*time.Second)) {
			t.Fatal("short input expiration was not retained after raising client lifespan")
		}
		until := actorExpiry.Time
		if subjectExpiry.After(until) {
			until = subjectExpiry.Time
		}
		time.Sleep(time.Until(until.Add(time.Second)))
		e.denied(exchange(subject.token, unusedActor), http.StatusBadRequest, "invalid_request")
		e.denied(exchange(shortSubject.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
	})
	f.run("prepared grant revoked input and replaced owner are refused", func(t *testing.T) {
		first := exchange(subject.token, rpt(e.actor, "document#read"))
		e.success(first, e.api.name)
		document["phase"] = "Prepared"
		save()
		e.denied(exchange(subject.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		e.denied(exchange(first.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		document["phase"] = "Committed"
		save()
		setAttributes(e.subject, map[string]string{"hanko.sh/application-owner": "replacement-uid"})
		e.denied(exchange(subject.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		setAttributes(e.subject, map[string]string{"hanko.sh/application-owner": "uid-" + e.subject.name})
	})
	f.run("cleanup removes only its grants and preserves ordinary authorization", func(t *testing.T) {
		// A second resource server's nonsecret actor entry is foreign to this
		// cleanup and must survive. Only its administrator removes it below.
		actor := f.client("managed", e.actor.name)
		attrs := actor["attributes"].(map[string]any)
		var marker map[string]any
		f.requireNoError(json.Unmarshal([]byte(attrs["oauth.bounded-delegation.actor.v1"].(string)), &marker))
		marker["owners"].(map[string]any)["other-resource-server"] = "other-owner-uid"
		data, err := json.Marshal(marker)
		f.requireNoError(err)
		setAttributes(e.actor, map[string]string{"oauth.bounded-delegation.actor.v1": string(data)})
		_, err = writer.ReconcileAuthorization(context.Background(), model, keycloak.AuthorizationManagedObjects{})
		f.requireNoError(err)
		actor = f.client("managed", e.actor.name)
		f.requireNoError(json.Unmarshal([]byte(actor["attributes"].(map[string]any)["oauth.bounded-delegation.actor.v1"].(string)), &marker))
		fixtureEqual(t, "only foreign shared owner retained", marker["owners"], map[string]any{"other-resource-server": "other-owner-uid"})
		_, err = writer.ApplyBoundedDelegation(context.Background(), model, prepared, keycloak.AuthorizationManagedObjects{}, "sha256:"+strings.Repeat("c", 64))
		f.requireNoError(err)
		actor = f.client("managed", e.actor.name)
		f.requireNoError(json.Unmarshal([]byte(actor["attributes"].(map[string]any)["oauth.bounded-delegation.actor.v1"].(string)), &marker))
		delete(marker["owners"].(map[string]any), "other-resource-server")
		data, err = json.Marshal(marker)
		f.requireNoError(err)
		setAttributes(e.actor, map[string]string{"oauth.bounded-delegation.actor.v1": string(data)})
		_, err = writer.ReconcileAuthorization(context.Background(), model, keycloak.AuthorizationManagedObjects{})
		f.requireNoError(err)
		for _, identity := range []exchangeClient{e.api, e.actor} {
			current := f.client("managed", identity.name)
			attrs := current["attributes"].(map[string]any)
			fixtureEqual(t, "grant attribute removed", attrs["oauth.bounded-delegation.v1"] == nil, true)
			fixtureEqual(t, "actor attribute removed", attrs["oauth.bounded-delegation.actor.v1"] == nil, true)
		}
		current := f.client("managed", e.actor.name)
		fixtureEqual(t, "original exchange setting restored", current["attributes"].(map[string]any)["standard.token.exchange.enabled"], "true")
		e.denied(exchange(subject.token, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
		rpt(e.subject, "document#read")
	})
}

func qualifyBoundedConcurrentReplay(f *keycloakFixture, e *exchangeExperiment, subject, actor string) {
	f.t.Helper()
	type outcome struct {
		status      int
		token, code string
		err         error
	}
	results := make(chan outcome, 8)
	start := make(chan struct{})
	for range 8 {
		go func() {
			<-start
			form := url.Values{"grant_type": {exchangeGrant}, "subject_token": {subject}, "subject_token_type": {exchangeAccessToken},
				"actor_token": {actor}, "actor_token_type": {exchangeAccessToken}, "audience": {e.api.name}, "client_id": {e.actor.name}, "client_secret": {e.actor.secret}}
			request, err := http.NewRequest(http.MethodPost, e.issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
			if err != nil {
				results <- outcome{err: err}
				return
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := f.http.Do(request)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			defer response.Body.Close()
			var body struct {
				AccessToken string `json:"access_token"`
				Error       string `json:"error"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&body)
			results <- outcome{response.StatusCode, body.AccessToken, body.Error, err}
		}()
	}
	close(start)
	successes := 0
	for range 8 {
		result := <-results
		f.requireNoError(result.err)
		f.secrets = append(f.secrets, result.token)
		if result.status == http.StatusOK {
			successes++
			e.success(exchangeResult{status: result.status, token: result.token, code: result.code}, e.api.name)
		} else {
			e.denied(exchangeResult{status: result.status, token: result.token, code: result.code}, http.StatusBadRequest, "invalid_request")
		}
	}
	fixtureEqual(f.t, "atomic actor single use", successes, 1)
}

func qualifyBoundedLiveMemberships(f *keycloakFixture, e *exchangeExperiment, writer *keycloak.Client, model keycloak.AuthorizationModel,
	document map[string]any, save func(), subject string, rpt func(exchangeClient, ...string) exchangeResult,
	exchange func(string, exchangeResult) exchangeResult,
) {
	f.t.Helper()
	users := map[string]string{}
	for _, identity := range []exchangeClient{e.actor, e.subject} {
		var user struct {
			ID string `json:"id"`
		}
		f.admin(http.MethodGet, identity.path()+"/service-account-user", nil, &user)
		users[identity.name] = user.ID
	}
	for _, name := range []string{"bounded-member", "bounded-child"} {
		f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": name}, nil)
	}
	var role, child map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/roles/bounded-member", nil, &role)
	f.admin(http.MethodGet, "/admin/realms/managed/roles/bounded-child", nil, &child)
	for _, id := range users {
		f.admin(http.MethodPost, "/admin/realms/managed/users/"+id+"/role-mappings/realm", []any{role}, nil)
	}
	grant := document["grants"].([]any)[0].(map[string]any)
	previousConditions := grant["conditions"]
	grant["conditions"] = []any{map[string]any{"kind": "role", "id": role["id"]}}
	save()
	issued := exchange(subject, rpt(e.actor, "document#read"))
	e.success(issued, e.api.name)
	principals := []keycloak.BoundedDelegationPrincipal{{Kind: "application", Ref: e.actor.name, UID: "uid-" + e.actor.name}, {Kind: "application", Ref: e.subject.name, UID: "uid-" + e.subject.name}}
	permission := keycloak.BoundedDelegationPermission{Name: "role-delegation", Resources: []string{"document"}, Scopes: []string{"read"},
		Actor:      keycloak.BoundedDelegationIdentity{Kind: "application", ClientID: e.actor.name, UID: "uid-" + e.actor.name},
		Subject:    keycloak.BoundedDelegationIdentity{Kind: "application", ClientID: e.subject.name, UID: "uid-" + e.subject.name},
		Principals: []keycloak.BoundedDelegationPrincipal{{Kind: "realm_role", Ref: "bounded-member"}}, MaxDepth: 2, MaxTTLSeconds: 30}
	prepare := func() (keycloak.BoundedDelegationPreparation, error) {
		return writer.PrepareBoundedDelegation(context.Background(), model, "uid-"+e.api.name,
			[]keycloak.BoundedDelegationPermission{permission}, map[string][]keycloak.BoundedDelegationPrincipal{"base-access": principals})
	}
	before, err := prepare()
	f.requireNoError(err)
	f.admin(http.MethodPost, "/admin/realms/managed/roles/bounded-member/composites", []any{child}, nil)
	after, err := prepare()
	f.requireNoError(err)
	fixtureEqual(f.t, "composite widening changes sealed runtime proof", before.Runtime != after.Runtime, true)
	f.admin(http.MethodDelete, "/admin/realms/managed/users/"+users[e.subject.name]+"/role-mappings/realm", []any{role}, nil)
	e.denied(exchange(subject, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
	_, err = prepare()
	fixtureEqual(f.t, "removed subject role fails local intersection", errors.Is(err, keycloak.ErrBoundedDelegationUnsupported), true)
	e.success(issued, e.api.name) // Offline JWT remains valid only until its bounded expiry.
	f.admin(http.MethodPost, "/admin/realms/managed/users/"+users[e.subject.name]+"/role-mappings/realm", []any{role}, nil)

	f.admin(http.MethodPost, "/admin/realms/managed/groups", map[string]any{"name": "bounded-team", "attributes": map[string][]string{"hanko.sh/organization-uid": {"team-uid"}}}, nil)
	var groups []struct {
		ID string `json:"id"`
	}
	f.admin(http.MethodGet, "/admin/realms/managed/groups?search=bounded-team&exact=true", nil, &groups)
	fixtureEqual(f.t, "one owned group", len(groups), 1)
	groupID := groups[0].ID
	for _, id := range users {
		f.admin(http.MethodPut, "/admin/realms/managed/users/"+id+"/groups/"+groupID, nil, nil)
	}
	grant["conditions"] = []any{map[string]any{"kind": "group", "id": groupID, "attribute": "hanko.sh/organization-uid", "value": "team-uid"}}
	save()
	e.success(exchange(subject, rpt(e.actor, "document#read")), e.api.name)
	permission.Principals = []keycloak.BoundedDelegationPrincipal{{Kind: "organization", Ref: "team", Groups: []keycloak.BoundedDelegationBinding{{ID: groupID, Attribute: "hanko.sh/organization-uid", Value: "team-uid"}}}}
	_, err = prepare()
	f.requireNoError(err)
	f.admin(http.MethodDelete, "/admin/realms/managed/users/"+users[e.subject.name]+"/groups/"+groupID, nil, nil)
	e.denied(exchange(subject, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
	_, err = prepare()
	fixtureEqual(f.t, "removed organization member fails local intersection", errors.Is(err, keycloak.ErrBoundedDelegationUnsupported), true)
	f.admin(http.MethodPut, "/admin/realms/managed/users/"+users[e.subject.name]+"/groups/"+groupID, nil, nil)
	f.admin(http.MethodPut, "/admin/realms/managed/groups/"+groupID, map[string]any{"name": "bounded-team", "attributes": map[string][]string{"hanko.sh/organization-uid": {"replacement-uid"}}}, nil)
	e.denied(exchange(subject, rpt(e.actor, "document#read")), http.StatusBadRequest, "invalid_request")
	grant["conditions"] = previousConditions
	save()
}

func qualifyBoundedLostAcknowledgement(f *keycloakFixture, e *exchangeExperiment, model keycloak.AuthorizationModel,
	prepared keycloak.BoundedDelegationPreparation, secret, phase string,
) {
	f.t.Helper()
	origin, err := url.Parse(f.baseURL)
	f.requireNoError(err)
	proxy := &httputil.ReverseProxy{Transport: f.http.Transport} // Verified fixture TLS on both connections.
	type phaseKey struct{}
	proxy.Rewrite = func(exchange *httputil.ProxyRequest) {
		exchange.SetURL(origin)
		request := exchange.Out
		request.Host = origin.Host
		if request.Method != http.MethodPut || request.URL.Path != e.api.path() || request.Body == nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 512*1024+1))
		_ = request.Body.Close()
		request.Body = io.NopCloser(strings.NewReader(string(body)))
		if err != nil {
			return
		}
		var client struct {
			Attributes map[string]string `json:"attributes"`
		}
		if len(body) > 512*1024 || json.Unmarshal(body, &client) != nil {
			return
		}
		var journal struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal([]byte(client.Attributes["oauth.bounded-delegation.v1"]), &journal) == nil {
			*request = *request.WithContext(context.WithValue(request.Context(), phaseKey{}, journal.Phase))
		}
	}
	var lost atomic.Bool
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.StatusCode < 300 && response.Request.Context().Value(phaseKey{}) == phase && lost.CompareAndSwap(false, true) {
			_ = response.Body.Close()
			response.StatusCode = http.StatusServiceUnavailable
			response.Body = io.NopCloser(strings.NewReader("{}"))
			response.ContentLength = 2
			response.Header.Set("Content-Length", "2")
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }
	server := httptest.NewTLSServer(proxy)
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	interrupted, err := keycloak.NewWithTLS(server.URL, "delegation-writer", secret, ca)
	f.requireNoError(err)
	revision := string(iamcontract.Hash(iamcontract.Version, "test", "lost-acknowledgement", []byte(phase)))
	_, err = interrupted.ApplyBoundedDelegation(context.Background(), model, prepared, keycloak.AuthorizationManagedObjects{}, revision)
	if err == nil || !lost.Load() {
		f.t.Fatal("native journal acknowledgement fault was not observed")
	}
	restarted, err := keycloak.NewWithTLS(f.baseURL, "delegation-writer", secret, f.ca)
	f.requireNoError(err)
	state, err := restarted.ApplyBoundedDelegation(context.Background(), model, prepared, keycloak.AuthorizationManagedObjects{}, revision)
	f.requireNoError(err)
	verified, _, err := restarted.ObserveBoundedDelegation(context.Background(), model, prepared, state.ManagedObjects, revision)
	f.requireNoError(err)
	fixtureEqual(f.t, "lost acknowledgement recovered from native state", verified, true)
	fixtureEqual(f.t, "one owned resource", len(state.ManagedObjects.Resources), 1)
	fixtureEqual(f.t, "one ordinary permission", len(state.ManagedObjects.Permissions), 1)
}

func qualifyBoundedDelegationController(f *keycloakFixture, e *exchangeExperiment, writer *keycloak.Client) {
	f.t.Helper()
	scheme := runtime.NewScheme()
	f.requireNoError(api.AddToScheme(scheme))
	meta := func(name, uid string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: "extension-test", UID: types.UID(uid), Generation: 1}
	}
	objects := []client.Object{&api.HankoRealm{ObjectMeta: meta("managed", "realm-uid")}}
	for _, identity := range []struct {
		ref    string
		client exchangeClient
	}{{"api", e.api}, {"actor", e.actor}, {"subject", e.subject}} {
		objects = append(objects, &api.HankoApplication{ObjectMeta: meta(identity.ref, "uid-"+identity.client.name),
			Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: identity.client.name, Type: "m2m", Protocol: "oidc"}})
	}
	depth, ttl := int32(2), int32(30)
	principals := []api.AuthorizationPrincipal{{Kind: "application", Ref: "actor"}, {Kind: "application", Ref: "subject"}}
	object := &api.HankoResourceServer{ObjectMeta: meta("extension-test", "extension-test"), Spec: api.HankoResourceServerSpec{
		RealmRef: "managed", ApplicationRef: "api", Audience: e.api.name,
		Scopes:    []api.AuthorizationScope{{Name: "read"}, {Name: "write"}},
		Resources: []api.AuthorizationResource{{Name: "document", URIs: []string{"https://api.example.test/document"}, Scopes: []string{"read", "write"}}},
		Permissions: []api.AuthorizationPermission{
			{Name: "base-access", Resources: []string{"document"}, Scopes: []string{"read", "write"}, Principals: principals},
			{Name: "delegate-read", Resources: []string{"document"}, Scopes: []string{"read"}, Principals: principals,
				Delegation: &api.AuthorizationDelegation{Actor: api.AuthorizationDelegationIdentity{Kind: "application", Ref: "actor"},
					Subject: api.AuthorizationDelegationIdentity{Kind: "application", Ref: "subject"}, MaxDepth: &depth, MaxTTLSeconds: &ttl}},
		},
	}}
	objects = append(objects, object)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithStatusSubresource(&api.HankoResourceServer{}).Build()
	lostStatus := &boundedLostStatusClient{Client: kube}
	var kubeWriter client.Client = lostStatus
	provider := writer
	reconciler := func() *controller.HankoResourceServerReconciler {
		return &controller.HankoResourceServerReconciler{Client: kubeWriter, APIReader: kube, Scheme: scheme,
			DriverFactory: func(string, map[string]string) authorization.Driver {
				return authorization.NewKeycloakDelegationDriver(provider)
			}}
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
	_, err := reconciler().Reconcile(context.Background(), request)
	if err == nil || !lostStatus.lost.Load() {
		f.t.Fatal("post-commit Kubernetes status failure was not exercised")
	}
	kubeWriter = kube
	committedAPI, committedActor := f.client("managed", e.api.name), f.client("managed", e.actor.name)
	_, err = reconciler().Reconcile(context.Background(), request)
	f.requireNoError(err)
	fixtureEqual(f.t, "status-loss recovery preserves native grant", f.client("managed", e.api.name), committedAPI)
	fixtureEqual(f.t, "status-loss recovery preserves actor", f.client("managed", e.actor.name), committedActor)
	var current api.HankoResourceServer
	f.requireNoError(kube.Get(context.Background(), request.NamespacedName, &current))
	fixtureEqual(f.t, "current generation applied", current.Status.AppliedGeneration, current.Generation)
	fixtureEqual(f.t, "provider capability qualified", current.Status.Capabilities.BoundedDelegation, true)
	found := false
	if current.Status.AuthorizationExplanation != nil {
		for _, path := range current.Status.AuthorizationExplanation.Paths {
			if path.Relationship == "delegated" && path.Delegation != nil && path.Delegation.Actor.Ref == "actor" && path.Delegation.Subject.Ref == "subject" {
				found = true
			}
		}
	}
	fixtureEqual(f.t, "observed local delegation origin", found, true)
	beforeAPI, beforeActor := f.client("managed", e.api.name), f.client("managed", e.actor.name)
	_, err = reconciler().Reconcile(context.Background(), request)
	f.requireNoError(err)
	fixtureEqual(f.t, "restart preserves native resource server", f.client("managed", e.api.name), beforeAPI)
	fixtureEqual(f.t, "restart preserves native actor", f.client("managed", e.actor.name), beforeActor)
	// Change desired authority after the plan has passed its initial checks but
	// immediately before the first native write. The composed fresh guard must win.
	f.requireNoError(kube.Get(context.Background(), request.NamespacedName, &current))
	changedTTL := int32(29)
	current.Spec.Permissions[1].Delegation.MaxTTLSeconds = &changedTTL
	current.Generation++
	f.requireNoError(kube.Update(context.Background(), &current))
	var changed atomic.Bool
	provider = writer.WithMutationGuard(func(ctx context.Context) error {
		if changed.CompareAndSwap(false, true) {
			var latest api.HankoResourceServer
			if err := kube.Get(ctx, request.NamespacedName, &latest); err != nil {
				return err
			}
			ttl := int32(28)
			latest.Spec.Permissions[1].Delegation.MaxTTLSeconds = &ttl
			latest.Generation++
			return kube.Update(ctx, &latest)
		}
		return nil
	})
	_, err = reconciler().Reconcile(context.Background(), request)
	if !changed.Load() || !errors.Is(err, iamcontract.ErrStale) {
		f.t.Fatal("concurrent spec change did not invalidate delegated execution")
	}
	fixtureEqual(f.t, "stale execution leaves grant unchanged", f.client("managed", e.api.name), beforeAPI)
	fixtureEqual(f.t, "stale execution leaves actor unchanged", f.client("managed", e.actor.name), beforeActor)
	var forbiddenWrites atomic.Int32
	provider = writer.WithMutationGuard(func(context.Context) error {
		forbiddenWrites.Add(1)
		return errors.New("fixture: read-only flow attempted a native mutation")
	})
	for _, imported := range []bool{false, true} {
		f.requireNoError(kube.Get(context.Background(), request.NamespacedName, &current))
		current.Spec.Mode = "Observe"
		if imported {
			current.Spec.Mode = "Manage"
			current.Labels = map[string]string{"hanko.sh/imported-by": "inventory"}
		}
		current.Generation++
		f.requireNoError(kube.Update(context.Background(), &current))
		_, _ = reconciler().Reconcile(context.Background(), request) // Imported acquisition may refuse an absent inventory.
		fixtureEqual(f.t, "read-only path attempts no provider writes", forbiddenWrites.Load(), int32(0))
		fixtureEqual(f.t, "read-only path preserves grant", f.client("managed", e.api.name), beforeAPI)
		fixtureEqual(f.t, "read-only path preserves actor", f.client("managed", e.actor.name), beforeActor)
	}
}

type boundedLostStatusClient struct {
	client.Client
	lost atomic.Bool
}
type boundedLostStatusWriter struct {
	client.SubResourceWriter
	lost *atomic.Bool
}

func (c *boundedLostStatusClient) Status() client.SubResourceWriter {
	return &boundedLostStatusWriter{c.Client.Status(), &c.lost}
}
func (w *boundedLostStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	if object, ok := object.(*api.HankoResourceServer); ok && object.Status.AppliedGeneration > 0 && w.lost.CompareAndSwap(false, true) {
		return errors.New("fixture: post-commit status response unavailable")
	}
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
}
