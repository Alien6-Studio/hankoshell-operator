package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// The ordinary graph fixture is reused, while client PUT deliberately implements
// Keycloak's merge/null-removal semantics. An omitted attribute must survive.
type boundedJournalFixture struct {
	base       *authorizationTestServer
	server     *httptest.Server
	actor      map[string]any
	faultPhase string
	triggered  bool
}

func TestBoundedActorRecoveryRequiresExplicitStoredIdentity(t *testing.T) {
	actor := BoundedDelegationBinding{ID: "actor-id", Attribute: adoption.ClientOwnerUIDKey, Value: "actor-uid"}
	marker := boundedDelegationActorMarker{Version: 1, Actor: actor, Owners: map[string]string{"audience-id": "owner-uid"}}
	valid, _ := json.Marshal(marker)
	for _, field := range []string{"version", "actor", "partial actor", "null actor", "null version"} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			_ = json.Unmarshal(valid, &document)
			switch field {
			case "partial actor":
				document["actor"] = map[string]any{"id": actor.ID}
			case "null actor":
				document["actor"] = nil
			case "null version":
				document["version"] = nil
			default:
				delete(document, field)
			}
			encoded, _ := json.Marshal(document)
			current := map[string]any{"attributes": map[string]any{BoundedDelegationActorAttribute: string(encoded), "standard.token.exchange.enabled": "true"}}
			if _, err := parseBoundedActorMarker(current, actor, "audience-id", "owner-uid"); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
				t.Fatal("recovery filled missing native identity from the requested actor")
			}
		})
	}
	current := map[string]any{"attributes": map[string]any{BoundedDelegationActorAttribute: string(valid), "standard.token.exchange.enabled": "true"}}
	parsed, err := parseBoundedActorMarker(current, actor, "audience-id", "owner-uid")
	if err != nil || parsed.ExchangePresent || parsed.PreviousExchange != "" || parsed.Owners["audience-id"] != "owner-uid" {
		t.Fatal("stored exchange history was replaced by current native configuration")
	}
}

func newBoundedJournalFixture(t *testing.T, fault string) *boundedJournalFixture {
	t.Helper()
	f := &boundedJournalFixture{base: newAuthorizationTestServer(t), faultPhase: fault,
		actor: map[string]any{adoption.ApplicationOwnerKey: "actor-uid", "standard.token.exchange.enabled": "false", "unrelated": "preserved"}}
	f.base.attributes[adoption.ApplicationOwnerKey] = "api-uid"
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *boundedJournalFixture) client() *Client {
	return New(f.server.URL, "operator", "synthetic", WithInsecureHTTP())
}
func (f *boundedJournalFixture) serve(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/realms/acme/clients/")
	if id != "client-uuid" && id != "actor-uuid" {
		f.base.ServeHTTP(w, r)
		return
	}
	f.base.mu.Lock()
	defer f.base.mu.Unlock()
	attrs := f.base.attributes
	if id == "actor-uuid" {
		attrs = f.actor
	}
	switch r.Method {
	case http.MethodGet:
		writeAuthorizationJSON(w, map[string]any{"id": id, "clientId": map[string]string{"client-uuid": "billing-api", "actor-uuid": "actor"}[id],
			"enabled": true, "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": f.base.enabled, "attributes": attrs})
	case http.MethodPut:
		var body struct {
			Attributes                   map[string]any `json:"attributes"`
			AuthorizationServicesEnabled bool           `json:"authorizationServicesEnabled"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		for k, v := range body.Attributes {
			if v == nil {
				delete(attrs, k)
			} else {
				attrs[k] = v
			}
		}
		if id == "client-uuid" {
			f.base.enabled = body.AuthorizationServicesEnabled
		}
		f.base.mutations++
		if raw, ok := body.Attributes[BoundedDelegationAttribute].(string); ok && !f.triggered && f.faultPhase != "" {
			var document BoundedDelegationDocument
			if json.Unmarshal([]byte(raw), &document) == nil && document.Phase == f.faultPhase {
				f.triggered = true
				w.WriteHeader(503)
				return
			}
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func boundedJournalModel() (AuthorizationModel, BoundedDelegationPreparation) {
	model := authorizationTestModel()
	model.OwnerUID = "resource-server-uid"
	model.ApplicationUID = "api-uid"
	document := boundedTestDocument()
	document.Phase = "Prepared"
	document.Grants[0].Authority.Permissions = map[string][]string{"invoices": {"invoices:read"}}
	return model, BoundedDelegationPreparation{Document: document}
}

func TestBoundedJournalRecoversEveryLostAcknowledgementFromNativeState(t *testing.T) {
	for _, phase := range []string{"Prepared", "Applied", "Verified", "Committed"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newBoundedJournalFixture(t, phase)
			model, prepared := boundedJournalModel()
			revision := prepared.Document.Revision
			_, err := fixture.client().ApplyBoundedDelegation(context.Background(), model, prepared, AuthorizationManagedObjects{}, revision)
			if err == nil || !fixture.triggered {
				t.Fatal("accepted native journal response was not lost")
			}
			restarted := fixture.client()
			state, err := restarted.ApplyBoundedDelegation(context.Background(), model, prepared, AuthorizationManagedObjects{}, revision)
			if err != nil {
				t.Fatal("native transaction did not recover", err)
			}
			verified, _, err := restarted.ObserveBoundedDelegation(context.Background(), model, prepared, state.ManagedObjects, revision)
			if err != nil || !verified || len(fixture.base.resources) != 1 || len(fixture.base.permissions) != 1 {
				t.Fatal("recovery duplicated or failed to commit native grants", err)
			}
			before := fixture.base.mutationCount()
			_, err = restarted.ApplyBoundedDelegation(context.Background(), model, prepared, AuthorizationManagedObjects{}, revision)
			if err != nil || fixture.base.mutationCount() != before {
				t.Fatal("committed recovery repeated native writes", err)
			}
			observed, err := restarted.ObserveBoundedAuthorization(context.Background(), model)
			if err != nil || len(observed.ManagedObjects.Resources) != 1 || fixture.base.mutationCount() != before {
				t.Fatal("observation mutated or lost recovered ownership", err)
			}
			_, err = restarted.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
			if err != nil {
				t.Fatal("owned cleanup failed", err)
			}
			if fixture.actor["standard.token.exchange.enabled"] != "false" || fixture.actor[BoundedDelegationActorAttribute] != nil || fixture.base.attributes[BoundedDelegationAttribute] != nil || fixture.actor["unrelated"] != "preserved" {
				t.Fatal("cleanup failed exact null removal or changed independent attributes")
			}
		})
	}
}

func TestBoundedJournalRefusesForeignOwnerBeforeAnyWrite(t *testing.T) {
	fixture := newBoundedJournalFixture(t, "")
	model, prepared := boundedJournalModel()
	foreign := prepared.Document
	foreign.OwnerUID = "foreign-owner"
	encoded, err := boundedDelegationJSON(foreign)
	if err != nil {
		t.Fatal(err)
	}
	fixture.base.attributes[BoundedDelegationAttribute] = string(encoded)
	_, err = fixture.client().ApplyBoundedDelegation(context.Background(), model, prepared, AuthorizationManagedObjects{}, prepared.Document.Revision)
	if !errors.Is(err, ErrAuthorizationOwnershipConflict) || fixture.base.mutationCount() != 0 {
		t.Fatal("foreign journal was overwritten", err)
	}
}
