package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestDelegatedExplanationRequiresObservedGrantAndPortableOrigin(t *testing.T) {
	model := delegationModel()
	model.Permissions[0].Scopes = []string{"read"}
	plan := delegationPlan(t, model, "private-actor-client-id", iamcontract.Preconditions{ResourceUID: "owner"})
	state := State{Observation: iamcontract.Observation{Complete: true, StateHash: iamcontract.Hash(iamcontract.Version, "test", "observation", nil)},
		Structure: &StructuralObservation{Enabled: true, Complete: true, Delegations: []string{model.Permissions[0].Name}, Resources: []ObservedResource{{Name: "invoice", Present: true, Scopes: []string{"read"}}}}}
	evidence := ExplanationEvidence{Complete: true}
	result := Explain(plan, state, evidence, 2, true)
	if !result.Complete || len(result.Paths) != 1 || result.Paths[0].Relationship != "delegated" || result.Paths[0].Delegation.Actor.Ref != "actor" || result.Paths[0].Delegation.Subject.Ref != "subject" {
		t.Fatal("observed delegation origin missing")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "private-") {
		t.Fatal("native identities escaped into explanation")
	}
	for _, scenario := range []string{"unverified", "missing actor ref", "missing subject ref", "missing resource", "unknown scopes", "scope not observed"} {
		t.Run(scenario, func(t *testing.T) {
			next := plan
			next.resolved.model = canonicalModel(plan.resolved.model)
			current := state
			graph := *state.Structure
			graph.Resources = append([]ObservedResource(nil), graph.Resources...)
			current.Structure = &graph
			switch scenario {
			case "unverified":
				graph.Delegations = nil
			case "missing actor ref":
				next.resolved.model.Permissions[0].Delegation.Actor.PortableRef = ""
			case "missing subject ref":
				next.resolved.model.Permissions[0].Delegation.Subject.PortableRef = ""
			case "missing resource":
				graph.Resources = nil
			case "unknown scopes":
				graph.Resources[0].UnknownScopes = 1
			case "scope not observed":
				graph.Resources[0].Scopes = []string{"other"}
			}
			explanation := Explain(next, current, evidence, 2, true)
			if explanation.Complete || len(explanation.Paths) != 0 {
				t.Fatal("unobserved delegated access was fabricated")
			}
		})
	}
}

func TestDelegationFindingsNameExcessWithoutProviderPayloads(t *testing.T) {
	err := boundedDelegationError(keycloak.BoundedDelegationExcessError{Permission: "delegate-read", Resource: "invoice", Scope: "admin"})
	var rejected DelegationRejection
	if !errors.As(err, &rejected) || len(rejected.Findings) != 3 {
		t.Fatal("machine-readable excess was lost")
	}
	for i, name := range []string{"delegate-read", "invoice", "admin"} {
		if rejected.Findings[i].ObjectName != name || rejected.Findings[i].Code != "DelegationAuthorityExceeded" {
			t.Fatal("excess did not identify its exact dimension")
		}
	}
	for _, source := range []error{keycloak.ErrBoundedDelegationUnsupported, keycloak.ErrAuthorizationOwnershipConflict, errors.New("private-provider-token")} {
		mapped := boundedDelegationError(source)
		if mapped == nil || strings.Contains(mapped.Error(), "private-provider-token") {
			t.Fatal("provider payload leaked or error was ignored")
		}
	}
}

func TestBoundedPreparationConvertsIntentWithoutMutatingUnavailableProvider(t *testing.T) {
	mutations, discoveries := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/acme/bounded-delegation":
			discoveries++
			_ = json.NewEncoder(w).Encode(keycloak.BoundedDelegationCapability{Contract: "bounded-delegation/software-v1", ExtensionVersion: "0.1.0-SNAPSHOT", KeycloakVersion: "26.8.1", Experimental: true, Enabled: true, MaxDepth: 4, MaxTTLSeconds: 600})
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-test-token", "expires_in": 300})
		case "/admin/realms/acme":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "realm-uid", "enabled": false, "accessTokenLifespan": 300})
		default:
			if r.Method != http.MethodGet {
				mutations++
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	driver := NewKeycloakDelegationDriver(keycloak.New(server.URL, "operator", "synthetic", keycloak.WithInsecureHTTP()))
	model := delegationModel()
	model.Realm = "acme"
	model.DelegationContext = &ResolvedDelegationContext{AudienceUID: "api-uid"}
	model.Permissions[0].Principals = append(model.Permissions[0].Principals, Principal{Kind: "organization", Ref: "team", Organization: &ResolvedOrganizationPrincipal{Groups: []OrganizationGroup{{ID: "native-group", UID: "group-uid"}}}})
	ordinary := model.Permissions[0]
	ordinary.Name = "ordinary"
	ordinary.Delegation = nil
	model.Permissions = append(model.Permissions, ordinary)
	_, err := driver.PrepareDelegation(context.Background(), model, "owner")
	if !errors.Is(err, ErrCapabilityUnsupported) || discoveries != 1 || mutations != 0 {
		t.Fatal("unavailable realm did not refuse before mutation")
	}
	clone := driver.WithMutationGuard(func(context.Context) error { return errors.New("revoked") }).(*KeycloakDriver)
	if !clone.boundedDelegation || clone.client == driver.client {
		t.Fatal("guard changed shared driver state or removed the profile")
	}
	mapped := boundedPrincipals(model.Permissions[0].Principals)
	if mapped[len(mapped)-1].Groups[0].Value != "group-uid" {
		t.Fatal("organization binding lost its UID")
	}
	mapped[len(mapped)-1].Groups[0].Value = "changed"
	if model.Permissions[0].Principals[len(mapped)-1].Organization.Groups[0].UID != "group-uid" {
		t.Fatal("native mapping aliases portable intent")
	}
}
