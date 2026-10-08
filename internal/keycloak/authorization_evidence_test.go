package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestAuthorizationObservationIgnoresProviderIDs(t *testing.T) {
	model := authorizationTestModel()
	model.OwnerUID = "same-owner"
	projections := []AuthorizationObservation{}
	for _, offset := range []int{0, 1000} {
		f := newAuthorizationTestServer(t)
		f.nextID = offset
		c := f.client()
		if _, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); err != nil {
			t.Fatal(err)
		}
		state, err := c.ObserveAuthorization(context.Background(), model)
		if err != nil {
			t.Fatal(err)
		}
		projections = append(projections, state.Observation)
	}
	if !reflect.DeepEqual(projections[0], projections[1]) {
		t.Fatal("provider-generated IDs entered canonical observation")
	}
}

func TestApplicationReconciliationPreservesAuthorizationOwnership(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "sibling-owner"
	if _, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); err != nil {
		t.Fatal(err)
	}
	journal := f.attributes[authorizationOwnerAttribute]
	if err := c.UpdateApp(context.Background(), "acme", CreateAppSpec{ClientID: "billing-api", Type: "m2m", Attributes: map[string]string{authorizationOwnerAttribute: "forged-journal", "team": "platform"}}); err != nil {
		t.Fatal(err)
	}
	if f.attributes[authorizationOwnerAttribute] != journal || !f.enabled {
		t.Fatal("application reconciliation overwrote sibling ownership")
	}
	if _, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); err != nil {
		t.Fatal("sibling update prevented ownership recovery", err)
	}
}

func TestAuthorizationDeletionAcknowledgementDoesNotProveRetirement(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "retirement-owner"
	state, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	f.ignoreDeletes = true
	empty := model
	empty.Scopes = nil
	empty.Resources = nil
	empty.Permissions = nil
	if _, err := c.ReconcileAuthorization(context.Background(), empty, state.ManagedObjects); !errors.Is(err, ErrAuthorizationReadBack) {
		t.Fatal("delete acknowledgement falsely proved convergence", err)
	}
	if err := c.DeleteAuthorizationOwned(context.Background(), model, state.ResourceServerID, state.ManagedObjects); !errors.Is(err, ErrAuthorizationReadBack) {
		t.Fatal("cleanup skipped deletion read-back", err)
	}
	f.ignoreDeletes = false
	if _, err := c.ReconcileAuthorization(context.Background(), empty, AuthorizationManagedObjects{}); err != nil {
		t.Fatal("retirement ownership was lost after read-back failure", err)
	}
}

func TestAuthorizationOwnershipRecoversWithoutKubernetesStatus(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "resource-server-uid"
	first, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	before := f.mutationCount()
	// Simulate losing the complete status patch after provider apply.
	recovered, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil || !reflect.DeepEqual(first.ManagedObjects, recovered.ManagedObjects) || before != f.mutationCount() {
		t.Fatal("status loss did not recover ownership without writes", err)
	}
	observed, err := c.ObserveAuthorization(context.Background(), model)
	if err != nil || observed.Drifted || !observed.Observation.Complete {
		t.Fatal("complete graph did not prove equality", err)
	}
	if before != f.mutationCount() {
		t.Fatal("observation mutated provider")
	}
	foreign := model
	foreign.OwnerUID = "other-uid"
	if _, err := c.ReconcileAuthorization(context.Background(), foreign, first.ManagedObjects); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
		t.Fatal("foreign journal was adopted")
	}
	if err := c.DeleteAuthorizationOwned(context.Background(), model, "", AuthorizationManagedObjects{}); err != nil {
		t.Fatal(err)
	}
	if f.enabled || len(f.scopes)+len(f.resources)+len(f.policies)+len(f.permissions) != 0 {
		t.Fatal("deletion without status leaked owned objects")
	}
}

func TestAuthorizationPartialApplyRecoversCheckpointedReferences(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "partial-uid"
	f.failPath = "/resource"
	partial, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err == nil || len(partial.ManagedObjects.Scopes) != 1 {
		t.Fatal("partial apply did not return operational ownership")
	}
	scopeID := partial.ManagedObjects.Scopes[0].ID
	f.mu.Lock()
	f.failPath = ""
	f.mu.Unlock()
	complete, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil || complete.ManagedObjects.Scopes[0].ID != scopeID {
		t.Fatal("partial apply repeated scope creation", err)
	}
}

func TestAuthorizationObservationDetectsEveryManagedDimension(t *testing.T) {
	for _, dimension := range []string{"enabled", "scope-description", "resource-uri", "resource-scope", "permission-scope", "permission-resource", "permission-policy", "policy-logic", "policy-strategy", "policy-required", "policy-principal", "ownership"} {
		t.Run(dimension, func(t *testing.T) {
			f := newAuthorizationTestServer(t)
			c := f.client()
			model := authorizationTestModel()
			model.OwnerUID = "observation-uid"
			state, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
			if err != nil {
				t.Fatal(err)
			}
			before, err := c.ObserveAuthorization(context.Background(), model)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			switch dimension {
			case "enabled":
				f.enabled = false
			case "scope-description":
				id := state.ManagedObjects.Scopes[0].ID
				v := f.scopes[id]
				v.DisplayName = "changed"
				f.scopes[id] = v
			case "resource-uri", "resource-scope":
				id := state.ManagedObjects.Resources[0].ID
				v := f.resources[id]
				if dimension == "resource-uri" {
					v.URIs = []string{"/changed"}
				} else {
					v.Scopes = nil
				}
				f.resources[id] = v
			case "permission-scope", "permission-resource", "permission-policy":
				id := state.ManagedObjects.Permissions[0].ID
				v := f.permissions[id]
				switch dimension {
				case "permission-scope":
					v.Scopes = nil
				case "permission-resource":
					v.Resources = nil
				case "permission-policy":
					v.Policies = nil
				}
				f.permissions[id] = v
			case "policy-logic", "policy-strategy", "policy-required", "policy-principal":
				id := state.ManagedObjects.Policies[0].ID
				v := f.policies[id]
				switch dimension {
				case "policy-logic":
					v.Logic = "NEGATIVE"
				case "policy-strategy":
					v.DecisionStrategy = "UNANIMOUS"
				case "policy-required":
					v.Roles[0].Required = true
				case "policy-principal":
					v.Roles[0].ID = "unknown-provider-id"
				}
				f.policies[id] = v
			case "ownership":
				delete(f.attributes, authorizationOwnerAttribute)
			}
			f.mu.Unlock()
			writes := f.mutationCount()
			after, err := c.ObserveAuthorization(context.Background(), model)
			if err != nil || !after.Drifted {
				t.Fatal("managed drift not detected", err)
			}
			x, _ := json.Marshal(before.Observation)
			y, _ := json.Marshal(after.Observation)
			if string(x) == string(y) || writes != f.mutationCount() {
				t.Fatal("observation identity unchanged or observation wrote provider")
			}
			if dimension == "policy-principal" && after.Observation.Complete {
				t.Fatal("unknown binding claimed complete observation")
			}
		})
	}
}

func TestAuthorizationJournalRejectsForgedStatusAndBudgets(t *testing.T) {
	f := newAuthorizationTestServer(t)
	f.enabled = true
	model := authorizationTestModel()
	model.OwnerUID = "forged-status-uid"
	_, err := f.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{ResourceServerID: "client-uuid"})
	if !errors.Is(err, ErrAuthorizationOwnershipConflict) || f.mutationCount() != 0 {
		t.Fatal("status alone adopted unmarked enabled server")
	}
	for _, value := range []string{"not-json", `{"version":1,"ownerUID":"another","objects":{"ResourceServerID":"client-uuid"}}`} {
		_, _, err := parseAuthorizationJournal(map[string]any{"attributes": map[string]any{authorizationOwnerAttribute: value}}, model.OwnerUID, "client-uuid")
		if !errors.Is(err, ErrAuthorizationOwnershipConflict) {
			t.Fatal("unsafe journal accepted")
		}
	}
	refs := make([]AuthorizationManagedReference, 65)
	if validAuthorizationObjects(AuthorizationManagedObjects{Scopes: refs}) {
		t.Fatal("oversized ownership accepted")
	}
}
