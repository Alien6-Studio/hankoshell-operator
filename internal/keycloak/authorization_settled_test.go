package keycloak

import (
	"context"
	"reflect"
	"testing"
)

func authorizationRequests(f *authorizationTestServer) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func TestSettledAuthorizationUsesOneFreshObservationAndRecoversLostStatus(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "settled-owner"
	first, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	before := authorizationRequests(f)
	if _, err := c.ObserveAuthorization(context.Background(), model); err != nil {
		t.Fatal(err)
	}
	observationReads := authorizationRequests(f) - before
	t.Logf("fresh observation budget: %d native reads", observationReads)
	mutations := f.mutationCount()
	// The complete Kubernetes checkpoint is absent on every attempt. Only a
	// fresh, valid native owner journal and actual graph can reconstruct it.
	for range 3 {
		before = authorizationRequests(f)
		state, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
		reads := authorizationRequests(f) - before
		if err != nil || !state.Observation.Complete || state.Drifted ||
			!reflect.DeepEqual(state.ManagedObjects, first.ManagedObjects) || reads > observationReads || f.mutationCount() != mutations {
			t.Fatalf("settled recovery: err=%v complete=%t drift=%t reads=%d observation=%d", err, state.Observation.Complete, state.Drifted, reads, observationReads)
		}
	}
	f.mu.Lock()
	id := first.ManagedObjects.Scopes[0].ID
	scope := f.scopes[id]
	scope.DisplayName = "native drift after prior observation"
	f.scopes[id] = scope
	f.mu.Unlock()
	if _, err := c.ReconcileAuthorization(context.Background(), model, first.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if f.mutationCount() != mutations+1 {
		t.Fatal("fresh native drift was cached or caused unrelated writes")
	}
	state, err := c.ObserveAuthorization(context.Background(), model)
	if err != nil || state.Drifted || !state.Observation.Complete {
		t.Fatal("native repair did not converge", err)
	}
}

func TestSettledAuthorizationStillRetiresRemovedOwnedGraph(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c := f.client()
	model := authorizationTestModel()
	model.OwnerUID = "retirement-owner"
	first, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.scopes["foreign-scope"] = authorizationScopeRepresentation{ID: "foreign-scope", Name: "foreign-scope"}
	f.mu.Unlock()
	model.Scopes, model.Resources, model.Permissions = nil, nil, nil
	retired, err := c.ReconcileAuthorization(context.Background(), model, first.ManagedObjects)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(retired.ManagedObjects.Scopes)+len(retired.ManagedObjects.Resources)+len(retired.ManagedObjects.Policies)+len(retired.ManagedObjects.Permissions) != 0 ||
		len(f.scopes) != 1 || f.scopes["foreign-scope"].Name != "foreign-scope" || len(f.resources)+len(f.policies)+len(f.permissions) != 0 {
		t.Fatal("settled observation bypassed retirement or touched foreign state")
	}
}

func TestSettledAuthorizationNeverTrustsAnUnavailableOrForeignJournal(t *testing.T) {
	for _, scenario := range []string{"unavailable", "foreign-owner", "partial-journal"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAuthorizationTestServer(t)
			c := f.client()
			model := authorizationTestModel()
			model.OwnerUID = "journal-owner"
			first, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			switch scenario {
			case "unavailable":
				f.failPath = "/scope"
			case "foreign-owner":
				model.OwnerUID = "replacement-owner"
			case "partial-journal":
				f.attributes[authorizationOwnerAttribute] = `{"version":1,"ownerUID":"journal-owner"}`
			}
			f.mu.Unlock()
			before := f.mutationCount()
			state, err := c.ReconcileAuthorization(context.Background(), model, first.ManagedObjects)
			if err == nil || state.Observation.Complete || before != f.mutationCount() {
				t.Fatal("unproved observation fabricated convergence or writes", err)
			}
		})
	}
}

func TestSettledAuthorizationRetiresEachUnobservedOwnedCategory(t *testing.T) {
	for _, category := range []string{"scope", "resource", "policy", "permission"} {
		t.Run(category, func(t *testing.T) {
			f := newAuthorizationTestServer(t)
			c := f.client()
			model := authorizationTestModel()
			model.OwnerUID = "retirement-owner"
			first, err := c.ReconcileAuthorization(t.Context(), model, AuthorizationManagedObjects{})
			if err != nil {
				t.Fatal(err)
			}
			owned := first.ManagedObjects
			extra := AuthorizationManagedReference{Name: "obsolete", ID: "obsolete"}
			f.mu.Lock()
			switch category {
			case "scope":
				owned.Scopes = append(owned.Scopes, extra)
				f.scopes[extra.ID] = authorizationScopeRepresentation{ID: extra.ID, Name: extra.Name}
			case "resource":
				owned.Resources = append(owned.Resources, extra)
				f.resources[extra.ID] = authorizationResourceRepresentation{ID: extra.ID, Name: extra.Name}
			case "policy":
				owned.Policies = append(owned.Policies, extra)
				f.policies[extra.ID] = authorizationPolicyRepresentation{ID: extra.ID, Name: extra.Name, Type: "role"}
			case "permission":
				owned.Permissions = append(owned.Permissions, extra)
				f.permissions[extra.ID] = authorizationPermissionRepresentation{ID: extra.ID, Name: extra.Name, Type: "scope"}
			}
			f.mu.Unlock()
			if err := c.saveAuthorizationOwnership(t.Context(), model, owned); err != nil {
				t.Fatal(err)
			}
			current, err := c.ReconcileAuthorization(t.Context(), model, owned)
			if err != nil || !reflect.DeepEqual(current.ManagedObjects, first.ManagedObjects) {
				t.Fatal("unchanged desired projection concealed obsolete owned state", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.deleteOrder) != 1 || f.deleteOrder[0] != category {
				t.Fatal("obsolete native object was not selectively retired")
			}
		})
	}
}
