package roles

import (
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestRoleObservationIdentityAndAdditiveMembership(t *testing.T) {
	p, err := Compile(Intent{RealmRef: "realm", Name: "parent", Description: "desired", Composites: []string{"child"}}, ResolvedReferences{Realm: "realm", Owner: "owner", Attributes: map[string][]string{"team": {"a", "b"}}}, KeycloakEvidence(), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	role := keycloak.RealmRole{ID: "provider-generated-id", Name: "parent", Description: "desired", Composite: true, Attributes: map[string][]string{OwnerAttribute: {"owner"}, "team": {"a", "b"}}}
	a := observeRole(&role, p, []string{"extra", "child"}, []string{"parent", "extra", "child"}, false)
	role.ID = "another-provider-id"
	b := observeRole(&role, p, []string{"child", "extra", "child"}, []string{"child", "parent", "extra"}, false)
	if a.Drifted || !a.Observation.Complete || a.Observation.StateHash != b.Observation.StateHash {
		t.Fatal("order/IDs/additive extra membership changed equality")
	}
	role.Description = "drift"
	c := observeRole(&role, p, []string{"child", "extra"}, []string{"parent", "child", "extra"}, false)
	if !c.Drifted || c.Observation.StateHash == a.Observation.StateHash {
		t.Fatal("description drift absent from observation")
	}
	role.Description = "desired"
	role.Attributes["team"] = []string{"b", "a"}
	if !observeRole(&role, p, []string{"child"}, []string{"parent", "child"}, false).Drifted {
		t.Fatal("native list order semantics were changed")
	}
	if !observeRole(&role, p, []string{"wrapper"}, []string{"parent", "wrapper", "child"}, false).Drifted {
		t.Fatal("transitive membership falsely proved declared direct relationship")
	}
}

func TestRoleObservationExcludesCredentialMetadataAndForeignOwner(t *testing.T) {
	p, err := Compile(Intent{RealmRef: "realm", Name: "role"}, ResolvedReferences{Realm: "realm", Owner: "owner"}, KeycloakEvidence(), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	role := keycloak.RealmRole{Name: "role", Attributes: map[string][]string{OwnerAttribute: {"owner"}, "password": {"fixture-secret-sentinel"}}}
	state := observeRole(&role, p, nil, nil, false)
	if state.Observation.Complete || !state.Drifted || len(state.Findings) != 1 || !state.Findings[0].ReadOnly {
		t.Fatal("credential metadata claimed complete equality")
	}
	iamconformance.NoSecrets(t, []string{"fixture-secret-sentinel"}, state, p, p.Identity())
	role.Attributes = map[string][]string{OwnerAttribute: {"foreign-uid"}}
	if state := observeRole(&role, p, nil, nil, false); state.Owned || !state.Drifted {
		t.Fatal("foreign ownership accepted")
	}
	if state := observeRole(nil, p, nil, nil, false); state.Present || !state.Drifted || !state.Observation.Complete {
		t.Fatal("absence not represented deterministically")
	}
}

func TestRoleReferenceEvidenceChangesOnlyProviderPlan(t *testing.T) {
	i := Intent{RealmRef: "realm", Name: "role"}
	r := ResolvedReferences{Realm: "realm", Owner: "owner"}
	a, _ := Compile(i, r, KeycloakEvidence(), iamcontract.Preconditions{References: "one"})
	b, _ := Compile(i, r, KeycloakEvidence(), iamcontract.Preconditions{References: "two"})
	if a.Identity().Intent != b.Identity().Intent || a.Identity().Plan == b.Identity().Plan {
		t.Fatal("reference freshness was absent from plan identity")
	}
}
