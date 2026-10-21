package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOrganizationGroupPolicyForeignCollisionIsNotAdopted(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	model := authorizationTestModel()
	model.OwnerUID = "owner"
	model.Permissions[0].Principals = []AuthorizationPrincipal{{Kind: "organization", Ref: "europe", Groups: []AuthorizationGroupDefinition{{ID: "owned-group"}}}}
	foreign := authorizationPolicyRepresentation{ID: "foreign-id", Name: managedPolicyName(model.Name, "readers#organizations"), Type: "group", Groups: []AuthorizationGroupDefinition{{ID: "foreign-group"}}, Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE"}
	provider.policies[foreign.ID] = foreign
	if _, err := provider.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
		t.Fatal("foreign group policy adopted", err)
	}
	provider.mu.Lock()
	got := provider.policies[foreign.ID]
	provider.mu.Unlock()
	if !policyEqual(got, foreign, "group") {
		t.Fatal("foreign group policy mutated")
	}
}

func TestOwnedGroupPolicyConvergesAndPreservesRoleAndForeignPolicies(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	c := provider.client()
	ctx := context.Background()
	model := authorizationTestModel()
	model.OwnerUID = "owner"
	model.Permissions[0].Principals = append(model.Permissions[0].Principals, AuthorizationPrincipal{Kind: "organization", Ref: "europe", Groups: []AuthorizationGroupDefinition{{ID: "group-b"}, {ID: "group-a"}, {ID: "group-a"}}})
	state, err := c.ReconcileAuthorization(ctx, model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ManagedObjects.Policies) != 2 {
		t.Fatal("mixed role/group policy count differs")
	}
	before := provider.mutationCount()
	state, err = c.ReconcileAuthorization(ctx, model, state.ManagedObjects)
	if err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != before {
		t.Fatal("group reconciliation is not idempotent")
	}
	provider.mu.Lock()
	var groupID string
	for id, p := range provider.policies {
		if p.Type == "group" {
			groupID = id
			p.GroupsClaim = "foreign-claim"
			p.Groups[0].ExtendChildren = true
			provider.policies[id] = p
		}
	}
	provider.policies["foreign-group-policy"] = authorizationPolicyRepresentation{ID: "foreign-group-policy", Name: "foreign", Type: "group", Groups: []AuthorizationGroupDefinition{{ID: "foreign-group"}}, GroupsClaim: "native-claim", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE"}
	provider.mu.Unlock()
	observed, err := c.ObserveAuthorization(ctx, model)
	if err != nil || !observed.Drifted {
		t.Fatal("group override/native inheritance drift ignored", err)
	}
	before = provider.mutationCount()
	if _, err := c.ObserveAuthorization(ctx, model); err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != before {
		t.Fatal("Observe mutated group policy")
	}
	state, err = c.ReconcileAuthorization(ctx, model, state.ManagedObjects)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	group := provider.policies[groupID]
	provider.mu.Unlock()
	if group.GroupsClaim != "" || len(group.Groups) != 2 || group.Groups[0].ExtendChildren || group.Groups[1].ExtendChildren {
		t.Fatal("owned group policy not repaired")
	}
	model.Permissions[0].Principals = model.Permissions[0].Principals[:1]
	state, err = c.ReconcileAuthorization(ctx, model, state.ManagedObjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ManagedObjects.Policies) != 1 || state.ManagedObjects.Policies[0].Name != "readers#realm_roles" {
		t.Fatal("group removal did not preserve role policy")
	}
	provider.mu.Lock()
	_, foreign := provider.policies["foreign-group-policy"]
	_, removed := provider.policies[groupID]
	provider.mu.Unlock()
	if !foreign || removed {
		t.Fatal("cleanup ownership boundary differs")
	}
}

func TestGroupPolicyObservationRequiresGenericAndTypedConsistency(t *testing.T) {
	generic := authorizationPolicyRepresentation{ID: "policy", Name: "owned", Type: "group", Config: map[string]string{"groups": "[{\"id\":\"deleted-group\",\"extendChildren\":false}]"}}
	typed := authorizationPolicyRepresentation{ID: "policy", Name: "owned", Type: "group"}
	index := authorizationPolicyIndex{byID: map[string]authorizationPolicyRepresentation{"policy": generic}, byName: map[string]authorizationPolicyRepresentation{"owned": generic}}
	if err := mergeTypedAuthorizationPolicies(&index, "group", []authorizationPolicyRepresentation{typed}); err != nil {
		t.Fatal(err)
	}
	if !index.byID["policy"].Incomplete || policyEqual(index.byID["policy"], typed, "group") {
		t.Fatal("deleted provider group binding was treated as synchronized")
	}
	if err := mergeTypedAuthorizationPolicies(&index, "group", []authorizationPolicyRepresentation{typed, typed}); !errors.Is(err, ErrAuthorizationReadLimit) {
		t.Fatal("duplicate typed policy identity accepted", err)
	}
	generic.Config["groups"] = "malformed"
	if _, err := consistentGroupPolicy(generic, typed); err == nil {
		t.Fatal("malformed binding accepted")
	}
	payload, _ := json.Marshal(authorizationPolicyPayload(typed, "group"))
	if !strings.Contains(string(payload), "\"groupsClaim\":\"\"") {
		t.Fatal("group override clearing omitted")
	}
	payload, _ = json.Marshal(authorizationPolicyPayload(typed, "role"))
	if strings.Contains(string(payload), "groupsClaim") {
		t.Fatal("existing role payload changed")
	}
}

func TestOrganizationObservationPreservesDistinctDeclaredGroupBindings(t *testing.T) {
	names := map[string]string{"root-id": "organization/europe", "child-id": "organization/france"}
	policy := authorizationPolicyRepresentation{Groups: []AuthorizationGroupDefinition{{ID: "child-id"}, {ID: "root-id"}}}
	var first, reversed ObservedAuthorizationPolicy
	observePolicyPrincipals(policy, names, &first)
	first.Principals = semanticSet(first.Principals)
	policy.Groups[0], policy.Groups[1] = policy.Groups[1], policy.Groups[0]
	observePolicyPrincipals(policy, names, &reversed)
	reversed.Principals = semanticSet(reversed.Principals)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(reversed)
	if string(a) != string(b) || len(first.Principals) != 2 || strings.Contains(string(a), "-id") {
		t.Fatal("observation collapsed descendants, depended on order or exported UUIDs")
	}
}

func TestOrganizationPolicyJournalBudgetRefusesBeforeMutation(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	c := provider.client()
	model := authorizationTestModel()
	model.OwnerUID = "owner"
	model.Permissions = nil
	for i := range 128 {
		model.Permissions = append(model.Permissions, AuthorizationPermission{Name: fmt.Sprintf("permission-%03d", i), Scopes: []string{"invoices:read"}, Principals: []AuthorizationPrincipal{{Kind: "realm_role", Ref: "billing-reader"}, {Kind: "application", Ref: "other"}, {Kind: "organization", Ref: "europe", Groups: []AuthorizationGroupDefinition{{ID: "group"}}}}})
	}
	if _, err := c.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); err == nil {
		t.Fatal("expanded policy journal budget accepted")
	}
	if provider.mutationCount() != 0 {
		t.Fatal("journal budget discovered after provider mutation")
	}
}

func TestGenericManagedScopePermissionIsNotNativePolicy(t *testing.T) {
	permission := authorizationPermissionRepresentation{ID: "permission", Name: "read", Type: "scope"}
	owned := AuthorizationManagedObjects{Permissions: []AuthorizationManagedReference{{Name: "read", ID: "permission"}}}
	policies := authorizationPolicyIndex{byID: map[string]authorizationPolicyRepresentation{"permission": {ID: "permission", Name: "read", Type: "scope"}}}
	permissions := map[string]authorizationPermissionRepresentation{"read": permission}
	if hasNativeAuthorizationPolicy(policies, permissions, nil, owned) {
		t.Fatal("journal-owned generic scope permission classified as native")
	}
	policies.byID["foreign"] = authorizationPolicyRepresentation{ID: "foreign", Name: "external", Type: "group"}
	if !hasNativeAuthorizationPolicy(policies, permissions, nil, owned) {
		t.Fatal("foreign native policy hidden")
	}
	delete(policies.byID, "foreign")
	owned.Permissions[0].ID = "foreign-journal"
	if !hasNativeAuthorizationPolicy(policies, permissions, nil, owned) {
		t.Fatal("unproven generic permission hidden")
	}
}
