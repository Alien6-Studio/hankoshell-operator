package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func explanationFixture(t *testing.T) (Plan, State, ExplanationEvidence) {
	t.Helper()
	group := OrganizationGroup{Ref: "europe", Namespace: "iam", UID: "uid", ID: "private-group-id", Path: "/Europe"}
	child := OrganizationGroup{Ref: "france", Namespace: "iam", UID: "child-uid", ID: "private-child-id", Path: "/Europe/France"}
	model := contractModel()
	model.Permissions[0].Resources = []string{"invoice"}
	model.Permissions[0].Principals = []Principal{{Kind: "organization", Ref: "europe", IncludeDescendants: true, Organization: &ResolvedOrganizationPrincipal{Groups: []OrganizationGroup{group, child}, Graph: iamcontract.Hash(iamcontract.Version, "test", "graph", nil)}}, {Kind: "realm_role", Ref: "reader", PortableRef: "reader-ref"}, {Kind: "application", Ref: "portal", PortableRef: "portal-ref"}, {Kind: "service_account", Ref: "worker", PortableRef: "worker-ref"}}
	intent := Normalize(model)
	resolved, err := Resolve(intent, model)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Compile(intent, resolved, KeycloakEvidence(Capabilities{ScopeGrants: true, ResourceObjects: true, ResourceURIMatching: true, OrganizationPrincipals: true, OrganizationDescendants: true, RolePrincipals: true, ApplicationPrincipals: true, ServiceAccountPrincipals: true}), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	graph := &StructuralObservation{Enabled: true, Complete: true, Resources: []ObservedResource{{Name: "invoice", Present: true, Scopes: []string{"read"}}}, Policies: []ObservedPolicy{
		{Name: "access#organizations", Present: true, Owned: true, Type: "group", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Principals: []string{"organization/europe/extendChildren=false", "organization/france/extendChildren=false"}},
		{Name: "access#role:reader", Present: true, Owned: true, Type: "role", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Principals: []string{"realm_role/reader/required=false"}},
		{Name: "access#clients", Present: true, Owned: true, Type: "client", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Principals: []string{"client/worker", "client/portal"}},
	}, Permissions: []ObservedPermission{{Name: "access", Present: true, Owned: true, Type: "scope", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Resources: []string{"invoice"}, Scopes: []string{"read", "write"}, Policies: []string{"access#organizations", "access#role:reader", "access#clients"}}}}
	state := State{Structure: graph, Observation: iamcontract.Observation{Complete: true, StateHash: iamcontract.Hash(iamcontract.Version, "test", "observation", nil)}}
	evidence := ExplanationEvidence{Complete: true, Organizations: []VerifiedOrganization{{Group: group}, {Group: child, Ancestors: []OrganizationGroup{group}}}, Roles: []RoleBinding{{OrganizationRef: "europe", Target: "reader", Chain: []RoleStep{{Kind: "realm_role", Ref: "reader-ref"}}}, {OrganizationRef: "europe", Target: "reader", Chain: []RoleStep{{Kind: "realm_role", Ref: "finance"}, {Kind: "realm_role", Ref: "reader-ref"}}}, {OrganizationRef: "france", Target: "reader", Chain: []RoleStep{{Kind: "client_role", Client: "portal", Ref: "finance"}, {Kind: "realm_role", Ref: "reader-ref"}}}}}
	return plan, state, evidence
}
func TestExplanationUsesObservedBindingsAndPreservesAlternatives(t *testing.T) {
	plan, state, evidence := explanationFixture(t)
	result := Explain(plan, state, evidence, 7, true)
	if !result.Complete || result.Truncated || result.Source != "Applied" || len(result.Paths) != 8 {
		t.Fatalf("expected eight distinct proven alternatives: %+v", result)
	}
	kinds := map[string]bool{}
	for _, p := range result.Paths {
		if p.Resource != "invoice" || p.Action != "read" {
			t.Fatal("unobserved resource/scope Cartesian pair fabricated")
		}
		kinds[p.Relationship] = true
		if p.Relationship == "descendant" && !slices.Equal(p.Ancestry, []string{"europe", "france"}) {
			t.Fatal("ancestry not based on Hanko refs")
		}
	}
	for _, v := range []string{"direct", "descendant", "generic", "mapped_role", "mapped_composite_role", "mapped_client_role"} {
		if !kinds[v] {
			t.Fatal("origin lost", v)
		}
	}
	data, _ := json.Marshal(result)
	for _, sentinel := range []string{"private-group-id", "private-child-id", "/Europe", "username", "email", "bearer", "password"} {
		if strings.Contains(string(data), sentinel) {
			t.Fatal("private/provider subject data exported")
		}
	}
	if !iamcontract.ValidDigest(result.ExplanationHash) || !iamcontract.ValidDigest(result.SourceObservationHash) {
		t.Fatal("invalid evidence identities")
	}
	if Explain(plan, state, evidence, 7, false).Source != "Observed" {
		t.Fatal("Observe claimed application")
	}
	state.Observation.Drifted = true
	if Explain(plan, state, evidence, 7, true).Source != "Observed" {
		t.Fatal("drift claimed application")
	}
}
func TestExplanationDoesNotInventMissingOrNativePaths(t *testing.T) {
	for _, name := range []string{"native", "unknown", "extendChildren", "groupsClaim", "foreign", "negative", "missing", "provenance"} {
		t.Run(name, func(t *testing.T) {
			plan, state, e := explanationFixture(t)
			switch name {
			case "native":
				state.Structure.Native = true
			case "unknown":
				state.Structure.Permissions[0].UnknownBindings = 1
			case "extendChildren":
				state.Structure.Policies[0].Principals[1] = "organization/france/extendChildren=true"
			case "groupsClaim":
				state.Structure.Policies[0].GroupsClaimConfigured = true
			case "foreign":
				state.Structure.Policies[0].Owned = false
			case "negative":
				state.Structure.Permissions[0].Logic = "NEGATIVE"
			case "missing":
				state.Structure.Complete = false
				state.Structure.Permissions[0].Policies = []string{"unknown-policy"}
			case "provenance":
				e.Complete = false
				e.Roles = nil
			}
			result := Explain(plan, state, e, 7, true)
			if result.Complete {
				t.Fatal("unproven structural account declared complete")
			}
			for _, p := range result.Paths {
				if (name == "extendChildren" || name == "groupsClaim" || name == "foreign") && p.SourceKind == "organization" {
					t.Fatal("unsafe group provenance fabricated")
				}
			}
		})
	}
	plan, state, e := explanationFixture(t)
	state.Structure.Permissions[0].Resources = nil
	if len(Explain(plan, state, e, 7, false).Paths) != 8 {
		t.Fatal("scope-only permission exact resource expansion lost")
	}
}
func TestExplanationOrderDuplicatesAndTruncation(t *testing.T) {
	plan, state, e := explanationFixture(t)
	expected := Explain(plan, state, e, 7, true)
	rng := rand.New(rand.NewSource(42)) // #nosec G404 -- deterministic response-order fixture, not a credential.
	for range 20 {
		rng.Shuffle(len(state.Structure.Policies), func(i, j int) {
			state.Structure.Policies[i], state.Structure.Policies[j] = state.Structure.Policies[j], state.Structure.Policies[i]
		})
		rng.Shuffle(len(e.Organizations), func(i, j int) { e.Organizations[i], e.Organizations[j] = e.Organizations[j], e.Organizations[i] })
		rng.Shuffle(len(e.Roles), func(i, j int) { e.Roles[i], e.Roles[j] = e.Roles[j], e.Roles[i] })
		slices.Reverse(state.Structure.Permissions[0].Policies)
		if Explain(plan, state, e, 7, true).ExplanationHash != expected.ExplanationHash {
			t.Fatal("response order changed semantic identity")
		}
	}
	e.Roles = append(e.Roles, e.Roles[0])
	if Explain(plan, state, e, 7, true).ExplanationHash != expected.ExplanationHash {
		t.Fatal("duplicate semantic role path changed identity")
	}
	paths := []ExplanationPath{}
	for i := range 300 {
		paths = append(paths, ExplanationPath{Permission: "access", Resource: fmt.Sprintf("r-%03d", i), Action: "read", SourceKind: "organization", SourceRef: "europe", OrganizationRef: "europe", Relationship: "direct"})
	}
	result := normalizeExplanation(Explanation{Source: "Observed", Paths: paths, Complete: true})
	if len(result.Paths) != 256 || !result.Truncated || result.Complete {
		t.Fatal("path budget not visible")
	}
	slices.Reverse(paths)
	if normalizeExplanation(Explanation{Source: "Observed", Paths: paths, Complete: true}).ExplanationHash != result.ExplanationHash {
		t.Fatal("truncation subset depends on order")
	}
	over := paths[0]
	over.Ancestry = make([]string, 34)
	result = normalizeExplanation(Explanation{Paths: []ExplanationPath{over}, Complete: true})
	if !result.Truncated || result.Complete || len(result.Paths) != 0 {
		t.Fatal("partial ancestry falsely certified")
	}
}

func TestExplanationStreamingAndSerializedBudget(t *testing.T) {
	b := explanationBuilder{result: &Explanation{Complete: true}}
	for i := 299; i >= 0; i-- {
		b.addPath(ExplanationPath{Permission: "access", Resource: fmt.Sprintf("r-%03d", i), Action: "read", SourceKind: "realm_role", SourceRef: "reader", Relationship: "generic"})
	}
	if len(b.result.Paths) != 256 || !b.result.Truncated || b.result.Paths[0].Resource != "r-000" || b.result.Paths[255].Resource != "r-255" {
		t.Fatal("streaming deterministic first-256 contract violated")
	}
	x := Explanation{Complete: true, Paths: []ExplanationPath{}}
	for i := range 256 {
		p := ExplanationPath{Permission: "access", Resource: fmt.Sprintf("r-%03d", i), Action: "read", SourceKind: "realm_role", SourceRef: "reader", Relationship: "mapped_composite_role"}
		for range 33 {
			p.Ancestry = append(p.Ancestry, strings.Repeat("a", 255))
			p.RoleChain = append(p.RoleChain, RoleStep{Kind: "realm_role", Ref: strings.Repeat("r", 255)})
		}
		x.Paths = append(x.Paths, p)
	}
	x = normalizeExplanation(x)
	bytes, _ := json.Marshal(x)
	if len(bytes) > 192*1024 || !x.Truncated || x.Complete {
		t.Fatal("large valid paths can overflow status storage budget")
	}
}

func TestExplanationTruncatesThreeHundredObservedResourceActionPaths(t *testing.T) {
	model := contractModel()
	model.Resources = nil
	model.Scopes = nil
	model.Permissions = []Permission{{Name: "access", Principals: []Principal{{Kind: "application", Ref: "portal"}}}}
	graph := &StructuralObservation{Enabled: true, Complete: true, Policies: []ObservedPolicy{{Name: "access#clients", Type: "client", Present: true, Owned: true, Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Principals: []string{"client/resolved-portal"}}}}
	for i := range 6 {
		scope := fmt.Sprintf("action-%d", i)
		model.Scopes = append(model.Scopes, Scope{Name: scope})
		model.Permissions[0].Scopes = append(model.Permissions[0].Scopes, scope)
	}
	for i := range 50 {
		name := fmt.Sprintf("resource-%02d", i)
		model.Resources = append(model.Resources, Resource{Name: name, Scopes: model.Permissions[0].Scopes})
		graph.Resources = append(graph.Resources, ObservedResource{Name: name, Present: true, Scopes: model.Permissions[0].Scopes})
	}
	graph.Permissions = []ObservedPermission{{Name: "access", Type: "scope", Present: true, Owned: true, Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Scopes: model.Permissions[0].Scopes, Policies: []string{"access#clients"}}}
	plan := contractPlan(t, model, iamcontract.Preconditions{})
	state := State{Structure: graph, Observation: iamcontract.Observation{Complete: true, StateHash: iamcontract.Hash(iamcontract.Version, "test", "observation", nil)}}
	result := Explain(plan, state, ExplanationEvidence{Complete: true}, 1, true)
	if !result.Truncated || result.Complete || len(result.Paths) != 256 {
		t.Fatal("actual observed paths were not bounded")
	}
	slices.Reverse(graph.Resources)
	slices.Reverse(graph.Permissions[0].Scopes)
	if Explain(plan, state, ExplanationEvidence{Complete: true}, 1, true).ExplanationHash != result.ExplanationHash {
		t.Fatal("actual observed truncation depends on response order")
	}
}
