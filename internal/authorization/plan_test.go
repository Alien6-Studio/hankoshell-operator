package authorization

import (
	"errors"
	"slices"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func contractModel() Model {
	return Model{Name: "api", Realm: "realm-ref", Audience: "urn:api", ApplicationRef: "application-ref", Scopes: []Scope{{Name: "read"}, {Name: "write"}}, Resources: []Resource{{Name: "invoice", URIs: []string{"/b", "/a"}, Scopes: []string{"read", "write"}}}, Permissions: []Permission{{Name: "access", Scopes: []string{"write", "read"}, Principals: []Principal{{Kind: "application", Ref: "web-ref"}, {Kind: "realm_role", Ref: "reader-ref"}}}}}
}
func contractPlan(t *testing.T, m Model, pre iamcontract.Preconditions) Plan {
	t.Helper()
	i := Normalize(m)
	resolved := canonicalModel(m)
	resolved.ApplicationRef = "client-id"
	resolved.Realm = "provider-realm"
	for j := range resolved.Permissions {
		for k := range resolved.Permissions[j].Principals {
			resolved.Permissions[j].Principals[k].Ref = "resolved-" + resolved.Permissions[j].Principals[k].Ref
		}
	}
	r, err := Resolve(i, resolved)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(i, r, KeycloakEvidence(Capabilities{ScopeGrants: true, ResourceObjects: true, ResourceURIMatching: true, RolePrincipals: true, ApplicationPrincipals: true}), pre)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAuthorizationIdentityCanonicalizationAndIsolation(t *testing.T) {
	m := contractModel()
	p := contractPlan(t, m, iamcontract.Preconditions{})
	slices.Reverse(m.Scopes)
	slices.Reverse(m.Resources[0].URIs)
	slices.Reverse(m.Resources[0].Scopes)
	slices.Reverse(m.Permissions[0].Scopes)
	slices.Reverse(m.Permissions[0].Principals)
	if contractPlan(t, m, iamcontract.Preconditions{Generation: 10}).Identity() != p.Identity() {
		t.Fatal("semantic sets/preconditions changed identity")
	}
	m.Resources[0].DisplayName = "Invoices"
	if contractPlan(t, m, iamcontract.Preconditions{}).Identity() == p.Identity() {
		t.Fatal("semantic change omitted")
	}
	m = contractModel()
	empty := m
	m.Resources = nil
	empty.Resources = []Resource{}
	if contractPlan(t, m, iamcontract.Preconditions{}).Identity() != contractPlan(t, empty, iamcontract.Preconditions{}).Identity() {
		t.Fatal("nil/empty differ")
	}
	if p.Identity().Intent == p.Identity().Plan {
		t.Fatal("intent/plan conflated")
	}
	// Input mutation after compilation cannot change a sealed plan.
	original := p.Identity()
	pSource := contractModel()
	q := contractPlan(t, pSource, iamcontract.Preconditions{})
	pSource.Permissions[0].Principals[0].Ref = "changed"
	if q.Identity() != original || q.Validate(q) != nil {
		t.Fatal("plan aliases input")
	}
	iamconformance.NoSecrets(t, []string{"fixture-client-secret", "fixture-bearer-token"}, p, p.Identity())
}
func TestAuthorizationPreconditionsAndCapabilitiesFailClosed(t *testing.T) {
	p := contractPlan(t, contractModel(), iamcontract.Preconditions{ResourceUID: "one", Generation: 1})
	for _, pre := range []iamcontract.Preconditions{{ResourceUID: "two", Generation: 1}, {ResourceUID: "one", Generation: 2}, {ResourceUID: "one", Generation: 1, References: "changed"}, {ResourceUID: "one", Generation: 1, Authority: "changed"}, {ResourceUID: "one", Generation: 1, Ownership: "changed"}} {
		if !errors.Is(p.Validate(contractPlan(t, contractModel(), pre)), iamcontract.ErrStale) {
			t.Fatal("stale preconditions accepted")
		}
	}
	if (Plan{}).Validate(Plan{}) == nil {
		t.Fatal("uncompiled plan accepted")
	}
	i := Normalize(contractModel())
	r, _ := Resolve(i, contractModel())
	e := KeycloakEvidence(Capabilities{})
	if _, err := Compile(i, r, e, iamcontract.Preconditions{}); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatal("capabilities bypassed")
	}
	e = p.evidence
	e.Findings = []iamcontract.Finding{{Classification: iamcontract.Lossy}}
	if _, err := Compile(i, r, e, iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrRejected) {
		t.Fatal("loss silently accepted")
	}
	r.model.Resources[0].Type = "changed"
	if _, err := Compile(i, r, p.evidence, iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrStale) {
		t.Fatal("resolver changed intent semantics")
	}
}
