package roles

import (
	"errors"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func rolePlan(t *testing.T, i Intent, r ResolvedReferences, pre iamcontract.Preconditions) Plan {
	t.Helper()
	p, e := Compile(i, r, KeycloakEvidence(), pre)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestRoleCanonicalIntentNativeAndPreconditions(t *testing.T) {
	i := Intent{RealmRef: "realm", Name: "editor", Composites: []string{"b", "a"}}
	r := ResolvedReferences{Realm: "realm", Owner: "uid", Attributes: map[string][]string{"b": {"first", "second"}, "a": {"team"}}}
	p := rolePlan(t, i, r, iamcontract.Preconditions{})
	i.Composites = []string{"a", "b"}
	i.Composite = true
	r.Attributes = map[string][]string{"a": {"team"}, "b": {"first", "second"}}
	if rolePlan(t, i, r, iamcontract.Preconditions{Generation: 2}).Identity() != p.Identity() {
		t.Fatal("map/order/defaults change identity")
	}
	r.Attributes["b"] = []string{"second", "first"}
	q := rolePlan(t, i, r, iamcontract.Preconditions{})
	if q.Identity().Intent != p.Identity().Intent || q.Identity().Plan == p.Identity().Plan {
		t.Fatal("native ordered metadata not bound separately")
	}
	r.Attributes = nil
	n := rolePlan(t, i, r, iamcontract.Preconditions{})
	r.Attributes = map[string][]string{}
	if rolePlan(t, i, r, iamcontract.Preconditions{}).Identity() != n.Identity() {
		t.Fatal("nil/empty native map differ")
	}
	i.Description = "changed"
	if rolePlan(t, i, r, iamcontract.Preconditions{}).Identity().Intent == n.Identity().Intent {
		t.Fatal("semantic change omitted")
	}
	if !errors.Is(n.Validate(rolePlan(t, n.intent, n.resolved, iamcontract.Preconditions{Generation: 1})), iamcontract.ErrStale) {
		t.Fatal("stale generation accepted")
	}
	if (Plan{}).Validate(Plan{}) == nil {
		t.Fatal("uncompiled plan accepted")
	}
	iamconformance.NoSecrets(t, []string{"fixture-secret", "fixture-private-key"}, p, n, q)
}
func TestRoleCapabilitiesAndNativeConflict(t *testing.T) {
	i := Intent{RealmRef: "realm", Name: "editor", Composite: true}
	r := ResolvedReferences{Realm: "realm", Owner: "uid"}
	for _, e := range []CapabilityEvidence{{Supported: Capabilities{RealmRoles: true}}, {Supported: Capabilities{}}, {Supported: Capabilities{true, true, true}, Findings: []iamcontract.Finding{{Classification: iamcontract.Unsupported}}}} {
		if _, err := Compile(i, r, e, iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrRejected) {
			t.Fatal("unsupported capability accepted")
		}
	}
	for _, key := range []string{OwnerAttribute, "client_secret", "password", "bearer-token"} {
		r.Attributes = map[string][]string{key: {"fixture-secret"}}
		if _, err := Compile(i, r, KeycloakEvidence(), iamcontract.Preconditions{}); err == nil {
			t.Fatal("native conflict/credential input accepted")
		}
	}
}
