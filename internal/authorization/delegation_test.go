package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func delegationModel() Model {
	m := contractModel()
	m.Permissions[0].Resources = []string{"invoice"}
	m.Permissions[0].Delegation = &Delegation{Actor: Principal{Kind: "service_account", Ref: "actor"}, Subject: Principal{Kind: "application", Ref: "subject"}, MaxDepth: 1, MaxTTLSeconds: 120}
	return m
}

// A synthetic capability is used only to exercise the neutral sealed plan. The
// real Keycloak adapter must still reject that plan at every entry point.
func delegationPlan(t *testing.T, m Model, nativeActor string, pre iamcontract.Preconditions) Plan {
	t.Helper()
	intent := Normalize(m)
	resolved := canonicalModel(m)
	d := resolved.Permissions[0].Delegation
	d.Actor.PortableRef, d.Subject.PortableRef = d.Actor.Ref, d.Subject.Ref
	d.Actor.Ref, d.Subject.Ref = nativeActor, "native-subject"
	references, err := Resolve(intent, resolved)
	if err != nil {
		t.Fatal(err)
	}
	caps, _ := NewKeycloakDriver(nil).Capabilities(context.Background(), "")
	caps.BoundedDelegation = true
	plan, err := Compile(intent, references, KeycloakEvidence(caps), pre)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestDelegationIntentSealsIdentitiesBoundsAndReferences(t *testing.T) {
	m := delegationModel()
	plan := delegationPlan(t, m, "native-actor", iamcontract.Preconditions{ResourceUID: "owner"})
	if !plan.required.BoundedDelegation {
		t.Fatal("delegation capability absent from plan")
	}
	for _, change := range []struct {
		name string
		edit func(*Delegation)
	}{
		{"actor", func(d *Delegation) { d.Actor.Ref = "another-actor" }},
		{"actor kind", func(d *Delegation) { d.Actor.Kind = "application" }},
		{"subject", func(d *Delegation) { d.Subject.Ref = "another-subject" }},
		{"depth", func(d *Delegation) { d.MaxDepth = 2 }},
		{"lifetime", func(d *Delegation) { d.MaxTTLSeconds = 60 }},
		{"task authorization", func(d *Delegation) { d.TaskAuthorization = "required" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			model := delegationModel()
			change.edit(model.Permissions[0].Delegation)
			if Normalize(model).Identity() == plan.Identity().Intent {
				t.Fatal("delegation change omitted from intent")
			}
		})
	}
	changed := delegationPlan(t, m, "replacement-native-actor", iamcontract.Preconditions{ResourceUID: "owner"})
	if changed.Identity().Intent != plan.Identity().Intent || changed.Identity().Plan == plan.Identity().Plan || !errors.Is(plan.Validate(changed), iamcontract.ErrStale) {
		t.Fatal("native identity change did not invalidate plan")
	}
	m.Permissions[0].Delegation.Actor.Ref = "mutated"
	m.Permissions[0].Delegation.MaxDepth = 4
	if plan.intent.model.Permissions[0].Delegation.Actor.Ref != "actor" || plan.resolved.model.Permissions[0].Delegation.MaxDepth != 1 {
		t.Fatal("sealed delegation aliases caller data")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "native-") || strings.Contains(string(encoded), "Actor") {
		t.Fatal("public plan serialized execution details")
	}
	other := delegationModel()
	other.Permissions[0].Delegation.Actor.Ref = "replacement"
	if _, err := Resolve(Normalize(delegationModel()), other); !errors.Is(err, iamcontract.ErrStale) {
		t.Fatal("resolver replaced portable actor")
	}
}

func TestDelegationValidationAndProviderCapabilityRefuseBeforePlan(t *testing.T) {
	for _, edit := range []func(*Permission){
		func(p *Permission) { p.Resources = nil },
		func(p *Permission) { p.Delegation.MaxDepth = 0 },
		func(p *Permission) { p.Delegation.MaxDepth = 5 },
		func(p *Permission) { p.Delegation.MaxTTLSeconds = 0 },
		func(p *Permission) { p.Delegation.MaxTTLSeconds = 601 },
		func(p *Permission) { p.Delegation.Actor.Kind = "realm_role" },
		func(p *Permission) { p.Delegation.Subject.Kind = "human" },
		func(p *Permission) { p.Delegation.Subject.Ref = "" },
		func(p *Permission) { p.Delegation.Subject = p.Delegation.Actor },
	} {
		m := delegationModel()
		edit(&m.Permissions[0])
		if !errors.Is(validateModel(m), iamcontract.ErrRejected) {
			t.Fatal("invalid delegation accepted")
		}
	}
	m := delegationModel()
	i := Normalize(m)
	r, err := Resolve(i, m)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := NewKeycloakDriver(nil).Capabilities(context.Background(), "realm")
	if err != nil || caps.BoundedDelegation {
		t.Fatal("Keycloak advertises unqualified bounded delegation")
	}
	plan, err := Compile(i, r, KeycloakEvidence(caps), iamcontract.Preconditions{})
	if !errors.Is(err, ErrCapabilityUnsupported) || plan.Identity().Plan != "" {
		t.Fatal("unsupported delegation produced executable plan")
	}
	caps.BoundedDelegation = true
	caps.ServiceAccountPrincipals = false
	if _, err := Compile(i, r, KeycloakEvidence(caps), iamcontract.Preconditions{}); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatal("actor identity capability was not required")
	}
}

func TestKeycloakDelegationCannotBeDroppedByObserveWriteAdoptionOrCleanup(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "provider must not be contacted", http.StatusInternalServerError)
	}))
	defer server.Close()
	driver := NewKeycloakDriver(keycloak.New(server.URL, "fixture", "fixture", keycloak.WithInsecureHTTP()))
	m := delegationModel()
	plan := delegationPlan(t, m, "native-actor", iamcontract.Preconditions{ResourceUID: "owner"})
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{"observe", func() error { _, err := driver.Observe(context.Background(), plan); return err }},
		{"reconcile", func() error { _, err := driver.Reconcile(context.Background(), plan, ManagedObjects{}); return err }},
		{"delete", func() error {
			return driver.DeleteOwned(context.Background(), m, ManagedObjects{ResourceServerID: "foreign"}, "owner")
		}},
		{"adoption", func() error { _, err := KeycloakAdoptionModel(m, "owner"); return err }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if !errors.Is(operation.call(), ErrCapabilityUnsupported) {
				t.Fatal("entry point ignored delegation")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("unsupported delegation reached provider transport")
	}
}

func TestDelegationRuntimeAndUIDsArePrivateButSealExecution(t *testing.T) {
	model := delegationModel()
	intent := Normalize(model)
	compile := func(model Model) Plan {
		t.Helper()
		resolved, err := Resolve(intent, model)
		if err != nil {
			t.Fatal(err)
		}
		caps, _ := NewKeycloakDriver(nil).Capabilities(context.Background(), "")
		caps.BoundedDelegation = true
		plan, err := Compile(intent, resolved, KeycloakEvidence(caps), iamcontract.Preconditions{ResourceUID: "resource-owner"})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	model.DelegationContext = &ResolvedDelegationContext{AudienceUID: "api-uid", Runtime: iamcontract.Digest("sha256:" + strings.Repeat("a", 64))}
	model.Permissions[0].Delegation.Actor.SoftwareUID = "actor-uid"
	model.Permissions[0].Delegation.Subject.SoftwareUID = "subject-uid"
	before := compile(model)
	if Normalize(model).Identity() != intent.Identity() {
		t.Fatal("runtime evidence contaminated portable intent")
	}
	for _, change := range []struct {
		name string
		edit func(*Model)
	}{
		{"audience UID", func(m *Model) { m.DelegationContext.AudienceUID = "replacement-api" }},
		{"actor UID", func(m *Model) { m.Permissions[0].Delegation.Actor.SoftwareUID = "replacement-actor" }},
		{"subject UID", func(m *Model) { m.Permissions[0].Delegation.Subject.SoftwareUID = "replacement-subject" }},
		{"live authority", func(m *Model) { m.DelegationContext.Runtime = iamcontract.Digest("sha256:" + strings.Repeat("b", 64)) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := canonicalModel(model)
			change.edit(&changed)
			if Normalize(changed).Identity() != intent.Identity() {
				t.Fatal("private identity changed portable intent")
			}
			after := compile(changed)
			if after.Identity().Plan == before.Identity().Plan || !errors.Is(before.Validate(after), iamcontract.ErrStale) {
				t.Fatal("changed execution evidence retained approval authority")
			}
		})
	}
	model.DelegationContext.AudienceUID = "caller-mutated"
	if before.resolved.model.DelegationContext.AudienceUID != "api-uid" {
		t.Fatal("sealed plan aliases caller evidence")
	}
}
