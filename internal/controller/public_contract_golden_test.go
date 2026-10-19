package controller

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

const publicCorpusPath = "../iamconformance/testdata/public-0.1.0/corpus.json"

func decodePublicSpec(t *testing.T, data []byte, value any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		t.Fatal(err)
	}
}

func publicFixtureIdentity(t *testing.T, fixture iamconformance.PublicFixture, owner string) iamcontract.PlanIdentity {
	t.Helper()
	pre := iamcontract.Preconditions{ResourceUID: owner, Generation: 1}
	switch fixture.Kind {
	case "HankoApplication":
		var spec api.HankoApplicationSpec
		decodePublicSpec(t, fixture.Spec, &spec)
		plan, err := applications.Compile(applicationIntent(spec), applications.ResolvedReferences{Realm: "resolved-realm", Owner: owner}, applications.KeycloakEvidence(), pre)
		if err != nil {
			t.Fatal(err)
		}
		return plan.Identity()
	case "HankoRole":
		var spec api.HankoRoleSpec
		decodePublicSpec(t, fixture.Spec, &spec)
		plan, err := roles.Compile(roles.Intent{RealmRef: spec.RealmRef, Name: spec.Name, Description: spec.Description, Composite: spec.Composite, Composites: spec.Composites}, roles.ResolvedReferences{Realm: "resolved-realm", Owner: owner}, roles.KeycloakEvidence(), pre)
		if err != nil {
			t.Fatal(err)
		}
		return plan.Identity()
	case "HankoResourceServer":
		var spec api.HankoResourceServerSpec
		decodePublicSpec(t, fixture.Spec, &spec)
		obj := &api.HankoResourceServer{Spec: spec}
		obj.Name = fixture.Name
		intent := authorizationIntent(obj)
		model := authorization.Model{Name: obj.Name, Realm: "resolved-realm", ApplicationRef: "resolved-client", Audience: spec.Audience, DisplayName: spec.DisplayName}
		for _, scope := range spec.Scopes {
			model.Scopes = append(model.Scopes, authorization.Scope{Name: scope.Name, Description: scope.Description})
		}
		for _, resource := range spec.Resources {
			model.Resources = append(model.Resources, authorization.Resource{Name: resource.Name, DisplayName: resource.DisplayName, Type: resource.Type, URIs: resource.URIs, Scopes: resource.Scopes})
		}
		for _, permission := range spec.Permissions {
			p := authorization.Permission{Name: permission.Name, Resources: permission.Resources, Scopes: permission.Scopes}
			for _, principal := range permission.Principals {
				p.Principals = append(p.Principals, authorization.Principal{Kind: principal.Kind, Ref: "resolved-" + principal.Ref})
			}
			model.Permissions = append(model.Permissions, p)
		}
		resolved, err := authorization.Resolve(intent, model)
		if err != nil {
			t.Fatal(err)
		}
		caps := authorization.Capabilities{ScopeGrants: true, ResourceObjects: true, ResourceURIMatching: true, ApplicationPrincipals: true, RolePrincipals: true}
		plan, err := authorization.Compile(intent, resolved, authorization.KeycloakEvidence(caps), pre)
		if err != nil {
			t.Fatal(err)
		}
		return plan.Identity()
	default:
		t.Fatal("unreviewed public compiler domain")
		return iamcontract.PlanIdentity{}
	}
}

func TestPublicContractPlanGoldens(t *testing.T) {
	corpus, err := iamconformance.ReadPublicCorpus("public-0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	update := os.Getenv("UPDATE_PUBLIC_FIXTURES") == "1"
	if update && os.Getenv("CI") != "" {
		t.Fatal("CI cannot rewrite reviewed public goldens")
	}
	for i := range corpus.Fixtures {
		fixture := &corpus.Fixtures[i]
		t.Run(fixture.Name, func(t *testing.T) {
			actual := publicFixtureIdentity(t, *fixture, corpus.OwnerUID)
			if update {
				fixture.Identity = actual
			}
			if actual != fixture.Identity {
				t.Fatalf("reviewed plan identity drift (-stored +current):\n- %+v\n+ %+v", fixture.Identity, actual)
			}
			for _, variant := range append(slices.Clone(fixture.Equivalent), fixture.DefaultedSpec) {
				other := *fixture
				other.Spec = variant
				if got := publicFixtureIdentity(t, other, corpus.OwnerUID); got != actual {
					t.Fatalf("order/default-equivalent intent changed plan: %+v != %+v", got, actual)
				}
			}
			data, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			var evidence map[string]string
			if err := json.Unmarshal(data, &evidence); err != nil || len(evidence) != 4 || evidence["contract"] != string(iamcontract.Version) {
				t.Fatal("public plan evidence wire shape changed")
			}
			if fixture.Kind != "HankoResourceServer" {
				replaced := publicFixtureIdentity(t, *fixture, "replaced-owner")
				if replaced.Plan == actual.Plan || replaced.Intent != actual.Intent {
					t.Fatal("owner UID must bind execution without changing portable intent")
				}
			}
		})
	}
	if update && !t.Failed() {
		data, err := json.MarshalIndent(corpus, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Clean(publicCorpusPath), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublicCanonicalizationPreservesAuthorityDistinctions(t *testing.T) {
	base := applications.Intent{RealmRef: "realm", ClientID: "portal"}
	empty := base
	empty.RedirectURIs = []string{}
	if applications.IntentIdentity(base) != applications.IntentIdentity(empty) {
		t.Fatal("nil/empty callback sets differ")
	}
	empty.ScopesManaged = true
	if applications.IntentIdentity(base) == applications.IntentIdentity(empty) {
		t.Fatal("unmanaged scopes collapsed into explicitly managed empty scopes")
	}
	changed := base
	changed.ClientID = " portal "
	if applications.IntentIdentity(base) == applications.IntentIdentity(changed) {
		t.Fatal("identifier whitespace silently changed authority")
	}
	i := roles.Intent{RealmRef: "realm", Name: "reader", Composites: []string{"writer", "writer"}}
	j := i
	j.Composites = []string{"writer"}
	if !reflect.DeepEqual(roles.Normalize(i), roles.Normalize(j)) {
		t.Fatal("additive composite membership is not a semantic set")
	}
}

func TestPublicLeafOwnershipMarkersRemainReadable(t *testing.T) {
	data, err := os.ReadFile("../iamconformance/testdata/public-0.1.0/ownership.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ApplicationAttribute string `json:"applicationAttribute"`
		RoleAttribute        string `json:"roleAttribute"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ApplicationAttribute != applications.OwnerAttribute || fixture.RoleAttribute != roles.OwnerAttribute {
		t.Fatal("public UID ownership marker changed without a migration corpus")
	}
}
