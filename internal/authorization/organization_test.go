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
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
)

func TestOrganizationIntentAndSealedResolvedIdentity(t *testing.T) {
	m := contractModel()
	m.Permissions[0].Principals = []Principal{{Kind: "organization", Ref: "europe"}}
	initial := Normalize(m).Identity()
	p := &m.Permissions[0].Principals[0]
	p.Organization = &ResolvedOrganizationPrincipal{Groups: []OrganizationGroup{{Ref: "europe", Namespace: "iam", UID: "uid", ID: "provider-id", Path: "/Europe"}}, Graph: iamcontract.Hash(iamcontract.Version, "test", "graph", nil)}
	if Normalize(m).Identity() != initial {
		t.Fatal("provider IDs or paths entered portable intent")
	}
	i := Normalize(m)
	r, err := Resolve(i, m)
	if err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{ScopeGrants: true, ResourceObjects: true, ResourceURIMatching: true, OrganizationPrincipals: true, OrganizationDescendants: true}
	plan, err := Compile(i, r, KeycloakEvidence(caps), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Organization.Groups[0].ID = "different-id"
	if plan.resolved.model.Permissions[0].Principals[0].Organization.Groups[0].ID != "provider-id" {
		t.Fatal("sealed plan aliases input group evidence")
	}
	r, err = Resolve(i, m)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Compile(i, r, KeycloakEvidence(caps), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Identity().Intent != plan.Identity().Intent || !errors.Is(plan.Validate(changed), iamcontract.ErrStale) {
		t.Fatal("provider resolution omitted from plan identity")
	}
	p.IncludeDescendants = true
	if Normalize(m).Identity() == initial {
		t.Fatal("descendant semantics omitted from intent")
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), "provider-id") || strings.Contains(string(encoded), "/Europe") {
		t.Fatal("private resolved evidence serialized publicly")
	}
	caps.OrganizationDescendants = false
	i = Normalize(m)
	r, _ = Resolve(i, m)
	if _, err := Compile(i, r, KeycloakEvidence(caps), iamcontract.Preconditions{}); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatal("unsupported descendant capability accepted", err)
	}
}

func TestExistingAuthorizationIdentityRemainsCompatible(t *testing.T) {
	// Recorded from the unchanged v0.3/main compiler before adding this principal.
	identity := contractPlan(t, contractModel(), iamcontract.Preconditions{}).Identity()
	if identity.Intent != "sha256:a59170eefc418059f747f1eea60d75f9cf73fdd61020ba056b539d0606dd0c20" || identity.Plan != "sha256:a94f0766fa11e613cb53282fc787dce04ec8e542319b2631681044d61a895307" {
		t.Fatal("existing role/application intent or required-capability plan bytes changed")
	}
}

func TestOrganizationAbsentFalseAndContradictoryDefaults(t *testing.T) {
	var absent, explicit Principal
	if json.Unmarshal([]byte(`{"Kind":"organization","Ref":"europe"}`), &absent) != nil || json.Unmarshal([]byte(`{"Kind":"organization","Ref":"europe","IncludeDescendants":false}`), &explicit) != nil {
		t.Fatal("principal decoding failed")
	}
	m := contractModel()
	m.Permissions[0].Principals = []Principal{absent}
	first := Normalize(m)
	m.Permissions[0].Principals = []Principal{explicit}
	if Normalize(m).Identity() != first.Identity() {
		t.Fatal("omitted/false descendants changed portable identity")
	}
	m.Permissions[0].Principals = []Principal{absent, {Kind: "organization", Ref: "europe", IncludeDescendants: true}}
	if !errors.Is(validateModel(Normalize(m).model), iamcontract.ErrRejected) {
		t.Fatal("contradictory map-key principals accepted by internal compiler")
	}
}

func TestOrganizationProviderOwnershipUsesExactSingletonMarkers(t *testing.T) {
	expected := OrganizationGroup{Ref: "europe", Namespace: "iam", UID: "uid", ID: "group", Name: "Europe", Path: "/Europe"}
	for _, test := range []struct {
		name, code string
		attrs      map[string][]string
		status     int
		path       string
	}{
		{"owned", "", map[string][]string{organization.OwnerName: {"europe"}, organization.OwnerNamespace: {"iam"}, organization.OwnerUID: {"uid"}}, 200, "/Europe"},
		{"markerless", "OrganizationOwnershipConflict", nil, 200, "/Europe"},
		{"foreign uid", "OrganizationOwnershipConflict", map[string][]string{organization.OwnerName: {"europe"}, organization.OwnerNamespace: {"iam"}, organization.OwnerUID: {"foreign"}}, 200, "/Europe"},
		{"ambiguous uid", "OrganizationOwnershipConflict", map[string][]string{organization.OwnerName: {"europe"}, organization.OwnerNamespace: {"iam"}, organization.OwnerUID: {"uid", "foreign"}}, 200, "/Europe"},
		{"wrong namespace", "OrganizationOwnershipConflict", map[string][]string{organization.OwnerName: {"europe"}, organization.OwnerNamespace: {"other"}, organization.OwnerUID: {"uid"}}, 200, "/Europe"},
		{"wrong name", "OrganizationOwnershipConflict", map[string][]string{organization.OwnerName: {"other"}, organization.OwnerNamespace: {"iam"}, organization.OwnerUID: {"uid"}}, 200, "/Europe"},
		{"missing view-users", "OrganizationReadUnavailable", nil, 403, "/Europe"},
		{"hierarchy moved", "OrganizationHierarchyMismatch", map[string][]string{organization.OwnerName: {"europe"}, organization.OwnerNamespace: {"iam"}, organization.OwnerUID: {"uid"}}, 200, "/Africa/Europe"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/realms/master/") {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet {
					writes++
				}
				w.WriteHeader(test.status)
				if test.status == 403 {
					_, _ = w.Write([]byte("private-provider-body"))
					return
				}
				_ = json.NewEncoder(w).Encode(keycloak.Group{ID: "group", Name: "Europe", Path: test.path, Attributes: test.attrs})
			}))
			defer server.Close()
			d := NewKeycloakDriver(keycloak.New(server.URL, "operator", "fixture-secret", keycloak.WithInsecureHTTP()))
			_, err := d.ReadOrganizationGroup(context.Background(), "managed", expected)
			if test.code == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var failure OrganizationError
				if !errors.As(err, &failure) || failure.Code != test.code {
					t.Fatal("wrong refusal", err)
				}
			}
			if writes != 0 || (err != nil && strings.Contains(err.Error(), "private-provider-body")) {
				t.Fatal("group verification wrote or exposed provider body")
			}
		})
	}
}
