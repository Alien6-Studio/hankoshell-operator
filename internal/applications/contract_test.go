package applications

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func testApplicationPlan(t *testing.T, i Intent, r ResolvedReferences, pre iamcontract.Preconditions) Plan {
	t.Helper()
	if i.RealmRef == "" {
		i.RealmRef = "realm"
	}
	if i.ClientID == "" {
		i.ClientID = "portal"
	}
	if r.Realm == "" {
		r.Realm = "resolved-realm"
	}
	if r.Owner == "" {
		r.Owner = "uid"
	}
	p, err := Compile(i, r, KeycloakEvidence(), pre)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestApplicationIntentDefaultsAndCanonicalSets(t *testing.T) {
	a := Intent{RealmRef: "realm", ClientID: "portal", Roles: []Role{{Name: "b"}, {Name: "a"}}, RedirectURIs: []string{"https://portal.test/b", "https://portal.test/a"}}
	b := a
	b.Protocol = "oidc"
	b.Pattern = "web"
	b.Roles = []Role{{Name: "a"}, {Name: "b"}}
	b.RedirectURIs = []string{"https://portal.test/a", "https://portal.test/b"}
	if IntentIdentity(a) != IntentIdentity(b) {
		t.Fatal("legacy omission/set order changed semantic identity")
	}
	b.ClientID = "other"
	if IntentIdentity(a) == IntentIdentity(b) {
		t.Fatal("application identity omitted from intent")
	}
	saml := Intent{RealmRef: "realm", ClientID: "https://portal.test/saml", Protocol: "saml", SAML: &SAML{ACS: []string{"https://portal.test/acs"}, SignedAssertions: true}}
	p := testApplicationPlan(t, saml, ResolvedReferences{}, iamcontract.Preconditions{})
	if p.Identity().Intent == IntentIdentity(a) {
		t.Fatal("protocol absent from semantic identity")
	}
	// Inputs cannot mutate a sealed plan after compilation.
	saml.SAML.ACS[0] = "https://foreign.test/acs"
	if p.intent.SAML.ACS[0] != "https://portal.test/acs" {
		t.Fatal("mutable caller-owned plan semantics")
	}
}
func TestApplicationPlanFreshnessAndPrivateSerialization(t *testing.T) {
	i := Intent{RealmRef: "realm", ClientID: "portal", Theme: "brand"}
	r := ResolvedReferences{Realm: "realm", Owner: "uid", Attributes: map[string]string{"team": "private-metadata"}}
	pre := iamcontract.Preconditions{ResourceUID: "uid", Generation: 1, References: "realm-reference", Authority: "local-authority"}
	p := testApplicationPlan(t, i, r, pre)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"private-metadata", "portal", "brand", "local-authority"} {
		if strings.Contains(string(data), value) {
			t.Fatal("plan serialization exposed private inputs")
		}
	}
	for _, change := range []func(*Intent, *ResolvedReferences, *iamcontract.Preconditions){
		func(_ *Intent, _ *ResolvedReferences, p *iamcontract.Preconditions) { p.Generation++ },
		func(_ *Intent, _ *ResolvedReferences, p *iamcontract.Preconditions) { p.ResourceUID = "replacement" },
		func(_ *Intent, _ *ResolvedReferences, p *iamcontract.Preconditions) {
			p.References = "theme-or-realm-change"
		},
		func(_ *Intent, _ *ResolvedReferences, p *iamcontract.Preconditions) {
			p.Authority = "observe-or-import"
		},
		func(_ *Intent, r *ResolvedReferences, _ *iamcontract.Preconditions) { r.Owner = "foreign" },
		func(i *Intent, _ *ResolvedReferences, _ *iamcontract.Preconditions) { i.ClientID = "other" },
	} {
		nextI, nextR, nextPre := i, r, pre
		change(&nextI, &nextR, &nextPre)
		next := testApplicationPlan(t, nextI, nextR, nextPre)
		if !errors.Is(p.Validate(next), iamcontract.ErrStale) {
			t.Fatal("stale execution accepted")
		}
	}
}
func TestSAMLRejectsIncompatibleSemanticsBeforeProviderExecution(t *testing.T) {
	base := Intent{RealmRef: "realm", ClientID: "https://portal.test/saml", Protocol: "saml", SAML: &SAML{ACS: []string{"https://portal.test/acs"}, SignedAssertions: true, NameIDFormat: "persistent"}}
	for name, change := range map[string]func(*Intent){
		"SPA": func(i *Intent) { i.Pattern = "spa" }, "web": func(i *Intent) { i.Pattern = "web" }, "M2M": func(i *Intent) { i.Pattern = "m2m" },
		"OIDC callbacks":     func(i *Intent) { i.RedirectURIs = []string{"https://portal.test/callback"} },
		"OIDC logout":        func(i *Intent) { i.PostLogoutURIs = []string{"https://portal.test/logout"} },
		"OIDC claims":        func(i *Intent) { i.Claims = []Claim{{Name: "claim"}} },
		"OIDC mappings":      func(i *Intent) { i.IdentityMappings = []IdentityMapping{{Name: "mapping"}} },
		"OIDC scopes":        func(i *Intent) { i.ScopesManaged = true },
		"secret rotation":    func(i *Intent) { i.Rotation = &Rotation{} },
		"secret projection":  func(i *Intent) { i.Projections = []Projection{{Namespace: "app", Name: "secret"}} },
		"unsigned assertion": func(i *Intent) { i.SAML.SignedAssertions = false },
		"missing SAML":       func(i *Intent) { i.SAML = nil },
		"unknown NameID":     func(i *Intent) { i.SAML.NameIDFormat = "arbitrary" },
	} {
		t.Run(name, func(t *testing.T) {
			i := Normalize(base)
			change(&i)
			if _, err := Compile(i, ResolvedReferences{Realm: "realm", Owner: "uid"}, KeycloakEvidence(), iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrRejected) {
				t.Fatal("incompatible SAML semantics accepted")
			}
		})
	}
	for _, key := range []string{"saml.server.signature", "saml_assertion_consumer_url_post", "saml.signing.private.key", "hanko.sh/application-owner", "hanko.app", "hanko.sh/resource-server-ownership", "protocol", "login_theme", "post.logout.redirect.uris", "client_secret", "client.secret.creation.time", "private-key"} {
		if _, err := Compile(base, ResolvedReferences{Realm: "realm", Owner: "uid", Attributes: map[string]string{key: "must-not-enter-plan"}}, KeycloakEvidence(), iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrRejected) {
			t.Fatalf("reserved metadata accepted: %s", key)
		}
	}
}
func TestExactHTTPSACSValidation(t *testing.T) {
	for _, uri := range []string{"https://portal.test/acs", "https://localhost:9443/acs", "https://portal.test/acs%20callback"} {
		if !ValidACS(uri) {
			t.Fatalf("valid exact ACS rejected: %s", uri)
		}
	}
	for _, uri := range []string{"", "http://localhost/acs", "https://user:password@portal.test/acs", "https://portal.test/*", "https://portal.test/acs#fragment", "https://portal.test/acs?query=1", "https://portal.test:65536/acs", "https://portal.test:0/acs", "https://portal.test/%0a", "https://portal.test/a\\b", strings.Repeat("a", 2049)} {
		if ValidACS(uri) {
			t.Fatalf("unsafe ACS accepted: %s", uri)
		}
	}
}
