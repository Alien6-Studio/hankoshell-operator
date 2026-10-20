package applications

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func TestExplicitWebOriginsPreserveEmptyAndCanonicalReviewedSets(t *testing.T) {
	base := Intent{RealmRef: "realm", Protocol: "oidc", Pattern: "spa", ClientID: "portal"}
	legacy := testApplicationPlan(t, base, ResolvedReferences{}, iamcontract.Preconditions{})
	if !slices.Equal(desired(legacy).WebOrigins, []string{"+"}) {
		t.Fatal("omitted origins changed the legacy redirect-derived policy")
	}
	for _, origins := range [][]string{{}, nil, {"https://portal.test", "http://localhost:3000"}} {
		intent := base
		intent.WebOrigins = &origins
		plan := testApplicationPlan(t, intent, ResolvedReferences{}, iamcontract.Preconditions{})
		want := stringSet(origins)
		if !slices.Equal(desired(plan).WebOrigins, want) || desired(plan).WebOrigins == nil {
			t.Fatal("explicit origin set was replaced with the legacy default or null")
		}
		if legacy.Identity().Intent == plan.Identity().Intent {
			t.Fatal("explicit CORS policy is absent from reviewed intent")
		}
		encoded, _ := json.Marshal(plan.intent)
		if len(origins) == 0 && !strings.Contains(string(encoded), `"WebOrigins":[]`) {
			t.Fatal("explicit empty origins were lost during plan normalization")
		}
		if len(origins) > 0 {
			reversed := slices.Clone(origins)
			slices.Reverse(reversed)
			intent.WebOrigins = &reversed
			if IntentIdentity(intent) != plan.Identity().Intent {
				t.Fatal("reordering an origin set invalidated semantic identity")
			}
			origins[0] = "https://changed.test"
			if !slices.Equal(desired(plan).WebOrigins, want) {
				t.Fatal("caller mutation changed a sealed CORS plan")
			}
		}
	}
}

func TestExplicitWebOriginsRejectCredentialAndWildcardPoliciesBeforeExecution(t *testing.T) {
	for _, value := range []string{"*", "https://*.example.test", "https://user:password@example.test", "https://example.test/a*b", "https://example.test/*/other", "https://example.test?token=private", "https://example.test?", "https://example.test#", "https://example.test#private", "ftp://example.test", "https://example.test:", "https://example.test:0", "https://example.test:65536", "https://example.test:invalid", "https://example.test\x7f", "https://example.test\n", ""} {
		t.Run(value, func(t *testing.T) {
			origins := []string{value}
			_, err := Compile(Intent{RealmRef: "realm", ClientID: "portal", Pattern: "spa", WebOrigins: &origins}, ResolvedReferences{Realm: "realm", Owner: "uid"}, KeycloakEvidence(), iamcontract.Preconditions{})
			if !errors.Is(err, iamcontract.ErrRejected) {
				t.Fatal("unqualified origin policy reached an executable plan")
			}
		})
	}
	maxOrigin := "https://portal.test/" + strings.Repeat("a", 255-len("https://portal.test/"))
	if !ValidWebOrigins([]string{maxOrigin}) || ValidWebOrigins([]string{maxOrigin + "a"}) {
		t.Fatal("native CORS storage budget is not enforced at its exact boundary")
	}
	for _, value := range []string{"+", "https://portal.test", "http://localhost:3000", "https://[::1]:8443", "https://portal.test/path", "https://portal.test/", "https://portal.test/login/*"} {
		if !ValidWebOrigins([]string{value}) {
			t.Fatal("qualified origin rejected")
		}
	}
	if ValidWebOrigins(make([]string, 65)) {
		t.Fatal("unbounded origin set accepted")
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = "https://portal.test"
	}
	if _, err := Compile(Intent{RealmRef: "realm", ClientID: "portal", Pattern: "spa", WebOrigins: &tooMany}, ResolvedReferences{Realm: "realm", Owner: "uid"}, KeycloakEvidence(), iamcontract.Preconditions{}); !errors.Is(err, iamcontract.ErrRejected) {
		t.Fatal("origin input budget was checked only after deduplication")
	}
	origins := []string{}
	_, err := Compile(Intent{RealmRef: "realm", ClientID: "https://portal.test/saml", Protocol: "saml", WebOrigins: &origins, SAML: &SAML{ACS: []string{"https://portal.test/acs"}, SignedAssertions: true}}, ResolvedReferences{Realm: "realm", Owner: "uid"}, KeycloakEvidence(), iamcontract.Preconditions{})
	if !errors.Is(err, iamcontract.ErrRejected) {
		t.Fatal("SAML accepted an OIDC CORS policy")
	}
}

func TestObservedWebOriginsDetectDriftAndBindMigrationReview(t *testing.T) {
	origins := []string{"https://portal.test", "http://localhost:3000"}
	plan := testApplicationPlan(t, Intent{Protocol: "oidc", Pattern: "spa", WebOrigins: &origins}, ResolvedReferences{}, iamcontract.Preconditions{})
	actual, complete := observedClient(desired(plan), plan)
	if !complete || applicationDrift(plan, observedApplication{Complete: true, Client: actual}) {
		t.Fatal("preserved explicit origins reported drift")
	}
	before, _ := json.Marshal(actual)
	actual.WebOrigins = []string{"https://changed.test"}
	after, _ := json.Marshal(actual)
	if slices.Equal(before, after) || !applicationDrift(plan, observedApplication{Complete: true, Client: actual}) {
		t.Fatal("native origin change did not invalidate observation and reconciliation")
	}
}
