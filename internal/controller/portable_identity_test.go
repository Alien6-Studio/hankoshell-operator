package controller

import (
	"encoding/json"
	"slices"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authentik"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func TestPortableApplicationIdentityAcrossBackends(t *testing.T) {
	corpus, err := iamconformance.ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Fixtures {
		if fixture.Manifest.Kind != "HankoApplication" {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			var spec api.HankoApplicationSpec
			if json.Unmarshal(fixture.Manifest.Spec, &spec) != nil {
				t.Fatal("invalid application fixture")
			}
			intent := applicationIntent(spec)
			refs := applications.ResolvedReferences{Realm: spec.RealmRef, Owner: "portable-owner", Attributes: spec.Attributes}
			findings := authentik.Classify(intent, refs)
			expected := fixture.Expected["authentik"]
			if expected.Classification == iamcontract.Unsupported {
				if len(findings) != 1 || findings[0].Code != expected.Reason {
					t.Fatalf("unsupported finding differs from reviewed fixture: %v", findings)
				}
				return
			}
			if len(findings) != 0 {
				t.Fatal("lossless fixture rejected")
			}
			kc, err := applications.Compile(intent, refs, applications.KeycloakEvidence(), iamcontract.Preconditions{})
			if err != nil {
				t.Fatal(err)
			}
			other, err := applications.CompileForBackend(iamcontract.Authentik, intent, refs, authentik.Evidence(), iamcontract.Preconditions{})
			if err != nil {
				t.Fatal(err)
			}
			if kc.Identity().Intent != other.Identity().Intent || kc.Identity().Plan == other.Identity().Plan {
				t.Fatal("portable meaning or execution authority crossed backend boundary")
			}
			reversed := intent
			reversed.RedirectURIs = append([]string(nil), intent.RedirectURIs...)
			slices.Reverse(reversed.RedirectURIs)
			same, err := applications.CompileForBackend(iamcontract.Authentik, reversed, refs, authentik.Evidence(), iamcontract.Preconditions{})
			if err != nil || same.Identity() != other.Identity() {
				t.Fatal("unordered portable intent changed identity")
			}
			changed := intent
			changed.ClientID += "-changed"
			if applications.IntentIdentity(changed) == other.Identity().Intent {
				t.Fatal("semantic difference did not change identity")
			}
			// The native driver also refuses a sealed plan from another backend before
			// touching its nil client; identity cannot be repurposed as write authority.
			if _, err := applications.NewKeycloakDriver(nil).Ensure(t.Context(), other); err == nil {
				t.Fatal("foreign execution backend accepted")
			}
		})
	}
}

func TestExperimentalJournalRejectsAmbiguousWireInput(t *testing.T) {
	for _, raw := range []string{`{"version":1,"version":2}`, `{"version":1,"unknown":"private-sentinel"}`, `{"version":1} {"version":2}`, `null`} {
		var journal providerJournal
		err := decodeProviderJSON([]byte(raw), &journal)
		if raw == "null" {
			continue
		} // Semantic completeness is checked against the current bound journal.
		if err == nil {
			t.Fatal("ambiguous or unknown journal accepted")
		}
		iamconformance.NoSecrets(t, []string{"private-sentinel"}, err.Error())
	}
}
