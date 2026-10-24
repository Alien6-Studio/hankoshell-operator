package iamconformance

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func TestReviewedPublicCorpusCarriesFrozenNonSecretEvidence(t *testing.T) {
	corpus, err := ReadPublicCorpus("public-initial")
	if err != nil {
		t.Fatal(err)
	}
	if corpus.Predecessor != "" || corpus.Limitation != "NoPublishedPredecessor" || len(corpus.Fixtures) != 6 {
		t.Fatal("fixture inventory invents public predecessor evidence")
	}
	kinds := map[string]bool{}
	for _, fixture := range corpus.Fixtures {
		kinds[fixture.Kind] = true
		if fixture.Identity.Contract != iamcontract.Version || fixture.Identity.Backend != iamcontract.Keycloak ||
			!iamcontract.ValidDigest(string(fixture.Identity.Intent)) || !iamcontract.ValidDigest(string(fixture.Identity.Plan)) {
			t.Fatal("corpus lost independently frozen compiler evidence")
		}
		for _, raw := range []json.RawMessage{fixture.Spec, fixture.DefaultedSpec, fixture.Status} {
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil || len(fields) == 0 {
				t.Fatal("stored/defaulted/public status object is missing")
			}
			for _, private := range []string{"clientSecret", "password", "access_token", "refresh_token", "privateKey"} {
				if _, exists := fields[private]; exists {
					t.Fatal("public fixture contains a private payload field")
				}
			}
		}
	}
	if len(kinds) != 3 || !kinds["HankoApplication"] || !kinds["HankoRole"] || !kinds["HankoResourceServer"] {
		t.Fatal("corpus no longer matches the selected compiler domains")
	}
	encoded, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || regexp.MustCompile(`eyJ[\w-]+\.[\w-]+\.[\w-]+`).Match(encoded) {
		t.Fatal("public fixture contains credential material")
	}
}

func TestPublicCorpusRefusesUndeclaredAndOutsideInputs(t *testing.T) {
	for _, name := range []string{"not-a-published-corpus", "../..", "/private", ""} {
		if corpus, err := ReadPublicCorpus(name); err == nil || len(corpus.Fixtures) != 0 {
			t.Fatal("reader accepted an undeclared or outside corpus")
		}
	}
}
