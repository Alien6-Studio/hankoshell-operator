package iamconformance

import (
	"encoding/json"
	"testing"
)

func TestPortableObservationRefusesUnboundOrStaleProof(t *testing.T) {
	corpus, err := ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	f := corpus.Fixtures[2]
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	status := map[string]any{"phase": "Ready", "backendKind": "authentik", "observedGeneration": 1, "evaluatedGeneration": 1, "appliedGeneration": 1, "observationGeneration": 1, "observationComplete": true, "driftState": "InSync", "intentHash": f.IntentIdentity, "evaluatedPlanHash": digest, "appliedPlanHash": digest, "observationPlanHash": digest, "observedStateHash": digest}
	check := func(s map[string]any) error {
		raw, _ := json.Marshal(map[string]any{"metadata": map[string]any{"generation": 1}, "status": s})
		return CheckPortableObservation(f, "authentik", raw)
	}
	if check(status) != nil {
		t.Fatal("complete reviewed evidence rejected")
	}
	for field, invalid := range map[string]any{"backendKind": "keycloak", "appliedGeneration": 0, "observationComplete": false, "intentHash": digest, "observedStateHash": "invalid", "observationPlanHash": "different"} {
		t.Run(field, func(t *testing.T) {
			old := status[field]
			status[field] = invalid
			if check(status) == nil {
				t.Fatal("unbound portable observation accepted")
			}
			status[field] = old
		})
	}
}

func TestPortableRefusalRequiresCurrentFinding(t *testing.T) {
	corpus, err := ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	f := corpus.Fixtures[0]
	for _, raw := range []string{
		`{"metadata":{"generation":1},"status":{"phase":"Error"}}`,
		`{"metadata":{"generation":1},"status":{"phase":"Error","conditions":[{"type":"Synced","status":"False","reason":"ExperimentalUnsupported","observedGeneration":0}]}}`,
		`{"metadata":{"generation":1},"status":{"phase":"Error","appliedPlanHash":"stale"}}`,
	} {
		if CheckPortableObservation(f, "authentik", []byte(raw)) == nil {
			t.Fatal("unproved refusal accepted")
		}
	}
}
