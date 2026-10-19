package iamconformance

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var portableDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// CheckPortableObservation checks the reviewed data contract, independent of the
// Kubernetes client or provider executor. It never includes a remote body in errors.
func CheckPortableObservation(f PortableFixture, provider string, raw []byte) error {
	expected, ok := f.Expected[provider]
	if !ok {
		return fmt.Errorf("unclassified portable provider")
	}
	var value struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Status portableStatus `json:"status"`
	}
	if json.Unmarshal(raw, &value) != nil || value.Status.Phase != expected.Phase {
		return fmt.Errorf("portable observation phase differs")
	}
	if expected.PlanEvidence {
		if err := checkPortableExecution(f, provider, value.Metadata.Generation, value.Status); err != nil {
			return err
		}
	}
	return checkPortableRefusal(expected, value.Metadata.Generation, value.Status)
}

func checkPortableRefusal(expected PortableExpectation, generation int64, s portableStatus) error {
	if expected.Classification == "unsupported" && (s.Applied != "" || s.Complete) {
		return fmt.Errorf("unsupported intent published applied evidence")
	}
	if expected.Classification == "unsupported" {
		found := false
		for _, c := range s.Conditions {
			if c.Type == "Synced" && c.Status == "False" && c.Reason == expected.StatusReason && c.Generation == generation {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unsupported fixture lacks the reviewed current finding")
		}
	}
	return nil
}

type portableStatus struct {
	Phase                 string `json:"phase"`
	Backend               string `json:"backendKind"`
	ObservedGeneration    int64  `json:"observedGeneration"`
	EvaluatedGeneration   int64  `json:"evaluatedGeneration"`
	AppliedGeneration     int64  `json:"appliedGeneration"`
	ObservationGeneration int64  `json:"observationGeneration"`
	Intent                string `json:"intentHash"`
	Evaluated             string `json:"evaluatedPlanHash"`
	Applied               string `json:"appliedPlanHash"`
	Observation           string `json:"observationPlanHash"`
	State                 string `json:"observedStateHash"`
	Complete              bool   `json:"observationComplete"`
	Drift                 string `json:"driftState"`
	Conditions            []struct {
		Type       string `json:"type"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
		Generation int64  `json:"observedGeneration"`
	} `json:"conditions"`
}

func checkPortableExecution(f PortableFixture, provider string, g int64, s portableStatus) error {
	for field, valid := range map[string]bool{"generation": g > 0, "backend": s.Backend == provider, "observedGeneration": s.ObservedGeneration == g, "evaluatedGeneration": s.EvaluatedGeneration == g, "appliedGeneration": s.AppliedGeneration == g, "observationGeneration": s.ObservationGeneration == g, "complete": s.Complete, "drift": s.Drift == "InSync", "plan": s.Evaluated == s.Applied && s.Applied == s.Observation} {
		if !valid {
			return fmt.Errorf("portable execution evidence is incomplete: %s", field)
		}
	}
	for _, hash := range []string{s.Intent, s.Evaluated, s.State} {
		if !portableDigest.MatchString(hash) {
			return fmt.Errorf("portable execution digest is invalid")
		}
	}
	if f.IntentIdentity != "" && s.Intent != string(f.IntentIdentity) {
		return fmt.Errorf("portable compiler identity differs from reviewed data")
	}
	return nil
}
