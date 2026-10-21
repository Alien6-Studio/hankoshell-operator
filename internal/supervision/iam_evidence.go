package supervision

import (
	"encoding/json"
	"slices"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const MaxIAMEvidenceResources = 64

// IAMEvidenceSnapshot is evidence only. It is deliberately not added to the
// existing heartbeat wire schema until the receiving Hub is qualified for it.
type IAMEvidenceSnapshot struct {
	Resources []IAMEvidence `json:"resources"`
	Truncated bool          `json:"truncated"`
}
type IAMEvidence struct {
	Kind                  string            `json:"kind"`
	Namespace             string            `json:"namespace"`
	Name                  string            `json:"name"`
	UID                   string            `json:"uid"`
	DesiredGeneration     int64             `json:"desiredGeneration"`
	ProcessedGeneration   int64             `json:"processedGeneration"`
	EvaluatedGeneration   int64             `json:"evaluatedGeneration"`
	AppliedGeneration     int64             `json:"appliedGeneration"`
	ContractVersion       string            `json:"contractVersion"`
	BackendKind           string            `json:"backendKind"`
	IntentHash            string            `json:"intentHash,omitempty"`
	EvaluatedPlanHash     string            `json:"evaluatedPlanHash,omitempty"`
	AppliedPlanHash       string            `json:"appliedPlanHash,omitempty"`
	ObservedStateHash     string            `json:"observedStateHash,omitempty"`
	ObservationGeneration int64             `json:"observationGeneration"`
	ObservationPlanHash   string            `json:"observationPlanHash,omitempty"`
	ObservationComplete   bool              `json:"observationComplete"`
	DriftState            string            `json:"driftState"`
	Findings              IAMFindingSummary `json:"findings"`
}
type IAMFindingSummary struct {
	Lossless    int  `json:"lossless"`
	Lossy       int  `json:"lossy"`
	Unsupported int  `json:"unsupported"`
	ReadOnly    int  `json:"readOnly"`
	Truncated   bool `json:"truncated"`
}

func findingSummary(findings []api.AuthorizationFinding) IAMFindingSummary {
	var s IAMFindingSummary
	s.Truncated = len(findings) > iamcontract.MaxFindings
	for _, f := range findings {
		switch f.Classification {
		case "lossless":
			s.Lossless++
		case "lossy":
			s.Lossy++
		case "unsupported":
			s.Unsupported++
		}
		if f.ReadOnly {
			s.ReadOnly++
		}
		if f.Code == "finding_budget_exceeded" {
			s.Truncated = true
		}
	}
	// Saturation is independent of input order, including adversarial status.
	s.Lossless = min(s.Lossless, iamcontract.MaxFindings)
	s.Lossy = min(s.Lossy, iamcontract.MaxFindings-s.Lossless)
	s.Unsupported = min(s.Unsupported, iamcontract.MaxFindings-s.Lossless-s.Lossy)
	s.ReadOnly = min(s.ReadOnly, iamcontract.MaxFindings)
	return s
}
func safeIAMDigest(value string) string {
	if iamcontract.ValidDigest(value) {
		return value
	}
	return ""
}

// BuildIAMEvidence is deterministic and bounded. It exports explicit evidence
// only, never annotations, native attributes, condition messages or owned IDs.
// Kubernetes status is untrusted input here too; this DTO grants no authority.
func BuildIAMEvidence(roles []api.HankoRole, servers []api.HankoResourceServer) IAMEvidenceSnapshot {
	result := IAMEvidenceSnapshot{Resources: []IAMEvidence{}}
	for _, obj := range roles {
		s := obj.Status
		result.Resources = append(result.Resources, IAMEvidence{Kind: "HankoRole", Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID), DesiredGeneration: obj.Generation, ProcessedGeneration: s.ObservedGeneration, EvaluatedGeneration: s.EvaluatedGeneration, AppliedGeneration: s.AppliedGeneration, ContractVersion: s.ContractVersion, BackendKind: s.BackendKind, IntentHash: s.IntentHash, EvaluatedPlanHash: s.EvaluatedPlanHash, AppliedPlanHash: s.AppliedPlanHash, ObservedStateHash: s.ObservedStateHash, ObservationGeneration: s.ObservationGeneration, ObservationPlanHash: s.ObservationPlanHash, ObservationComplete: s.ObservationComplete, DriftState: s.DriftState, Findings: findingSummary(s.Findings)})
	}
	for _, obj := range servers {
		s := obj.Status
		result.Resources = append(result.Resources, IAMEvidence{Kind: "HankoResourceServer", Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID), DesiredGeneration: obj.Generation, ProcessedGeneration: s.ObservedGeneration, EvaluatedGeneration: s.EvaluatedGeneration, AppliedGeneration: s.AppliedGeneration, ContractVersion: s.ContractVersion, BackendKind: s.BackendKind, IntentHash: s.IntentHash, EvaluatedPlanHash: s.EvaluatedPlanHash, AppliedPlanHash: s.AppliedPlanHash, ObservedStateHash: s.ObservedStateHash, ObservationGeneration: s.ObservationGeneration, ObservationPlanHash: s.ObservationPlanHash, ObservationComplete: s.ObservationComplete, DriftState: s.DriftState, Findings: findingSummary(s.Findings)})
	}
	for i := range result.Resources {
		r := &result.Resources[i]
		r.Namespace = iamBoundedIdentity(r.Namespace, 63)
		r.Name = iamBoundedIdentity(r.Name, 253)
		r.UID = iamBoundedIdentity(r.UID, 128)
		if r.ContractVersion != string(iamcontract.Version) {
			r.ContractVersion = ""
		}
		if r.BackendKind != "keycloak" {
			r.BackendKind = ""
		}
		r.IntentHash = safeIAMDigest(r.IntentHash)
		r.EvaluatedPlanHash = safeIAMDigest(r.EvaluatedPlanHash)
		r.AppliedPlanHash = safeIAMDigest(r.AppliedPlanHash)
		r.ObservedStateHash = safeIAMDigest(r.ObservedStateHash)
		r.ObservationPlanHash = safeIAMDigest(r.ObservationPlanHash)
		if r.DriftState != "InSync" && r.DriftState != "Drifted" {
			r.DriftState = "Unknown"
		}
		if r.AppliedGeneration == 0 {
			r.AppliedPlanHash = ""
		}
	}
	slices.SortFunc(result.Resources, func(a, b IAMEvidence) int {
		if n := strings.Compare(a.Kind+"/"+a.Namespace+"/"+a.Name+"/"+a.UID, b.Kind+"/"+b.Namespace+"/"+b.Name+"/"+b.UID); n != 0 {
			return n
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	result.Truncated = len(result.Resources) > MaxIAMEvidenceResources
	result.Resources = result.Resources[:min(len(result.Resources), MaxIAMEvidenceResources)]
	return result
}

func iamBoundedIdentity(value string, limit int) string {
	runes := []rune(value)
	return string(runes[:min(len(runes), limit)])
}
