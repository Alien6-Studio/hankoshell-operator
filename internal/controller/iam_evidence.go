package controller

import (
	"errors"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The public statuses stay flat for v1alpha1 compatibility. This private view
// shares update semantics without serializing a plan or accepting public hashes.
type iamEvidence struct {
	processed, evaluated, applied, observationGeneration                                         *int64
	contract, backend, intent, evaluatedPlan, appliedPlan, observedState, observationPlan, drift *string
	complete                                                                                     *bool
	qualification                                                                                *api.IAMCapabilityEvidence
}

func authorizationEvidence(s *api.HankoResourceServerStatus) iamEvidence {
	return iamEvidence{&s.ObservedGeneration, &s.EvaluatedGeneration, &s.AppliedGeneration, &s.ObservationGeneration, &s.ContractVersion, &s.BackendKind, &s.IntentHash, &s.EvaluatedPlanHash, &s.AppliedPlanHash, &s.ObservedStateHash, &s.ObservationPlanHash, &s.DriftState, &s.ObservationComplete, &s.CapabilityEvidence}
}
func roleEvidence(s *api.HankoRoleStatus) iamEvidence {
	return iamEvidence{&s.ObservedGeneration, &s.EvaluatedGeneration, &s.AppliedGeneration, &s.ObservationGeneration, &s.ContractVersion, &s.BackendKind, &s.IntentHash, &s.EvaluatedPlanHash, &s.AppliedPlanHash, &s.ObservedStateHash, &s.ObservationPlanHash, &s.DriftState, &s.ObservationComplete, &s.CapabilityEvidence}
}
func (e iamEvidence) process(generation int64, observe bool) {
	*e.processed = generation
	// Old appliedPlanHash was written after HTTP acknowledgement alone. It is
	// not upgraded into new proof; the next Manage read-back re-establishes it.
	if observe || *e.applied == 0 || *e.contract != string(iamcontract.Version) {
		*e.applied = 0
		*e.appliedPlan = ""
	}
}
func (e iamEvidence) evaluate(generation int64, identity iamcontract.PlanIdentity) {
	*e.evaluated = generation
	*e.contract = string(identity.Contract)
	*e.backend = string(identity.Backend)
	*e.intent = string(identity.Intent)
	*e.evaluatedPlan = string(identity.Plan)
	*e.qualification = api.IAMCapabilityEvidence{Source: "adapter-and-real-qualification", QualificationWindow: "26.7.5,26.8.0"}
}
func (e iamEvidence) observe(generation int64, identity iamcontract.PlanIdentity, observation iamcontract.Observation) {
	if !iamcontract.ValidDigest(string(observation.StateHash)) {
		return
	}
	*e.observationGeneration = generation
	*e.observationPlan = string(identity.Plan)
	*e.observedState = string(observation.StateHash)
	*e.complete = observation.Complete
	*e.drift = "Unknown"
	if observation.Drifted {
		*e.drift = "Drifted"
	} else if observation.Complete {
		*e.drift = "InSync"
	}
}
func (e iamEvidence) apply(generation int64, identity iamcontract.PlanIdentity) {
	*e.applied = generation
	*e.appliedPlan = string(identity.Plan)
}
func observationError(o iamcontract.Observation) error {
	if !o.Complete || !iamcontract.ValidDigest(string(o.StateHash)) {
		return iamcontract.ErrObservationIncomplete
	}
	if o.Drifted {
		return iamcontract.ErrDrift
	}
	return nil
}
func iamFailureReason(err error, fallback string) string {
	switch {
	case errors.Is(err, iamcontract.ErrStale):
		return "StalePlan"
	case errors.Is(err, iamcontract.ErrObservationIncomplete):
		return "ObservationIncomplete"
	case errors.Is(err, iamcontract.ErrDrift):
		return "DriftDetected"
	case errors.Is(err, iamcontract.ErrRejected):
		return "Unsupported"
	default:
		return fallback
	}
}
func iamCondition(conditions *[]metav1.Condition, generation int64, kind string, status metav1.ConditionStatus, reason, message string) {
	setCondition(conditions, kind, status, reason, iamcontract.Bound(iamcontract.Finding{Message: message}).Message)
	for i := range *conditions {
		if (*conditions)[i].Type == kind {
			(*conditions)[i].ObservedGeneration = generation
		}
	}
}

type iamEvaluationRejected struct {
	cause             error
	identity          iamcontract.PlanIdentity
	authorizationCaps authorization.Capabilities
	roleCaps          roles.Capabilities
	findings          []iamcontract.Finding
}

func (e iamEvaluationRejected) Error() string {
	return "IAM execution semantics rejected before mutation"
}
func (e iamEvaluationRejected) Unwrap() error { return e.cause }
