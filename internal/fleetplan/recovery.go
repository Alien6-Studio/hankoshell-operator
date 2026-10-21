package fleetplan

import (
	"reflect"
	"time"
)

// VerifyReference proves historical content, never current execution authority.
// The reference must already be checkpointed locally. Its signature and original
// validity are checked at acceptance, then its key is checked against CURRENT
// local trust. A revoked or expired key cannot authorize rollback indirectly.
func VerifyReference(envelope, trust []byte, target Target, now, acceptedAt time.Time, checkpoint Checkpoint) (Verified, error) {
	if checkpoint.Sequence < 1 || acceptedAt.IsZero() || acceptedAt.After(now.Add(ClockSkew)) {
		return Verified{}, Refusal("FleetRollbackReferenceInvalid")
	}
	v, err := Verify(envelope, trust, target, acceptedAt, checkpoint)
	if err != nil {
		return Verified{}, err
	}
	if v.Identity() != checkpoint.Identity || v.Plan().Sequence != checkpoint.Sequence {
		return Verified{}, Refusal("FleetRollbackReferenceInvalid")
	}
	var t Trust
	if !decodeTrust(trust, &t) {
		return Verified{}, Refusal("FleetTrustInvalid")
	}
	if _, err := approvedKey(t, v.plan, now); err != nil {
		return Verified{}, err
	}
	return v, nil
}

// VerifyRollback binds a newly signed higher sequence to exact retained desired
// state, including source and all capability requirements. A reference cannot
// weaken the policy or introduce extra content under an old identity.
func VerifyRollback(candidate, reference Verified) error {
	p, old := candidate.plan, reference.plan
	if candidate.identity == "" || reference.identity == "" || p.RollbackOf != reference.identity ||
		p.Sequence <= old.Sequence || p.Target != old.Target || p.Source != old.Source ||
		p.ContractVersion != old.ContractVersion || p.Mode != old.Mode || p.MinimumOperatorVersion != old.MinimumOperatorVersion ||
		!reflect.DeepEqual(p.Requirements, old.Requirements) || !reflect.DeepEqual(p.ObjectRequirements, old.ObjectRequirements) ||
		!reflect.DeepEqual(p.Content, old.Content) {
		return Refusal("FleetRollbackReferenceInvalid")
	}
	return nil
}

// RecoveryTime refuses clock regression and sticky expiry independently of
// cryptographic validation. The high-water time is durable tenant evidence.
func RecoveryTime(now, verifiedAt time.Time, expired bool) error {
	if expired {
		return Refusal("FleetPlanExpired")
	}
	if now.Before(verifiedAt.Add(-ClockSkew)) {
		return Refusal("FleetClockRegression")
	}
	return nil
}
