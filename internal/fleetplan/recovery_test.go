package fleetplan_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
)

func TestFleetReferencedRollback(t *testing.T) {
	f := newFixture(t)
	raw, trust := f.signed(t, nil), marshal(t, f.trust)
	old, err := fleetplan.Verify(raw, trust, f.plan.Target, f.now, fleetplan.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := fleetplan.Checkpoint{Sequence: 1, Identity: old.Identity()}
	// Reference remains provable after original validity, without reviving it.
	reference, err := fleetplan.VerifyReference(raw, trust, f.plan.Target, f.now.Add(15*time.Minute), f.now, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleetplan.Verify(raw, trust, f.plan.Target, f.now.Add(15*time.Minute), checkpoint); fleetplan.Reason(err) != "FleetPlanExpired" {
		t.Fatal("expired execution revived")
	}
	f.plan.Sequence = 3
	f.plan.RollbackOf = old.Identity()
	candidate, err := fleetplan.Verify(f.signed(t, nil), trust, f.plan.Target, f.now, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleetplan.VerifyRollback(candidate, reference); err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{"content", "source", "policy", "target", "sequence", "reference", "empty"} {
		t.Run(boundary, func(t *testing.T) {
			changed := f
			changed.plan = candidate.Plan()
			switch boundary {
			case "content":
				changed.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(changed.plan.Content.Realms[0]), "true", "false", 1))
			case "source":
				changed.plan.Source.Revision = strings.Repeat("c", 40)
			case "policy":
				changed.plan.Mode = "partial"
			case "target":
				changed.plan.Target.TenantUID = "other"
			case "sequence":
				changed.plan.Sequence = 1
			case "reference":
				changed.plan.RollbackOf = "sha256:" + strings.Repeat("c", 64)
			case "empty":
				if fleetplan.VerifyRollback(fleetplan.Verified{}, reference) == nil {
					t.Fatal("zero authority")
				}
				return
			}
			v, err := fleetplan.Verify(changed.signed(t, nil), trust, changed.plan.Target, f.now, fleetplan.Checkpoint{})
			if err != nil {
				t.Fatal(err)
			}
			if fleetplan.Reason(fleetplan.VerifyRollback(v, reference)) != "FleetRollbackReferenceInvalid" {
				t.Fatal("rollback changed retained state")
			}
		})
	}
	for _, boundary := range []string{"zero", "future", "wrong-identity", "wrong-sequence", "tampered", "revoked", "expired-key"} {
		t.Run(boundary, func(t *testing.T) {
			cp, at, data, keys := checkpoint, f.now, raw, trust
			switch boundary {
			case "zero":
				cp.Sequence = 0
			case "future":
				at = f.now.Add(20 * time.Minute)
			case "wrong-identity":
				cp.Identity = "sha256:" + strings.Repeat("e", 64)
			case "wrong-sequence":
				cp.Sequence = 2
			case "tampered":
				data = []byte(`{}`)
			case "revoked":
				revoked := f.trust
				revoked.Keys = nil
				keys = marshal(t, revoked)
			case "expired-key":
				expired := f.trust
				expired.Keys = append([]fleetplan.Key(nil), f.trust.Keys...)
				expired.Keys[0].NotAfter = f.now.Add(time.Minute)
				keys = marshal(t, expired)
			}
			if _, err := fleetplan.VerifyReference(data, keys, f.plan.Target, f.now.Add(15*time.Minute), at, cp); err == nil {
				t.Fatal("unverified reference accepted")
			}
		})
	}
}

func TestFleetRecoveryClockAndStickyExpiry(t *testing.T) {
	now := time.Now()
	if err := fleetplan.RecoveryTime(now, now, false); err != nil {
		t.Fatal(err)
	}
	if err := fleetplan.RecoveryTime(now.Add(-fleetplan.ClockSkew), now, false); err != nil {
		t.Fatal(err)
	}
	if fleetplan.Reason(fleetplan.RecoveryTime(now.Add(-time.Minute), now, false)) != "FleetClockRegression" {
		t.Fatal("backward jump accepted")
	}
	if fleetplan.Reason(fleetplan.RecoveryTime(now.Add(-time.Hour), now, true)) != "FleetPlanExpired" {
		t.Fatal("clock rollback revived expired identity")
	}
}
