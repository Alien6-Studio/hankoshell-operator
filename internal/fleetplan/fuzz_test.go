package fleetplan_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
)

func FuzzFleetEnvelope(f *testing.F) {
	fixture := newFuzzFixture(f)
	valid, trust := fixture.signed(f, nil), marshal(f, fixture.trust)
	for _, data := range [][]byte{valid, []byte(`{}`), append(bytes.Clone(valid), []byte(" {}")...), []byte(strings.Repeat(" ", fleetplan.MaxEnvelope+1))} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		verified, err := fleetplan.Verify(data, trust, fixture.plan.Target, fixture.now, fleetplan.Checkpoint{})
		if err == nil {
			qualifyFuzzVerified(t, verified, data, trust, fixture)
		}
	})
}

// Signing mutated payloads reaches semantic, ownership and replay checks that
// random envelope bytes cannot reach through the Ed25519 barrier.
func FuzzFleetSignedPayload(f *testing.F) {
	fixture := newFuzzFixture(f)
	trust := marshal(f, fixture.trust)
	for _, data := range [][]byte{marshal(f, fixture.plan), []byte(`{}`), []byte(`{"sequence":1,"sequence":2}`), []byte(strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33))} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fleetplan.MaxEnvelope {
			return
		}
		envelope := fixture.signed(t, data)
		verified, err := fleetplan.Verify(envelope, trust, fixture.plan.Target, fixture.now, fleetplan.Checkpoint{})
		if err == nil {
			qualifyFuzzVerified(t, verified, envelope, trust, fixture)
		}
	})
}

func FuzzFleetTrust(f *testing.F) {
	fixture := newFuzzFixture(f)
	envelope := fixture.signed(f, nil)
	for _, data := range [][]byte{marshal(f, fixture.trust), []byte(`{"version":"hanko.sh/fleet-trust/v1alpha1","keys":[]}`), []byte(`{}`), []byte(strings.Repeat(" ", fleetplan.MaxTrust+1))} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, trust []byte) {
		verified, err := fleetplan.Verify(envelope, trust, fixture.plan.Target, fixture.now, fleetplan.Checkpoint{})
		if err == nil {
			qualifyFuzzVerified(t, verified, envelope, trust, fixture)
		}
	})
}

func qualifyFuzzVerified(t *testing.T, v fleetplan.Verified, envelope, trust []byte, fixture fixture) {
	t.Helper()
	p := v.Plan()
	if len(envelope) > fleetplan.MaxEnvelope || len(trust) > fleetplan.MaxTrust || p.Target != fixture.plan.Target || p.Sequence < 1 || !fixture.now.Before(p.ExpiresAt) {
		t.Fatal("unbound or stale plan verified")
	}
	checkpoint := fleetplan.Checkpoint{Sequence: p.Sequence, Identity: v.Identity(), Applied: true}
	replay, err := fleetplan.Verify(envelope, trust, p.Target, fixture.now, checkpoint)
	if err != nil || !replay.Current() || replay.Identity() != v.Identity() {
		t.Fatal("same-plan recovery changed identity")
	}
	checkpoint.Sequence++
	if _, err := fleetplan.Verify(envelope, trust, p.Target, fixture.now, checkpoint); fleetplan.Reason(err) != "FleetPlanDowngrade" {
		t.Fatal("downgrade bypassed checkpoint")
	}
	target := p.Target
	target.TenantUID += "-foreign"
	if _, err := fleetplan.Verify(envelope, trust, target, fixture.now, fleetplan.Checkpoint{}); err == nil {
		t.Fatal("foreign target accepted")
	}
	var parsed fleetplan.Envelope
	if json.Unmarshal(envelope, &parsed) != nil {
		t.Fatal("accepted malformed envelope")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parsed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatal("accepted malformed signature")
	}
	sig[0] ^= 1
	parsed.Signature = base64.RawURLEncoding.EncodeToString(sig)
	if _, err := fleetplan.Verify(marshal(t, parsed), trust, p.Target, fixture.now, fleetplan.Checkpoint{}); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

// A fixed synthetic key keeps coordinator seeds valid in every worker process.
// It never authorizes an installation or a production publisher.
func newFuzzFixture(f *testing.F) fixture {
	result := newFixture(f)
	result.private = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	public := result.private.Public().(ed25519.PublicKey)
	result.trust.Keys[0].PublicKey = base64.RawURLEncoding.EncodeToString(public)
	return result
}
