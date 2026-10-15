package fleetplan_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

type fixture struct {
	plan    fleetplan.Plan
	trust   fleetplan.Trust
	now     time.Time
	private ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: "tenant-id", ClusterID: "cluster-id", Namespace: "auth", TenantName: "tenant"}, TenantUID: "tenant-uid"}
	return fixture{
		plan: fleetplan.Plan{Issuer: "https://publisher.example.test", KeyID: "publisher-1", Target: target,
			Source:          fleetplan.Source{Repository: "example/config", Revision: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64)},
			ContractVersion: string(iamcontract.Version), Sequence: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), Mode: "all-or-refuse",
			Content: fleetplan.Content{Realms: []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","metadata":{"name":"realm","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"otpRequired":true}}`)}}},
		trust: fleetplan.Trust{Version: fleetplan.TrustVersion, Keys: []fleetplan.Key{{ID: "publisher-1", Issuer: "https://publisher.example.test", PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Scopes: []fleetplan.Scope{target.Scope}, Sources: []string{"example/config"}}}},
		now:   now, private: private,
	}
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f fixture) signed(t *testing.T, payload []byte) []byte {
	t.Helper()
	if payload == nil {
		payload = marshal(t, f.plan)
	}
	return marshal(t, fleetplan.Envelope{Version: fleetplan.EnvelopeVersion, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, fleetplan.SigningInput(payload)))})
}

func TestVerifiedFleetPlanIdentityAndRecovery(t *testing.T) {
	f := newFixture(t)
	envelope, trust := f.signed(t, nil), marshal(t, f.trust)
	v, err := fleetplan.Verify(envelope, trust, f.plan.Target, f.now, fleetplan.Checkpoint{})
	if err != nil || v.Current() || !iamcontract.ValidDigest(v.Identity()) {
		t.Fatalf("valid plan: %v", err)
	}
	for _, applied := range []bool{false, true} {
		recovered, err := fleetplan.Verify(envelope, trust, f.plan.Target, f.now, fleetplan.Checkpoint{Sequence: 1, Identity: v.Identity(), Applied: applied})
		if err != nil || recovered.Identity() != v.Identity() || recovered.Current() != applied {
			t.Fatal("same pending/applied plan did not retain its checkpoint")
		}
	}
	changed := v.Plan()
	changed.Content.Realms[0][0] = 'x'
	if bytes.Equal(changed.Content.Realms[0], v.Plan().Content.Realms[0]) {
		t.Fatal("caller changed the verified snapshot")
	}
	if string(marshal(t, v)) != "{}" {
		t.Fatal("sealed verification result serialized executable content")
	}
	if fleetplan.Reason(errors.New("remote-secret-sentinel")) != "FleetPlanFailed" {
		t.Fatal("unknown errors were exposed")
	}
}

func TestFleetPlanRejectsUnqualifiedAuthorityAndFreshness(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*fixture)
	}{
		{"unknown-key", "FleetKeyUnapproved", func(f *fixture) { f.plan.KeyID = "other" }},
		{"issuer", "FleetKeyUnapproved", func(f *fixture) { f.plan.Issuer = "other" }},
		{"source-authority", "FleetIssuerAuthorityMismatch", func(f *fixture) { f.plan.Source.Repository = "other/config" }},
		{"target-authority", "FleetIssuerAuthorityMismatch", func(f *fixture) { f.plan.Target.ClusterID = "other" }},
		{"contract", "FleetSourceInvalid", func(f *fixture) { f.plan.ContractVersion = "unknown" }},
		{"revision", "FleetSourceInvalid", func(f *fixture) { f.plan.Source.Revision = "main" }},
		{"digest", "FleetSourceInvalid", func(f *fixture) { f.plan.Source.Digest = "mutable" }},
		{"zero-sequence", "FleetValidityInvalid", func(f *fixture) { f.plan.Sequence = 0 }},
		{"negative-sequence", "FleetValidityInvalid", func(f *fixture) { f.plan.Sequence = -1 }},
		{"empty-time", "FleetValidityInvalid", func(f *fixture) { f.plan.IssuedAt = time.Time{} }},
		{"long-validity", "FleetValidityInvalid", func(f *fixture) { f.plan.ExpiresAt = f.now.Add(2 * time.Hour) }},
		{"bad-window", "FleetValidityInvalid", func(f *fixture) { f.plan.NotBefore = f.plan.ExpiresAt.Add(time.Second) }},
		{"backdated-window", "FleetValidityInvalid", func(f *fixture) { f.plan.NotBefore = f.now.Add(-time.Hour) }},
		{"future", "FleetPlanNotYetValid", func(f *fixture) { f.plan.IssuedAt = f.now.Add(time.Minute); f.plan.NotBefore = f.plan.IssuedAt }},
		{"not-before", "FleetPlanNotYetValid", func(f *fixture) { f.plan.NotBefore = f.now.Add(time.Minute) }},
		{"expired", "FleetPlanExpired", func(f *fixture) { f.now = f.plan.ExpiresAt }},
		{"mode", "FleetCapabilitiesUnsupported", func(f *fixture) { f.plan.Mode = "unknown" }},
		{"capability", "FleetCapabilitiesUnsupported", func(f *fixture) { f.plan.Requirements = []string{"invalid/requirement"} }},
		{"rollback", "FleetRollbackUnsupported", func(f *fixture) { f.plan.RollbackOf = "sha256:" + strings.Repeat("c", 64) }},
		{"duplicate-key", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys = append(f.trust.Keys, f.trust.Keys[0]) }},
		{"bad-key", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].PublicKey = "invalid" }},
		{"oversize-key", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].PublicKey = strings.Repeat("a", 100) }},
		{"bad-key-id", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].ID = "" }},
		{"empty-scopes", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].Scopes = nil }},
		{"invalid-scope", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].Scopes[0].Namespace = "" }},
		{"invalid-source", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys[0].Sources = []string{""} }},
		{"no-keys", "FleetTrustInvalid", func(f *fixture) { f.trust.Keys = nil }},
		{"trust-version", "FleetTrustInvalid", func(f *fixture) { f.trust.Version = "unknown" }},
		{"key-expired", "FleetKeyExpired", func(f *fixture) { f.trust.Keys[0].NotAfter = f.now }},
		{"key-future", "FleetKeyExpired", func(f *fixture) { f.trust.Keys[0].NotBefore = f.now.Add(time.Minute) }},
		{"many-objects", "FleetContentInvalid", func(f *fixture) {
			for len(f.plan.Content.Realms) <= fleetplan.MaxObjects {
				f.plan.Content.Realms = append(f.plan.Content.Realms, f.plan.Content.Realms[0])
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.plan.Target
			tc.change(&f)
			_, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), target, f.now, fleetplan.Checkpoint{})
			if err == nil || fleetplan.Reason(err) != tc.reason {
				t.Fatalf("want %s, got %v", tc.reason, err)
			}
		})
	}
}

func TestFleetContentCannotCarryLocalAuthority(t *testing.T) {
	for index, metadata := range []string{
		`"finalizers":["foreign/retain"]`, `"ownerReferences":[]`, `"resourceVersion":"1"`,
		`"annotations":{"hanko.sh/adoption-candidate":"remote-secret-sentinel"}`,
		`"annotations":{"mesh.hanko.io/state":"remote-secret-sentinel"}`,
	} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			f := newFixture(t)
			f.plan.Content.Realms[0] = json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","metadata":{"name":"realm","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"},` + metadata + `},"spec":{}}`)
			_, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{})
			if err == nil || strings.Contains(err.Error(), "remote-secret-sentinel") {
				t.Fatal("local authority accepted or remote content exposed")
			}
		})
	}
}

func TestFleetLabelsCannotClaimLocalAuthority(t *testing.T) {
	f := newFixture(t)
	f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"hanko.sh/tenant":"tenant"`, `"hanko.sh/tenant":"tenant","hanko.io/approved":"true"`, 1))
	if _, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetContentAuthorityInvalid" {
		t.Fatal("remote label granted local authority")
	}
}

func TestFleetPlanClosedDecodingAndSignature(t *testing.T) {
	f := newFixture(t)
	trust := marshal(t, f.trust)
	payload := marshal(t, f.plan)
	for name, data := range map[string][]byte{
		"empty": nil, "oversize": bytes.Repeat([]byte("x"), fleetplan.MaxEnvelope+1),
		"unknown-envelope":   append([]byte(`{"unknown":true,`), f.signed(t, nil)[1:]...),
		"wrong-case":         bytes.Replace(f.signed(t, nil), []byte(`"version"`), []byte(`"Version"`), 1),
		"unknown-payload":    f.signed(t, append([]byte(`{"unknown":true,`), payload[1:]...)),
		"duplicate-payload":  f.signed(t, append([]byte(`{"sequence":1,`), payload[1:]...)),
		"wrong-case-payload": f.signed(t, bytes.Replace(payload, []byte(`"sequence"`), []byte(`"Sequence"`), 1)),
		"trailing":           append(f.signed(t, nil), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fleetplan.Verify(data, trust, f.plan.Target, f.now, fleetplan.Checkpoint{}); err == nil {
				t.Fatal("ambiguous or unsupported envelope accepted")
			}
		})
	}
	var e fleetplan.Envelope
	if err := json.Unmarshal(f.signed(t, nil), &e); err != nil {
		t.Fatal(err)
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := fleetplan.Verify(marshal(t, e), trust, f.plan.Target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetSignatureInvalid" {
		t.Fatal("forged signature accepted")
	}
	for _, target := range []fleetplan.Target{{}, {Scope: f.plan.Target.Scope, TenantUID: "recreated"}} {
		if _, err := fleetplan.Verify(f.signed(t, nil), trust, target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetTargetMismatch" {
			t.Fatal("wrong target accepted")
		}
	}
	v, err := fleetplan.Verify(f.signed(t, nil), trust, f.plan.Target, f.now, fleetplan.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	for _, checkpoint := range []fleetplan.Checkpoint{
		{Sequence: 2, Identity: v.Identity()}, {Sequence: 1, Identity: "sha256:" + strings.Repeat("f", 64)},
		{Sequence: -1}, {Identity: v.Identity()}, {Sequence: 1},
	} {
		if _, err := fleetplan.Verify(f.signed(t, nil), trust, f.plan.Target, f.now, checkpoint); err == nil {
			t.Fatal("invalid/replayed sequence accepted")
		}
	}
}

func TestFleetRotationNeedsIndependentLocalApproval(t *testing.T) {
	f := newFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.private, f.plan.KeyID = private, "publisher-2"
	envelope := f.signed(t, nil)
	if _, err := fleetplan.Verify(envelope, marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetKeyUnapproved" {
		t.Fatal("Hub supplied an unapproved rotation")
	}
	key := f.trust.Keys[0]
	key.ID, key.PublicKey = "publisher-2", base64.RawURLEncoding.EncodeToString(public)
	f.trust.Keys = append(f.trust.Keys, key)
	if _, err := fleetplan.Verify(envelope, marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	f.trust.Keys = f.trust.Keys[:1]
	if _, err := fleetplan.Verify(envelope, marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetKeyUnapproved" {
		t.Fatal("revoked key retained authority")
	}
	// Two approved tuples do not authorize their cross product.
	f = newFixture(t)
	second := f.plan.Target.Scope
	second.ClusterID, second.TenantID = "other-cluster", "other-tenant"
	f.trust.Keys[0].Scopes = append(f.trust.Keys[0].Scopes, second)
	f.plan.Target.ClusterID = "other-cluster"
	if _, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); fleetplan.Reason(err) != "FleetIssuerAuthorityMismatch" {
		t.Fatal("scope tuples became independent wildcard sets")
	}
}

func TestFleetDecodingAndCheckpointReasons(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		reason          string
		envelope, trust []byte
		checkpoint      fleetplan.Checkpoint
	}{
		{"FleetEnvelopeInvalid", []byte(`{}`), marshal(t, f.trust), fleetplan.Checkpoint{}},
		{"FleetPayloadInvalid", marshal(t, fleetplan.Envelope{Version: fleetplan.EnvelopeVersion, Payload: "!"}), marshal(t, f.trust), fleetplan.Checkpoint{}},
		{"FleetTrustInvalid", f.signed(t, nil), []byte(`{"unknown":true}`), fleetplan.Checkpoint{}},
		{"FleetCheckpointInvalid", f.signed(t, nil), marshal(t, f.trust), fleetplan.Checkpoint{Sequence: 1}},
		{"FleetPlanDowngrade", f.signed(t, nil), marshal(t, f.trust), fleetplan.Checkpoint{Sequence: 2, Identity: "sha256:" + strings.Repeat("a", 64)}},
		{"FleetSequenceConflict", f.signed(t, nil), marshal(t, f.trust), fleetplan.Checkpoint{Sequence: 1, Identity: "sha256:" + strings.Repeat("a", 64)}},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := fleetplan.Verify(tc.envelope, tc.trust, f.plan.Target, f.now, tc.checkpoint)
			if fleetplan.Reason(err) != tc.reason {
				t.Fatalf("want %s, got %v", tc.reason, err)
			}
		})
	}
}
