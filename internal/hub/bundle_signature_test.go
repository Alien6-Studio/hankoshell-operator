package hub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestBundleHMACRejectsTamperingAndOtherCredentials(t *testing.T) {
	const credential = "bundle-test-credential"
	bundle := Bundle{Version: "v1", TenantID: "tenant-a"}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(credential))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	signed := SignedBundle{Bundle: bundle, Signature: hex.EncodeToString(mac.Sum(nil))}
	client := New("https://hub.example.test", bundle.TenantID, credential)
	if !client.VerifyBundle(&signed) {
		t.Fatal("valid independently signed bundle was rejected")
	}
	for name, mutate := range map[string]func(*SignedBundle){
		"payload":   func(b *SignedBundle) { b.Bundle.Version = "v2" },
		"tenant":    func(b *SignedBundle) { b.Bundle.TenantID = "tenant-b" },
		"signature": func(b *SignedBundle) { b.Signature = strings.Repeat("0", 64) },
		"truncated": func(b *SignedBundle) { b.Signature = b.Signature[:32] },
		"empty":     func(b *SignedBundle) { b.Signature = "" },
		"malformed-payload": func(b *SignedBundle) {
			b.Bundle.Realms = []json.RawMessage{json.RawMessage(`{"metadata":`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := signed
			mutate(&changed)
			if client.VerifyBundle(&changed) {
				t.Fatal("tampered bundle was accepted")
			}
		})
	}
	if New("https://hub.example.test", bundle.TenantID, "other-credential").VerifyBundle(&signed) {
		t.Fatal("bundle signed with another credential was accepted")
	}
}

func TestBundleVerifierEnforcesBudgetEvenWithValidHMAC(t *testing.T) {
	const credential = "bundle-test-credential"
	c := New("https://hub.example.test", "tenant-a", credential)
	if c.VerifyBundle(nil) {
		t.Fatal("missing bundle was accepted")
	}
	for _, count := range []int{200, 201} {
		bundle := Bundle{Version: "fixture", TenantID: "tenant-a"}
		for range count {
			bundle.Apps = append(bundle.Apps, json.RawMessage(`{}`))
		}
		payload, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		key := sha256.Sum256([]byte(credential))
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write(payload)
		signed := SignedBundle{Bundle: bundle, Signature: hex.EncodeToString(mac.Sum(nil))}
		if c.VerifyBundle(&signed) != (count == 200) {
			t.Fatalf("valid HMAC bypassed the aggregate object budget: %d", count)
		}
	}
}
