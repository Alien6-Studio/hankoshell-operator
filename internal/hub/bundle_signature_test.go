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
