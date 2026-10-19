package hub

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzLegacyBundle(f *testing.F) {
	for _, seed := range []string{`{"bundle":{"version":"1","tenantID":"t","realms":[{}]},"signature":"synthetic"}`, `{"bundle":{"apps":[],"apps":[{}]}}`, `{"bundle":null}`, strings.Repeat(" ", maxBundleEnvelopeBytes+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		bundle, err := decodeLegacyBundle(data)
		if err != nil {
			return
		}
		if bundle == nil || legacyBundleObjectCount(&bundle.Bundle) > maxLegacyBundleObjects || len(data) > maxBundleEnvelopeBytes {
			t.Fatal("unbounded legacy bundle accepted")
		}
		if (&Client{hmacKey: []byte("synthetic-key")}).VerifyBundle(bundle) && (&Client{hmacKey: []byte("other-key")}).VerifyBundle(bundle) {
			t.Fatal("bundle authenticated under unrelated keys")
		}
		if _, err := decodeLegacyBundle(append(append([]byte{}, data...), []byte(" {}")...)); err == nil {
			t.Fatal("trailing bundle accepted")
		}
	})
}

func FuzzHubControlResponse(f *testing.F) {
	for _, seed := range []string{`{"ok":true}`, `{"ok":true,"agentUpdate":{"version":"1.0.0","digest":"synthetic"}}`, `{"ok":true,"ok":false}`, `{"token":"synthetic","tenantID":"t","clusterID":"c","expiresAt":"2026-10-17T00:00:00Z"}`, strings.Repeat(" ", maxHubControlResponseBytes+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, target := range []any{new(StatusAck), new(EnrollResult)} {
			accepted := decodeControlResponse(data, target)
			if accepted && (len(data) > maxHubControlResponseBytes || !json.Valid(data)) {
				t.Fatal("unbounded control response accepted")
			}
			if accepted && decodeControlResponse(append(append([]byte{}, data...), []byte(" {}")...), target) {
				t.Fatal("ambiguous control response accepted")
			}
		}
	})
}
