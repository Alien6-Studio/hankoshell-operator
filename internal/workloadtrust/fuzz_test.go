package workloadtrust

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzPublicDiscovery(f *testing.F) {
	for _, seed := range []string{`{"issuer":"https://cluster.example.test","jwks_uri":"https://cluster.example.test/jwks"}`, `{"issuer":"a","issuer":"b"}`, `{}[]`, strings.Repeat(" ", PublicDocumentLimit+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var doc DiscoveryDocument
		if decodePublicDocument(data, &doc) == nil {
			if len(data) > PublicDocumentLimit || !json.Valid(data) {
				t.Fatal("discovery bounds bypassed")
			}
			if decodePublicDocument(append(append([]byte{}, data...), []byte(" {}")...), &doc) == nil {
				t.Fatal("accepted trailing discovery document")
			}
		}
	})
}

func FuzzPublicKeys(f *testing.F) {
	for _, seed := range []string{publicTestKeys, `{"keys":[]}`, `{"keys":[{"kty":"oct","kid":"k","k":"private"}]}`, strings.Repeat(" ", PublicDocumentLimit+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		hash, err := PublicKeysHash(data)
		if err != nil {
			return
		}
		var doc struct {
			Keys []map[string]json.RawMessage `json:"keys"`
		}
		if json.Unmarshal(data, &doc) != nil || len(doc.Keys) == 0 || len(doc.Keys) > 64 || len(hash) != 71 {
			t.Fatal("accepted unbounded keyset")
		}
		// A private component must invalidate evidence, including on an otherwise
		// valid public key. Compare projections without relying on field order.
		doc.Keys[0]["d"] = json.RawMessage(`"synthetic-private"`)
		altered, _ := json.Marshal(doc)
		if _, err := PublicKeysHash(altered); err == nil {
			t.Fatal("private material became public evidence")
		}
	})
}

func FuzzTrustRecoveryMetadata(f *testing.F) {
	p := testPlan(f)
	journal, err := p.Journal(Digest("state", 1), "Applied")
	if err != nil {
		f.Fatal(err)
	}
	checkpoint, err := p.Checkpoint("Owned")
	if err != nil {
		f.Fatal(err)
	}
	approval, _ := json.Marshal(p.AgeReview(300))
	for _, seed := range []string{journal, checkpoint, string(approval), `{}`, journal + `{}`, strings.Repeat("x", 8193)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if j, err := ParseJournal(value); err == nil {
			b, _ := json.Marshal(j)
			if string(b) != value || !j.valid() {
				t.Fatal("journal lost canonical identity")
			}
		}
		if c, err := ParseCheckpoint(value); err == nil {
			b, _ := json.Marshal(c)
			if string(b) != value || !c.valid() {
				t.Fatal("checkpoint lost canonical identity")
			}
		}
		if p.ApproveAge(value, 300) == nil && value != string(approval) {
			t.Fatal("stale or foreign age approval accepted")
		}
	})
}
