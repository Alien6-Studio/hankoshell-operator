package iamconformance

import (
	"encoding/json"
	"testing"
)

func TestPortableCorpusInventoryAndPrivacy(t *testing.T) {
	corpus, err := ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	NoSecrets(t, []string{"client_secret", "Bearer ", "PRIVATE KEY", "password"}, corpus)
	raw, _ := json.Marshal(corpus)
	for _, mutate := range []func(*PortableCorpus){
		func(c *PortableCorpus) { delete(c.Fixtures[0].Expected, "authentik") },
		func(c *PortableCorpus) { c.Fixtures[2].IntentIdentity = "" },
		func(c *PortableCorpus) { c.Fixtures[0].Manifest.Kind = "HankoApplication" },
		func(c *PortableCorpus) { c.Fixtures[0].Capability = "future-capability" },
		func(c *PortableCorpus) { c.Fixtures[1].Capability = c.Fixtures[0].Capability },
		func(c *PortableCorpus) {
			v := c.Fixtures[0].Expected["authentik"]
			v.Reason = ""
			c.Fixtures[0].Expected["authentik"] = v
		},
		func(c *PortableCorpus) {
			v := c.Fixtures[0].Expected["authentik"]
			v.Classification = "lossy"
			c.Fixtures[0].Expected["authentik"] = v
		},
	} {
		var copy PortableCorpus
		_ = json.Unmarshal(raw, &copy)
		mutate(&copy)
		data, _ := json.Marshal(copy)
		if _, err := DecodePortableCorpus(data); err == nil {
			t.Fatal("unreviewed corpus accepted")
		}
	}
	if _, err := DecodePortableCorpus(append(raw, raw...)); err == nil {
		t.Fatal("ambiguous corpus accepted")
	}
}
