package workloadbinding

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzDeliveryRecord(f *testing.F) {
	sa, _ := testIntent()
	hash := Digest("fixture", 1)
	seed, _ := json.Marshal(Record{Schema: Schema, OwnerUID: string(sa.UID), Namespace: "workloads", Name: "metadata", UID: "target-uid", Workload: sa.Spec.Authentication.Kubernetes.Workload, Revision: hash, MetadataHash: hash})
	for _, value := range []string{"", string(seed), `{}`, string(seed) + `{}`, strings.Repeat("x", 4097)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		r, err := ParseRecord(value)
		if err != nil {
			return
		}
		if r == nil {
			if value != "" {
				t.Fatal("nonempty delivery record disappeared")
			}
			return
		}
		canonical, _ := json.Marshal(r)
		if !r.valid() || string(canonical) != value || len(value) > 4096 {
			t.Fatal("unbound delivery record accepted")
		}
	})
}
