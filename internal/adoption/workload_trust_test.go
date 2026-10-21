package adoption

import "testing"

func TestWorkloadEvidenceCannotWidenUnrelatedLeaves(t *testing.T) {
	f := Fact{Domain: "workload-trust", Identity: "native-uuid", Object: "cluster", Field: "workloadIssuer", Classification: Supported, RoundTrip: Lossless, Value: Value{Text: "https://cluster.example.test"}}
	if !validFact(f) {
		t.Fatal("qualified workload evidence refused")
	}
	for _, change := range []func(*Fact){func(f *Fact) { f.Domain = "application" }, func(f *Fact) { f.Field = "credentialPresence" }, func(f *Fact) { f.Value.Text = "https://credential@cluster.example.test" }, func(f *Fact) { f.Value.Text = "https://cluster.example.test?credential=excluded" }, func(f *Fact) { f.Value.Set = []string{"unexpected"} }, func(f *Fact) { f.Classification = Preserved }, func(f *Fact) { f.RoundTrip = PreservedNative }} {
		copy := f
		change(&copy)
		if validFact(copy) {
			t.Fatal("workload fact widened safe evidence schema")
		}
	}
	if !ReservedAttribute("hanko.sh/workload-trust-journal") || !ReservedAttribute("hanko.sh/workload-trust-checkpoint") {
		t.Fatal("ownership wire metadata not reserved")
	}
}
