package workloadauth

import (
	"strings"
	"testing"
)

func validJournal() Journal {
	h := Hash("fixture", 1)
	return Journal{Schema: Schema, OwnerUID: "identity-uid", Generation: 1, RequestID: "review-one", ClientUUID: "native-uid", PreviousMode: "Secret", DesiredMode: "Kubernetes", TrustUID: "trust-uid", ProviderID: "provider-uid", BindingRevision: h, WorkloadUID: "workload-uid", PreparedWorkloadRevision: "workload-one", NativeStateHash: h, AppliedStateHash: h, PlanHash: h, Step: "Prepared"}
}
func TestClosedJournalRejectsUnknownDuplicateNoncanonicalAndCredentialFields(t *testing.T) {
	j := validJournal()
	value := Encode(j)
	if parsed, err := ParseJournal(value); err != nil || parsed == nil || *parsed != j {
		t.Fatal("journal did not round-trip")
	}
	for _, bad := range []string{"", " " + value, value + "{}", strings.Replace(value, `"step":"Prepared"`, `"step":"Unknown"`, 1), strings.Replace(value, `"schema":`, `"clientSecret":"credential","schema":`, 1), strings.Replace(value, `"generation":1`, `"generation":1,"generation":1`, 1), strings.Replace(value, `"ownerUID":"identity-uid"`, `"ownerUID":"eyJheader.payload.signature"`, 1)} {
		if bad == "" {
			if p, e := ParseJournal(bad); p != nil || e != nil {
				t.Fatal("absent journal")
			}
			continue
		}
		if _, err := ParseJournal(bad); err == nil && !strings.Contains(bad, "eyJheader.payload.signature") {
			t.Fatal("unqualified journal accepted")
		}
	}
	// A JWT-shaped token cannot be substituted for any approved digest.
	j.NativeStateHash = "eyJheader.payload.signature"
	if _, err := ParseJournal(Encode(j)); err == nil {
		t.Fatal("credential-shaped native-state evidence accepted")
	}
}
func TestReviewAndCleanupRequireExactCurrentIdentity(t *testing.T) {
	j := validJournal()
	r := Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
	if !r.Matches(j) {
		t.Fatal("current review rejected")
	}
	for _, change := range []func(*Journal){func(j *Journal) { j.RequestID = "other" }, func(j *Journal) { j.ClientUUID = "other" }, func(j *Journal) { j.WorkloadUID = "other" }, func(j *Journal) { j.BindingRevision = Hash("other", 1) }, func(j *Journal) { j.PlanHash = Hash("other", 1) }} {
		changed := j
		change(&changed)
		if r.Matches(changed) {
			t.Fatal("stale external review authorized cleanup")
		}
	}
}
