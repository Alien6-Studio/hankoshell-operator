package workloadauth

import (
	"strings"
	"testing"
)

func FuzzAuthenticationJournal(f *testing.F) {
	for _, seed := range []string{"", Encode(validJournal()), `{}`, Encode(validJournal()) + `{}`, strings.Repeat("x", 8193)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		j, err := ParseJournal(value)
		if err != nil {
			return
		}
		if j == nil {
			if value != "" {
				t.Fatal("nonempty journal disappeared")
			}
			return
		}
		if !j.Valid() || Encode(j) != value {
			t.Fatal("noncanonical transaction accepted")
		}
	})
}

func FuzzAuthenticationApproval(f *testing.F) {
	j := validJournal()
	a := Approval{Strategy: "CoordinatedCutover", OwnerUID: j.OwnerUID, Generation: j.Generation, RequestID: j.RequestID, ExpectedClientUUID: j.ClientUUID, ReviewedStateHash: j.NativeStateHash, BindingRevision: j.BindingRevision, PreparedWorkloadRevision: j.PreparedWorkloadRevision, PreviousMode: j.PreviousMode, DesiredMode: j.DesiredMode, TrustUID: j.TrustUID, ProviderID: j.ProviderID, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash, PreparationApproved: true}
	review := Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
	for _, seed := range []string{Encode(a), Encode(review), Encode(Cleanup{Review: review, SecretUID: "secret-uid"}), `{}`, Encode(a) + `{}`, strings.Repeat("x", 8193)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, target := range []any{new(Approval), new(Review), new(Cleanup)} {
			if Decode(value, target) == nil && Encode(target) != value {
				t.Fatal("ambiguous transaction authorization accepted")
			}
		}
		var parsed Approval
		if Decode(value, &parsed) == nil && parsed.Matches(j) && value != Encode(a) {
			t.Fatal("foreign transaction approval accepted")
		}
	})
}
