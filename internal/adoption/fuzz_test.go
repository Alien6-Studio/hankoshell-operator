package adoption

import (
	"strings"
	"testing"
)

func FuzzAdoptionReceipt(f *testing.F) {
	valid, _ := (Receipt{ContractVersion: Version, TargetKind: "HankoApplication", TargetUID: "target-uid", CandidateHash: "sha256:" + strings.Repeat("a", 64)}).Canonical()
	for _, seed := range []string{valid, `{}`, valid + `{}`, strings.Repeat("x", MaxReceiptBytes+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		receipt, err := ParseReceipt(value)
		if err == nil {
			canonical, err := receipt.Canonical()
			if err != nil || canonical != value || len(value) > MaxReceiptBytes {
				t.Fatal("noncanonical acquisition checkpoint accepted")
			}
		}
	})
}

func FuzzAdoptionApproval(f *testing.F) {
	f.Add("inventory", string(Version), "sha256:"+strings.Repeat("a", 64))
	f.Add("..", "", "")
	f.Fuzz(func(t *testing.T, source, contract, candidate string) {
		annotations := map[string]string{SourceAnnotation: source, ContractAnnotation: contract, CandidateAnnotation: candidate}
		a, err := ParseApproval(annotations)
		if err != nil {
			return
		}
		if !a.Requested || a.Contract != Version || len(a.Source) > 253 || !hashPattern.MatchString(a.CandidateHash) {
			t.Fatal("incomplete adoption consent accepted")
		}
		annotations["hanko.sh/migrate-keycloak-client-uuid"] = "legacy"
		if _, err := ParseApproval(annotations); err != ErrApprovalConflict {
			t.Fatal("conflicting approval channels accepted")
		}
		delete(annotations, ContractAnnotation)
		delete(annotations, CandidateAnnotation)
		delete(annotations, "hanko.sh/migrate-keycloak-client-uuid")
		if readOnly, err := ParseApproval(annotations); err != nil || readOnly.Requested {
			t.Fatal("source selection became write consent")
		}
	})
}
