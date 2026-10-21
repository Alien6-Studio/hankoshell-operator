package adoption

import (
	"strings"
	"testing"
)

func TestApprovalMetadataIsExactAndSourceAloneIsReadOnly(t *testing.T) {
	full := map[string]string{SourceAnnotation: "inventory-keycloak", ContractAnnotation: string(Version), CandidateAnnotation: "sha256:" + strings.Repeat("a", 64)}
	for _, test := range []struct {
		name          string
		annotations   map[string]string
		ok, requested bool
	}{
		{"none", nil, true, false},
		{"source-only", map[string]string{SourceAnnotation: "inventory-keycloak"}, true, false},
		{"exact", full, true, true},
		{"contract-only", map[string]string{ContractAnnotation: string(Version)}, false, true},
		{"candidate-only", map[string]string{CandidateAnnotation: full[CandidateAnnotation]}, false, true},
		{"source-contract", map[string]string{SourceAnnotation: "inventory", ContractAnnotation: string(Version)}, false, true},
		{"source-candidate", map[string]string{SourceAnnotation: "inventory", CandidateAnnotation: full[CandidateAnnotation]}, false, true},
		{"cross-namespace", map[string]string{SourceAnnotation: "other/inventory"}, false, false},
		{"empty-source", map[string]string{SourceAnnotation: ""}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, err := ParseApproval(test.annotations)
			if (err == nil) != test.ok || a.Requested != test.requested {
				t.Fatalf("approval result: requested=%v error=%v", a.Requested, err)
			}
		})
	}
	for _, replacement := range []struct{ key, value string }{
		{ContractAnnotation, "future"}, {ContractAnnotation, ""}, {CandidateAnnotation, "sha256:" + strings.Repeat("A", 64)}, {CandidateAnnotation, "sha256:" + strings.Repeat("a", 63)},
		{"hanko.sh/migrate-keycloak-client-uuid", "legacy"}, {"hanko.sh/migrate-keycloak-observation", ""},
	} {
		a := map[string]string{}
		for k, v := range full {
			a[k] = v
		}
		a[replacement.key] = replacement.value
		if _, err := ParseApproval(a); err == nil {
			t.Fatalf("accepted invalid %s", replacement.key)
		}
	}
}

func TestReceiptRejectsAmbiguousOrUnboundedWireForms(t *testing.T) {
	r := Receipt{Version, "HankoServiceAccount", "target-uid", "sha256:" + strings.Repeat("b", 64)}
	value, err := r.Canonical()
	if err != nil || len(value) > MaxReceiptBytes {
		t.Fatal(err)
	}
	got, err := ParseReceipt(value)
	if err != nil || got != r {
		t.Fatal("canonical round trip failed", err)
	}
	for _, invalid := range []string{" " + value, value + " ", strings.Replace(value, "{", "{\"extra\":true,", 1), strings.Replace(value, "{", "{\"targetUID\":\"other\",", 1), strings.Repeat("x", 513), strings.Replace(value, "HankoServiceAccount", "HankoRealm", 1), strings.Replace(value, "target-uid", "", 1)} {
		if _, err := ParseReceipt(invalid); err == nil {
			t.Fatal("accepted ambiguous receipt")
		}
	}
}
