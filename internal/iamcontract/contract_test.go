package iamcontract

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestVersionAndDomainSeparation(t *testing.T) {
	b := []byte("{}")
	base := Hash(Version, "roles", "intent", b)
	for _, d := range []Digest{Hash("future", "roles", "intent", b), Hash(Version, "authorization", "intent", b), Hash(Version, "roles", "plan", b)} {
		if base == d {
			t.Fatal("contract/domain/purpose collision")
		}
	}
}
func TestFindingsFailClosedAndBounded(t *testing.T) {
	for _, c := range []FindingClassification{Lossy, Unsupported, "unknown"} {
		if !errors.Is(Accept([]Finding{{Classification: c}}), ErrRejected) {
			t.Fatal("non-lossless finding accepted")
		}
	}
	if err := Accept([]Finding{{Classification: Lossless}}); err != nil {
		t.Fatal(err)
	}
	f := Bound(Finding{Message: strings.Repeat("a", 1000), ObjectName: strings.Repeat("a", 1000)})
	if len(f.Message) > 256 || len(f.ObjectName) > 255 {
		t.Fatal("unbounded finding")
	}
}
func TestProviderErrorDoesNotRenderRemoteCredentials(t *testing.T) {
	sentinel := "fixture-secret-sentinel"
	cause := errors.New(strings.Repeat(sentinel, 1000))
	err := SafeError(cause)
	if !errors.Is(err, cause) || strings.Contains(err.Error(), sentinel) || len(err.Error()) > 256 {
		t.Fatal("unsafe provider error")
	}
}

func TestFindingsOverflowRetainsRefusalAndIsOrderIndependent(t *testing.T) {
	findings := []Finding{}
	for i := range 100 {
		findings = append(findings, Finding{Classification: Lossless, ObjectKind: "role", Code: fmt.Sprintf("known-%03d", i), Message: strings.Repeat("m", 1000)})
	}
	findings = append(findings, Finding{Classification: Lossy, ObjectKind: "role", Code: "desired_loss", Message: "desired mapping cannot be lossless"})
	a := Findings(findings)
	slices.Reverse(findings)
	b := Findings(findings)
	if !reflect.DeepEqual(a, b) || len(a) != MaxFindings || a[0].Classification != Lossy || a[len(a)-1].Code != "finding_budget_exceeded" {
		t.Fatal("bounded summary hid rejection or depended on order")
	}
	if !errors.Is(Accept(findings), ErrRejected) {
		t.Fatal("overflow allowed desired loss")
	}
}
