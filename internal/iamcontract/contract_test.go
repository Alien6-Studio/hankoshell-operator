package iamcontract

import (
	"errors"
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
