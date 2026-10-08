// Package iamconformance supplies reusable behavior qualification helpers.
// It is imported only by tests, never by operator code or provider adapters.
package iamconformance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// Fixture uses behavior callbacks, not a universal production provider API.
// Each domain supplies real setup, mutation observation and ownership checks.
type Fixture struct {
	Compile        func(bool) iamcontract.PlanIdentity
	Refuse         func() error
	Writes         func() int
	Observe        func() error
	Manage         func() error
	DriftAndRepair func() error
	Foreign        func() error
	DeleteOwned    func() error
	VerifyDeleted  func() error
}

// Run exercises the same execution guarantees across domain-specific adapters.
func Run(t *testing.T, f Fixture) {
	t.Helper()
	if f.Compile(false) != f.Compile(true) {
		t.Fatal("order-equivalent compilation differs")
	}
	NoMutation(t, f.Writes, func() error {
		if f.Refuse() == nil {
			t.Fatal("unsupported intent accepted")
		}
		return nil
	})
	if err := f.Manage(); err != nil {
		t.Fatal(err)
	}
	t.Run("idempotent Manage", func(t *testing.T) { NoMutation(t, f.Writes, f.Manage) })
	t.Run("read-only Observe", func(t *testing.T) { NoMutation(t, f.Writes, f.Observe) })
	if err := f.DriftAndRepair(); err != nil {
		t.Fatal(err)
	}
	NoMutation(t, f.Writes, func() error {
		if f.Foreign() == nil {
			t.Fatal("foreign object implicitly adopted")
		}
		return nil
	})
	if err := f.DeleteOwned(); err != nil {
		t.Fatal(err)
	}
	if err := f.VerifyDeleted(); err != nil {
		t.Fatal(err)
	}
	t.Run("idempotent deletion", func(t *testing.T) { NoMutation(t, f.Writes, f.DeleteOwned) })
}

// NoMutation counts actual writes rather than assuming an Observe method is safe.
func NoMutation(t *testing.T, writes func() int, action func() error) {
	t.Helper()
	before := writes()
	if err := action(); err != nil {
		t.Fatal(err)
	}
	if writes() != before {
		t.Fatalf("read/refusal/idempotent path mutated provider: %d -> %d writes", before, writes())
	}
}

// NoSecrets verifies exactly the rendered public surfaces, not private fixtures.
func NoSecrets(t *testing.T, sentinels []string, values ...any) {
	t.Helper()
	for _, v := range values {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sentinels {
			if s != "" && strings.Contains(string(b), s) {
				t.Fatal("credential leaked into serialized evidence (value withheld)")
			}
		}
	}
}
