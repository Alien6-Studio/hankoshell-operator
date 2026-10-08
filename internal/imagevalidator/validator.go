// Package imagevalidator enforces the operator image trust policy (ADR-017/044).
// Workload execution requires a release approval and signature (ADR-047).
// ValidateImageRef only checks structural identity and never authorizes execution.
package imagevalidator

import (
	_ "crypto/sha256" // Register SHA-256 for OCI digest validation.
	"fmt"
	"os"
	"strings"

	"github.com/distribution/reference"
)

// ErrUntrustedImage is returned when an image reference does not match any
// registry and repository identity in the configured allowlist.
type ErrUntrustedImage struct {
	Image     string
	Allowlist []string
}

func (e *ErrUntrustedImage) Error() string {
	return fmt.Sprintf("imagevalidator: %q is not in the trusted registry allowlist %v — set HANKO_TRUSTED_REGISTRIES (ADR-017)", e.Image, e.Allowlist)
}

// Validator checks image references against a registry allowlist.
type Validator struct {
	prefixes   []string
	trusted    []trustedImagePath
	invalid    bool
	policyFile string
	verifier   SignatureVerifier
}

type trustedImagePath struct {
	registry   string
	repository string
}

// New returns a Validator loaded from HANKO_TRUSTED_REGISTRIES (comma-separated
// registries or repository paths). If the env var is unset or empty, the validator is in
// deny-all mode: every image reference is rejected.
func New() *Validator {
	raw := os.Getenv("HANKO_TRUSTED_REGISTRIES")
	if strings.TrimSpace(raw) == "" {
		return NewWithPrefixes()
	}
	return NewWithPrefixes(strings.Split(raw, ",")...)
}

// NewWithPrefixes returns a Validator with an explicit list of trusted prefixes.
// Used in tests.
func NewWithPrefixes(prefixes ...string) *Validator {
	v := &Validator{prefixes: append([]string(nil), prefixes...)}
	for _, prefix := range prefixes {
		trusted, err := parseTrustedPath(prefix)
		if err != nil {
			v.invalid = true
			return v
		}
		v.trusted = append(v.trusted, trusted)
	}
	return v
}

func parseTrustedPath(prefix string) (trustedImagePath, error) {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	registryOnly := !strings.Contains(prefix, "/")
	toParse := prefix
	if registryOnly {
		// Two path components avoid Docker Hub's implicit library/ normalization.
		toParse += "/hanko-allowlist/placeholder"
	}
	named, err := reference.ParseNamed(toParse)
	if err != nil || !reference.IsNameOnly(named) {
		return trustedImagePath{}, fmt.Errorf("imagevalidator: invalid trusted identity %q", prefix)
	}
	trusted := trustedImagePath{registry: reference.Domain(named), repository: reference.Path(named)}
	if registryOnly {
		if trusted.registry != prefix {
			return trustedImagePath{}, fmt.Errorf("imagevalidator: registry must be explicit: %q", prefix)
		}
		trusted.repository = ""
	}
	return trusted, nil
}

// ValidateImageRef parses a canonical reference and matches complete registry
// and repository boundaries. Invalid allowlist configuration denies all images.
// Returns nil on success or *ErrUntrustedImage on failure.
func (v *Validator) ValidateImageRef(image string) error {
	if v == nil {
		return &ErrUntrustedImage{Image: image}
	}
	named, err := reference.ParseNamed(image)
	if err != nil || v.invalid {
		return &ErrUntrustedImage{Image: image, Allowlist: v.prefixes}
	}
	registry, repository := reference.Domain(named), reference.Path(named)
	for _, trusted := range v.trusted {
		if registry == trusted.registry && (trusted.repository == "" ||
			repository == trusted.repository || strings.HasPrefix(repository, trusted.repository+"/")) {
			return nil
		}
	}
	return &ErrUntrustedImage{Image: image, Allowlist: v.prefixes}
}

// MustValidate panics in test mode; in production it returns the error.
// Use ValidateImageRef directly — this is a convenience for test assertions.
func (v *Validator) MustValidate(image string) error {
	return v.ValidateImageRef(image)
}
