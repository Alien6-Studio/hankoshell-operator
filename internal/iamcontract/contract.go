// Package iamcontract contains evidence shared by domain-specific IAM adapters.
// It deliberately contains no provider operations or Kubernetes API types.
package iamcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
)

type ContractVersion string

const Version ContractVersion = "hanko.sh/iam-contract/v1alpha1"

type BackendKind string

const Keycloak BackendKind = "keycloak"

type Digest string

// Hash domain-separates explicit canonical domain bytes. Callers must construct
// those bytes from reviewed semantic structs, never from CRs or credentials.
func Hash(version ContractVersion, domain, purpose string, canonical []byte) Digest {
	h := sha256.New()
	for _, value := range []string{string(version), domain, purpose, string(canonical)} {
		_, _ = h.Write([]byte(strconv.Itoa(len(value)) + ":" + value))
	}
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

type FindingClassification string

const (
	Lossless    FindingClassification = "lossless"
	Lossy       FindingClassification = "lossy"
	Unsupported FindingClassification = "unsupported"
)

type Finding struct {
	Classification FindingClassification
	ObjectKind     string
	ObjectName     string
	Code           string
	Message        string
	ReadOnly       bool
}

// Bound budgets machine-readable findings; messages must be locally authored.
func Bound(f Finding) Finding {
	f.ObjectKind = bounded(f.ObjectKind, 64)
	f.ObjectName = bounded(f.ObjectName, 255)
	f.Code = bounded(f.Code, 64)
	f.Message = bounded(f.Message, 256)
	return f
}
func bounded(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

var ErrRejected = errors.New("IAM semantics rejected before mutation")
var ErrStale = errors.New("IAM execution inputs changed; recompile required")

func Accept(findings []Finding) error {
	for _, f := range findings {
		if f.Classification != Lossless {
			return ErrRejected
		}
	}
	return nil
}

type PlanIdentity struct {
	Contract ContractVersion `json:"contract"`
	Backend  BackendKind     `json:"backend"`
	Intent   Digest          `json:"intent"`
	Plan     Digest          `json:"plan"`
}

// Preconditions are local execution checks, not portable semantic identity.
// References are safe resource identities/generations, never Secret data.
type Preconditions struct {
	ResourceUID string
	Generation  int64
	References  Digest
	Ownership   Digest
	Authority   Digest
}

// ProviderError retains errors.Is/As without rendering remote responses into
// status, events or logs. The provider HTTP client still enforces byte budgets.
type providerError struct{ cause error }

func (e providerError) Error() string { return "IAM provider operation failed" }
func (e providerError) Unwrap() error { return e.cause }
func SafeError(err error) error {
	if err == nil {
		return nil
	}
	return providerError{cause: err}
}
