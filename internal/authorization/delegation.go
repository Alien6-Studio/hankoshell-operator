package authorization

import (
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const (
	DefaultDelegationDepth      = int32(1)
	DefaultDelegationTTLSeconds = int32(120)
)

// Delegation restricts one existing permission to two explicit software
// identities. The containing ResourceServer supplies the only target audience.
type Delegation struct {
	Actor         Principal
	Subject       Principal
	MaxDepth      int32
	MaxTTLSeconds int32
}

// DelegationError carries a fixed local finding, never provider response data.
type DelegationError struct{}

func (DelegationError) Error() string {
	return "provider does not enforce bounded delegated authority"
}
func (DelegationError) Unwrap() error { return ErrCapabilityUnsupported }

func DelegationUnsupported() error { return DelegationError{} }

// HasDelegation also protects conversion, adoption and cleanup entry points:
// silently dropping this field would turn a constrained grant into an ordinary one.
func HasDelegation(model Model) bool {
	for _, permission := range model.Permissions {
		if permission.Delegation != nil {
			return true
		}
	}
	return false
}

func validateDelegation(permission Permission) error {
	d := permission.Delegation
	if d == nil {
		return nil
	}
	if len(permission.Resources) == 0 || d.MaxDepth < 1 || d.MaxDepth > 4 || d.MaxTTLSeconds < 1 || d.MaxTTLSeconds > 600 {
		return iamcontract.ErrRejected
	}
	for _, identity := range []Principal{d.Actor, d.Subject} {
		if (identity.Kind != "application" && identity.Kind != "service_account") || strings.TrimSpace(identity.Ref) == "" || identity.IncludeDescendants || identity.Organization != nil {
			return iamcontract.ErrRejected
		}
	}
	if d.Actor.Kind == d.Subject.Kind && d.Actor.Ref == d.Subject.Ref {
		return iamcontract.ErrRejected
	}
	return nil
}
