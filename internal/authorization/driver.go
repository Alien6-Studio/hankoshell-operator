// Package authorization defines the provider-neutral operator contract for
// protected API authorization. Provider adapters own all external API calls;
// reconcilers only validate Kubernetes references and drive this interface.
package authorization

import (
	"context"
	"errors"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// ErrCapabilityUnsupported is returned before mutation when desired semantics
// cannot be represented by the selected provider.
var ErrCapabilityUnsupported = errors.New("authorization capability unsupported")

// ErrOwnershipConflict reports a same-named provider object which is not in the
// CR status ownership set. Such objects are never adopted implicitly.
var ErrOwnershipConflict = errors.New("authorization object is not owned by Hanko")

// Capabilities declares provider semantics explicitly.
type Capabilities struct {
	OrganizationPrincipals   bool `json:",omitempty"`
	OrganizationDescendants  bool `json:",omitempty"`
	ScopeGrants              bool
	RolePrincipals           bool
	ApplicationPrincipals    bool
	ServiceAccountPrincipals bool
	ResourceObjects          bool
	ResourceURIMatching      bool
	UMARPT                   bool
	NativePermissionClaim    bool
}

// Model is the portable desired state passed to a provider driver.
type Model struct {
	Name           string
	Realm          string
	Audience       string
	DisplayName    string
	ApplicationRef string
	Scopes         []Scope
	Resources      []Resource
	Permissions    []Permission
}

type Scope struct {
	Name        string
	Description string
}

type Resource struct {
	Name        string
	DisplayName string
	URIs        []string
	Type        string
	Scopes      []string
}

type Permission struct {
	Name       string
	Resources  []string
	Scopes     []string
	Principals []Principal
}

type Principal struct {
	Kind               string
	Ref                string
	PortableRef        string `json:",omitempty"`
	IncludeDescendants bool   `json:",omitempty"`
	// Organization is private execution evidence; Normalize removes it from intent.
	Organization *ResolvedOrganizationPrincipal `json:",omitempty"`
}

// ResolvedOrganizationPrincipal keeps verified execution groups separate from
// the portable object reference. Graph binds the complete bounded namespace
// inventory; Ancestors binds verified structural ancestors without granting them.
type ResolvedOrganizationPrincipal struct {
	Groups    []OrganizationGroup
	Ancestors []OrganizationGroup
	Graph     iamcontract.Digest
}

// OrganizationGroup is independently verified provider evidence, never public
// desired state, status authority or a subject/membership inventory.
type OrganizationGroup struct {
	Ref, Namespace, UID, ID, Name, Path string
}

// OrganizationGroupReader provides current strict ownership/hierarchy reads.
// Capability support alone does not imply that the credential can perform them.
type OrganizationGroupReader interface {
	ReadOrganizationGroup(context.Context, string, OrganizationGroup) (OrganizationGroup, error)
}

// ManagedObjects is the complete provider object ownership set. IDs originate
// from provider create responses and are safe deletion targets for this CR.
type ManagedObjects struct {
	ResourceServerID string
	Scopes           []ManagedReference
	Resources        []ManagedReference
	Policies         []ManagedReference
	Permissions      []ManagedReference
}

type ManagedReference struct {
	Name string
	ID   string
}

// State is the read-back provider observation after reconciliation.
type State struct {
	ProviderResourceServerID string
	Drifted                  bool
	Observation              iamcontract.Observation
	Capabilities             Capabilities
	ManagedObjects           ManagedObjects
	Structure                *StructuralObservation
	RealmRoleIDs             map[string]string `json:"-"`
	Findings                 []Finding
}

type Finding = iamcontract.Finding

// Driver is implemented once per provider. Reconcile must be idempotent and
// DeleteOwned must ignore every provider object absent from owned.
type Driver interface {
	Capabilities(context.Context, string) (Capabilities, error)
	Observe(context.Context, Plan) (State, error)
	Reconcile(context.Context, Plan, ManagedObjects) (State, error)
	DeleteOwned(context.Context, Model, ManagedObjects, string) error
}

// ValidateCapabilities rejects unsupported desired state without mutation.
func ValidateCapabilities(model Model, capabilities Capabilities) error {
	if len(model.Scopes) > 0 && !capabilities.ScopeGrants {
		return errors.Join(ErrCapabilityUnsupported, errors.New("scope_grants is required"))
	}
	if len(model.Resources) > 0 && !capabilities.ResourceObjects {
		return errors.Join(ErrCapabilityUnsupported, errors.New("resource_objects is required"))
	}
	for _, resource := range model.Resources {
		if len(resource.URIs) > 0 && !capabilities.ResourceURIMatching {
			return errors.Join(ErrCapabilityUnsupported, errors.New("resource_uri_matching is required"))
		}
	}
	for _, permission := range model.Permissions {
		for _, principal := range permission.Principals {
			supported := map[string]bool{
				"realm_role":      capabilities.RolePrincipals,
				"application":     capabilities.ApplicationPrincipals,
				"service_account": capabilities.ServiceAccountPrincipals,
				"organization":    capabilities.OrganizationPrincipals,
			}[principal.Kind]
			if !supported {
				return errors.Join(ErrCapabilityUnsupported, errors.New("principal semantics are unsupported"))
			}
			if principal.IncludeDescendants && (principal.Kind != "organization" || !capabilities.OrganizationDescendants) {
				return ErrCapabilityUnsupported
			}
		}
	}
	return nil
}

// BoundedManagedObjects refuses oversized operational evidence. Ownership must
// never be silently truncated, since that would lose cleanup/retry boundaries.
func BoundedManagedObjects(objects ManagedObjects) bool {
	if len(objects.ResourceServerID) > 128 {
		return false
	}
	for _, group := range []struct {
		refs  []ManagedReference
		limit int
	}{{objects.Scopes, 64}, {objects.Resources, 64}, {objects.Policies, 256}, {objects.Permissions, 128}} {
		if len(group.refs) > group.limit {
			return false
		}
		seen := map[string]bool{}
		for _, ref := range group.refs {
			if ref.Name == "" || ref.ID == "" || len(ref.Name) > 512 || len(ref.ID) > 128 || seen[ref.Name] {
				return false
			}
			seen[ref.Name] = true
		}
	}
	return true
}
