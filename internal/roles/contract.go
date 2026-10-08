// Package roles separates portable realm-role semantics from Keycloak mapping.
package roles

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

var ErrOwnershipConflict = errors.New("role is not owned by this HankoRole")

const OwnerAttribute = "hanko.sh/role-owner"

// Intent contains portable semantics. Composites are an additive set; provider
// composites outside this set remain intact, matching the existing contract.
type Intent struct {
	RealmRef    string
	Name        string
	Description string
	Composite   bool
	Composites  []string
}

// ResolvedReferences contains no Kubernetes name lookup or credentials. Owner
// is a local resource identity, not portable meaning. Native attributes remain
// private metadata; they are never copied into evidence, status or logs.
type ResolvedReferences struct {
	Realm      string
	Owner      string
	Attributes map[string][]string
}
type Capabilities struct{ RealmRoles, Composites, NativeAttributes bool }
type CapabilityEvidence struct {
	Supported      Capabilities
	Source, Window string
	Findings       []iamcontract.Finding
}

func KeycloakEvidence() CapabilityEvidence {
	return CapabilityEvidence{Supported: Capabilities{true, true, true}, Source: "adapter-and-real-qualification", Window: "26.7.5,26.8.0"}
}

type State struct{ Present, Owned, Drifted bool }

// Driver is role-domain-specific. AuthorityClosure returns names for local
// authority validation; the adapter owns provider traversal and ID mapping.
type Driver interface {
	Capabilities(context.Context) (CapabilityEvidence, error)
	Observe(context.Context, Plan) (State, error)
	Reconcile(context.Context, Plan) (State, error)
	DeleteOwned(context.Context, Plan) error
	AuthorityClosure(context.Context, string, string) ([]string, error)
}
type Plan struct {
	identity      iamcontract.PlanIdentity
	intent        Intent
	resolved      ResolvedReferences
	evidence      CapabilityEvidence
	preconditions iamcontract.Preconditions
}

func (p Plan) Identity() iamcontract.PlanIdentity { return p.identity }
func (p Plan) MarshalJSON() ([]byte, error)       { return json.Marshal(p.identity) }
func (p Plan) Validate(current Plan) error {
	if p.identity.Contract != iamcontract.Version || p.identity != current.identity || p.preconditions != current.preconditions {
		return iamcontract.ErrStale
	}
	if err := iamcontract.Accept(current.evidence.Findings); err != nil {
		return err
	}
	return validate(p.intent, p.resolved, current.evidence)
}
func Normalize(i Intent) Intent {
	i.Composites = append([]string{}, i.Composites...)
	slices.Sort(i.Composites)
	i.Composites = slices.Compact(i.Composites)
	// Existing reconciliation adds declared composites regardless of the flag.
	i.Composite = i.Composite || len(i.Composites) > 0
	return i
}
func Compile(i Intent, r ResolvedReferences, e CapabilityEvidence, pre iamcontract.Preconditions) (Plan, error) {
	i = Normalize(i)
	r.Attributes = cloneAttributes(r.Attributes)
	if err := iamcontract.Accept(e.Findings); err != nil {
		return Plan{}, err
	}
	if err := validate(i, r, e); err != nil {
		return Plan{}, err
	}
	ib, _ := json.Marshal(i)
	id := iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: iamcontract.Hash(iamcontract.Version, "roles", "intent", ib)}
	// Native attribute values are lists of metadata: order is retained, while map
	// key order is canonical JSON. Nil/empty collections are equivalent.
	required := Capabilities{RealmRoles: true, Composites: len(i.Composites) > 0 || i.Composite, NativeAttributes: len(r.Attributes) > 0}
	pb, _ := json.Marshal(struct {
		Intent   iamcontract.Digest
		Backend  iamcontract.BackendKind
		Required Capabilities
		Resolved ResolvedReferences
	}{id.Intent, id.Backend, required, r})
	id.Plan = iamcontract.Hash(iamcontract.Version, "roles", "plan", pb)
	return Plan{identity: id, intent: i, resolved: r, evidence: e, preconditions: pre}, nil
}
func validate(i Intent, r ResolvedReferences, e CapabilityEvidence) error {
	if i.Name == "" || i.RealmRef == "" || r.Realm == "" || r.Owner == "" || !e.Supported.RealmRoles {
		return iamcontract.ErrRejected
	}
	if (i.Composite || len(i.Composites) > 0) && !e.Supported.Composites {
		return iamcontract.ErrRejected
	}
	if len(r.Attributes) > 0 && !e.Supported.NativeAttributes {
		return iamcontract.ErrRejected
	}
	if err := validateNativeAttributes(r.Attributes); err != nil {
		return err
	}
	for _, c := range i.Composites {
		if c == "" || c == i.Name {
			return iamcontract.ErrRejected
		}
	}
	return nil
}
func cloneAttributes(v map[string][]string) map[string][]string {
	result := maps.Clone(v)
	if result == nil {
		result = map[string][]string{}
	}
	for k, values := range result {
		result[k] = append([]string{}, values...)
	}
	return result
}

func validateNativeAttributes(attributes map[string][]string) error {
	if _, exists := attributes[OwnerAttribute]; exists {
		return iamcontract.ErrRejected
	}
	for k := range attributes {
		switch strings.ToLower(k) {
		case "password", "client_secret", "client-secret", "access_token", "bearer-token", "private_key", "private-key", "credential":
			return iamcontract.ErrRejected
		}
	}
	return nil
}
