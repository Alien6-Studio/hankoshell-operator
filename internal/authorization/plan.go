package authorization

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// Intent has logical Hanko references; ResolvedReferences has provider-facing
// realm/role names and client identifiers. Neither has Secret dependencies.
type Intent struct{ model Model }
type ResolvedReferences struct{ model Model }

func Normalize(model Model) Intent {
	model = canonicalModel(model)
	for i := range model.Permissions {
		for j := range model.Permissions[i].Principals {
			model.Permissions[i].Principals[j].Organization = nil
		}
	}
	return Intent{model: model}
}

func (i Intent) Identity() iamcontract.Digest {
	data, _ := json.Marshal(i.model)
	return iamcontract.Hash(iamcontract.Version, "authorization", "intent", data)
}

// Resolve only permits relationship substitution, not a change in semantics.
func Resolve(intent Intent, model Model) (ResolvedReferences, error) {
	if !sameGraph(intent.model, model) {
		return ResolvedReferences{}, iamcontract.ErrStale
	}
	return ResolvedReferences{model: canonicalModel(model)}, nil
}
func sameGraph(a, b Model) bool {
	a = canonicalModel(a)
	b = canonicalModel(b)
	for _, m := range []*Model{&a, &b} {
		m.Realm = ""
		m.ApplicationRef = ""
		for i := range m.Permissions {
			for j := range m.Permissions[i].Principals {
				p := &m.Permissions[i].Principals[j]
				if p.Kind != "organization" {
					p.Ref = ""
				}
				p.Organization = nil
			}
			slices.SortFunc(m.Permissions[i].Principals, comparePrincipal)
		}
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// CapabilityEvidence distinguishes adapter semantics, tested qualification and
// runtime discovery. Keycloak uses static knowledge, never extra admin grants.
type CapabilityEvidence struct {
	Supported Capabilities
	Qualified bool
	Source    string
	Window    string
	Findings  []iamcontract.Finding
}

func KeycloakEvidence(caps Capabilities) CapabilityEvidence {
	return CapabilityEvidence{Supported: caps, Qualified: true, Source: "adapter-and-real-qualification", Window: "26.7.5,26.8.0"}
}

// Plan is an in-process sealed snapshot. JSON exposes identity only; it cannot
// reconstruct executable authority or carry provider payloads to Hub.
type Plan struct {
	identity      iamcontract.PlanIdentity
	intent        Intent
	resolved      ResolvedReferences
	evidence      CapabilityEvidence
	preconditions iamcontract.Preconditions
	required      Capabilities
}

func (p Plan) Evidence() CapabilityEvidence       { return p.evidence }
func (p Plan) Identity() iamcontract.PlanIdentity { return p.identity }
func (p Plan) MarshalJSON() ([]byte, error)       { return json.Marshal(p.identity) }
func (p Plan) Validate(current Plan) error {
	if p.identity.Contract != iamcontract.Version || p.identity != current.identity || p.preconditions != current.preconditions {
		return iamcontract.ErrStale
	}
	if err := iamcontract.Accept(current.evidence.Findings); err != nil {
		return err
	}
	return ValidateCapabilities(p.resolved.model, current.evidence.Supported)
}
func Compile(intent Intent, resolved ResolvedReferences, evidence CapabilityEvidence, pre iamcontract.Preconditions) (Plan, error) {
	if err := iamcontract.Accept(evidence.Findings); err != nil {
		return Plan{}, err
	}
	if err := validateModel(intent.model); err != nil {
		return Plan{}, err
	}
	if err := validateModel(resolved.model); err != nil {
		return Plan{}, err
	}
	if err := ValidateCapabilities(resolved.model, evidence.Supported); err != nil {
		return Plan{}, err
	}
	if err := validateOrganizations(resolved.model); err != nil {
		return Plan{}, err
	}
	if !sameGraph(intent.model, Normalize(resolved.model).model) {
		return Plan{}, iamcontract.ErrStale
	}
	required := requiredCapabilities(resolved.model)
	ib, _ := json.Marshal(intent.model)
	identity := iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: iamcontract.Hash(iamcontract.Version, "authorization", "intent", ib)}
	pb, _ := json.Marshal(struct {
		Intent     iamcontract.Digest
		Backend    iamcontract.BackendKind
		Required   Capabilities
		Resolved   Model
		References iamcontract.Digest
		Authority  iamcontract.Digest
	}{identity.Intent, identity.Backend, required, resolved.model, pre.References, pre.Authority})
	identity.Plan = iamcontract.Hash(iamcontract.Version, "authorization", "plan", pb)
	return Plan{identity: identity, intent: intent, resolved: resolved, evidence: evidence, preconditions: pre, required: required}, nil
}
func requiredCapabilities(m Model) Capabilities {
	c := Capabilities{ScopeGrants: len(m.Scopes) > 0, ResourceObjects: len(m.Resources) > 0}
	for _, r := range m.Resources {
		c.ResourceURIMatching = c.ResourceURIMatching || len(r.URIs) > 0
	}
	for _, p := range m.Permissions {
		for _, v := range p.Principals {
			switch v.Kind {
			case "realm_role":
				c.RolePrincipals = true
			case "application":
				c.ApplicationPrincipals = true
			case "service_account":
				c.ServiceAccountPrincipals = true
			case "organization":
				c.OrganizationPrincipals = true
				c.OrganizationDescendants = c.OrganizationDescendants || v.IncludeDescendants
			}
		}
	}
	return c
}

func knownSet(values []string, known map[string]bool) bool {
	for _, value := range values {
		if !known[value] {
			return false
		}
	}
	return true
}
func canonicalModel(m Model) Model {
	result := m
	result.Scopes = append([]Scope{}, m.Scopes...)
	slices.SortFunc(result.Scopes, func(a, b Scope) int { return strings.Compare(a.Name, b.Name) })
	result.Resources = append([]Resource{}, m.Resources...)
	for i := range result.Resources {
		result.Resources[i].URIs = stringSet(result.Resources[i].URIs)
		result.Resources[i].Scopes = stringSet(result.Resources[i].Scopes)
	}
	slices.SortFunc(result.Resources, func(a, b Resource) int { return strings.Compare(a.Name, b.Name) })
	result.Permissions = append([]Permission{}, m.Permissions...)
	for i := range result.Permissions {
		p := &result.Permissions[i]
		p.Resources = stringSet(p.Resources)
		p.Scopes = stringSet(p.Scopes)
		p.Principals = append([]Principal{}, p.Principals...)
		for j := range p.Principals {
			if o := p.Principals[j].Organization; o != nil {
				copy := *o
				copy.Groups = canonicalGroups(o.Groups)
				copy.Ancestors = canonicalGroups(o.Ancestors)
				p.Principals[j].Organization = &copy
			}
		}
		slices.SortFunc(p.Principals, comparePrincipal)
		p.Principals = slices.CompactFunc(p.Principals, func(a, b Principal) bool {
			return comparePrincipal(a, b) == 0 && a.IncludeDescendants == b.IncludeDescendants
		})
	}
	slices.SortFunc(result.Permissions, func(a, b Permission) int { return strings.Compare(a.Name, b.Name) })
	return result
}
func stringSet(v []string) []string {
	r := append([]string{}, v...)
	slices.Sort(r)
	return slices.Compact(r)
}
func comparePrincipal(a, b Principal) int {
	if c := strings.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	return strings.Compare(a.Ref, b.Ref)
}

func validateModel(m Model) error {
	if m.Name == "" || m.Realm == "" || m.ApplicationRef == "" || m.Audience == "" {
		return iamcontract.ErrRejected
	}
	scopes := map[string]bool{}
	resources := map[string]bool{}
	permissions := map[string]bool{}
	for _, s := range m.Scopes {
		if s.Name == "" || scopes[s.Name] {
			return iamcontract.ErrRejected
		}
		scopes[s.Name] = true
	}
	for _, r := range m.Resources {
		if r.Name == "" || resources[r.Name] {
			return iamcontract.ErrRejected
		}
		resources[r.Name] = true
		for _, s := range r.Scopes {
			if !scopes[s] {
				return iamcontract.ErrRejected
			}
		}
	}
	return validatePermissions(m.Permissions, scopes, resources, permissions)
}
func validatePermissions(desired []Permission, scopes, resources, permissions map[string]bool) error {
	for _, p := range desired {
		if p.Name == "" || permissions[p.Name] || len(p.Principals) == 0 || len(p.Scopes) == 0 {
			return iamcontract.ErrRejected
		}
		permissions[p.Name] = true
		if !knownSet(p.Resources, resources) || !knownSet(p.Scopes, scopes) {
			return iamcontract.ErrRejected
		}
		principalKeys := map[string]bool{}
		for _, v := range p.Principals {
			key := v.Kind + "\x00" + v.Ref
			if v.Ref == "" || principalKeys[key] || (v.IncludeDescendants && v.Kind != "organization") {
				return iamcontract.ErrRejected
			}
			principalKeys[key] = true
		}
	}
	return nil
}

func canonicalGroups(groups []OrganizationGroup) []OrganizationGroup {
	result := slices.Clone(groups)
	slices.SortFunc(result, func(a, b OrganizationGroup) int { return strings.Compare(a.Ref+"\x00"+a.ID, b.Ref+"\x00"+b.ID) })
	return result
}

func validateOrganizations(model Model) error {
	for _, permission := range model.Permissions {
		if err := validatePermissionOrganizations(permission); err != nil {
			return err
		}
	}
	if expectedPolicyCount(model.Permissions) > 256 {
		return OrganizationFailure("OrganizationPolicyBudgetExceeded")
	}
	return nil
}
func validatePermissionOrganizations(permission Permission) error {
	ids := map[string]bool{}
	for _, p := range permission.Principals {
		if p.Kind != "organization" {
			continue
		}
		if err := validateResolvedOrganization(p); err != nil {
			return err
		}
		for _, g := range p.Organization.Groups {
			ids[g.ID] = true
		}
	}
	if len(ids) > 128 {
		return OrganizationFailure("OrganizationExpansionTooLarge")
	}
	return nil
}
func validateResolvedOrganization(p Principal) error {
	if p.Organization == nil || len(p.Organization.Groups) == 0 || !iamcontract.ValidDigest(string(p.Organization.Graph)) {
		return OrganizationFailure("OrganizationNotCurrent")
	}
	if len(p.Organization.Groups) > 128 {
		return OrganizationFailure("OrganizationExpansionTooLarge")
	}
	if len(p.Organization.Ancestors) > 32 {
		return OrganizationFailure("OrganizationHierarchyTooDeep")
	}
	if !p.IncludeDescendants && len(p.Organization.Groups) != 1 {
		return OrganizationFailure("OrganizationPolicyUnsupported")
	}
	for _, g := range p.Organization.Groups {
		if g.ID == "" || g.UID == "" || g.Namespace == "" || g.Ref == "" || g.Path == "" {
			return OrganizationFailure("OrganizationOwnershipConflict")
		}
	}
	return nil
}
func expectedPolicyCount(permissions []Permission) int {
	count := 0
	for _, p := range permissions {
		kinds := map[string]bool{}
		for _, v := range p.Principals {
			kind := v.Kind
			if kind == "application" || kind == "service_account" {
				kind = "client"
			}
			kinds[kind] = true
		}
		count += len(kinds)
	}
	return count
}
