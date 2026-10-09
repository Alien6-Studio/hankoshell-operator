package authorization

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// Explanation is bounded structural evidence, never a runtime subject decision
// or adoption, execution or deletion authority. Source is stamped from read-back.
type Explanation struct {
	SourceGeneration      int64             `json:"sourceGeneration"`
	SourcePlanHash        string            `json:"sourcePlanHash"`
	SourceObservationHash string            `json:"sourceObservationHash"`
	Source                string            `json:"source"`
	Complete              bool              `json:"complete"`
	Truncated             bool              `json:"truncated"`
	ExplanationHash       string            `json:"explanationHash"`
	Paths                 []ExplanationPath `json:"paths"`
}
type ExplanationPath struct {
	Permission      string     `json:"permission"`
	Resource        string     `json:"resource"`
	Action          string     `json:"action"`
	SourceKind      string     `json:"sourceKind"`
	SourceRef       string     `json:"sourceRef"`
	OrganizationRef string     `json:"organizationRef,omitempty"`
	Relationship    string     `json:"relationship"`
	Ancestry        []string   `json:"ancestry,omitempty"`
	RoleChain       []RoleStep `json:"roleChain,omitempty"`
}
type RoleStep struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Client string `json:"client,omitempty"`
}

// StructuralObservation is private normalized provider evidence. Unknown raw
// principal values and IDs never cross this domain boundary.
type StructuralObservation struct {
	Enabled     bool
	Complete    bool
	Native      bool
	Resources   []ObservedResource
	Policies    []ObservedPolicy
	Permissions []ObservedPermission
}
type ObservedResource struct {
	Name          string
	Present       bool
	Scopes        []string
	UnknownScopes int
}
type ObservedPolicy struct {
	Name, Type, Logic, DecisionStrategy   string
	Present, Owned, GroupsClaimConfigured bool
	Principals                            []string
	UnknownPrincipals                     int
}
type ObservedPermission struct {
	Name, Type, Logic, DecisionStrategy string
	Present, Owned                      bool
	Resources, Scopes, Policies         []string
	UnknownBindings                     int
}

// VerifiedOrganization contains current strict ownership and declared ancestry.
// Role bindings are observed direct group mappings plus proven composite edges.
type VerifiedOrganization struct {
	Group     OrganizationGroup
	Ancestors []OrganizationGroup
}
type RoleBinding struct {
	OrganizationRef, Target string
	Chain                   []RoleStep
	Ancestry                []string
}
type ExplanationEvidence struct {
	Organizations []VerifiedOrganization
	Roles         []RoleBinding
	Findings      []Finding
	Complete      bool
}

func ExplanationFinding(code string) Finding {
	messages := map[string]string{
		"ExplanationIncomplete":          "structural authorization observation has unresolved bindings",
		"ExplanationTruncated":           "structural explanation exceeds its bounded path budget",
		"ProvenanceReadUnavailable":      "optional role provenance read is unavailable; authorization synchronization is independent",
		"NativeAuthorizationUnexplained": "provider-native authorization may supply additional paths outside the portable model",
		"RoleProvenanceAmbiguous":        "an observed role chain cannot be safely mapped to declared role identities",
		"CompositeClosureIncomplete":     "role provenance traversal is cyclic, incomplete or exceeds its budget",
		"OrganizationProvenanceStale":    "organization provenance dependencies are not current or changed during observation",
	}
	message, ok := messages[code]
	if !ok {
		code = "ExplanationIncomplete"
		message = messages[code]
	}
	return Finding{Classification: iamcontract.Unsupported, ObjectKind: "authorization_explanation", Code: code, Message: message, ReadOnly: true}
}

// Explain consumes observed bindings rather than constructing grants from YAML.
// Desired refs identify only the portable labels of independently proven edges.
func Explain(plan Plan, state State, evidence ExplanationEvidence, generation int64, applied bool) Explanation {
	result := Explanation{SourceGeneration: generation, SourcePlanHash: string(plan.Identity().Plan), SourceObservationHash: string(state.Observation.StateHash), Source: "Observed", Paths: []ExplanationPath{}}
	if applied && state.Observation.Complete && !state.Observation.Drifted {
		result.Source = "Applied"
	}
	evidence = canonicalExplanationEvidence(evidence)
	// Bind the authorization binding observation and additional privately verified
	// provenance snapshot. The ordinary observedStateHash remains independent of
	// optional deeper reads, preserving authorization availability and proof.
	snapshot, _ := json.Marshal(struct {
		Authorization iamcontract.Digest
		Evidence      ExplanationEvidence
		Native        bool
	}{state.Observation.StateHash, evidence, state.Structure != nil && state.Structure.Native})
	result.SourceObservationHash = string(iamcontract.Hash(iamcontract.Version, "authorization", "explanation-observation", snapshot))
	graph := state.Structure
	result.Complete = evidence.Complete && graph != nil && state.Observation.Complete && graph.Complete && !graph.Native
	if graph == nil {
		return normalizeExplanation(result)
	}
	if !graph.Enabled {
		return normalizeExplanation(result)
	}

	builder := explanationBuilder{result: &result, evidence: evidence, resources: map[string]ObservedResource{}, policies: map[string]ObservedPolicy{}, permissions: map[string]Permission{}}
	for _, r := range graph.Resources {
		builder.resources[r.Name] = r
	}
	for _, p := range graph.Policies {
		builder.policies[p.Name] = p
	}
	for _, p := range plan.resolved.model.Permissions {
		builder.permissions[p.Name] = p
	}
	for _, p := range graph.Permissions {
		builder.permission(p)
	}
	return normalizeExplanation(result)
}

type explanationBuilder struct {
	result      *Explanation
	evidence    ExplanationEvidence
	resources   map[string]ObservedResource
	policies    map[string]ObservedPolicy
	permissions map[string]Permission
}

func (b *explanationBuilder) permission(p ObservedPermission) {
	want, declared := b.permissions[p.Name]
	if !declared || !p.Present {
		return
	}
	if !p.Owned || p.Type != "scope" || p.Logic != "POSITIVE" || p.DecisionStrategy != "AFFIRMATIVE" || p.UnknownBindings > 0 {
		b.result.Complete = false
		return
	}
	selected := slices.Clone(p.Resources)
	if len(selected) == 0 {
		for name, r := range b.resources {
			if r.Present {
				selected = append(selected, name)
			}
		}
	}
	for _, name := range stringSet(selected) {
		b.resource(p, want, name)
	}
}
func (b *explanationBuilder) resource(p ObservedPermission, want Permission, name string) {
	resource, ok := b.resources[name]
	if !ok || !resource.Present || resource.UnknownScopes > 0 {
		b.result.Complete = false
		return
	}
	for _, action := range stringSet(p.Scopes) {
		if !slices.Contains(resource.Scopes, action) {
			continue
		}
		for _, policy := range p.Policies {
			b.policy(p, want, name, action, policy)
		}
	}
}
func (b *explanationBuilder) policy(p ObservedPermission, want Permission, resource, action, policyName string) {
	policy, ok := b.policies[policyName]
	if !ok || !policy.Present || !policy.Owned || policy.Logic != "POSITIVE" || policy.UnknownPrincipals > 0 || policy.DecisionStrategy != "AFFIRMATIVE" || !supportedObservedPolicy(policy) {
		b.result.Complete = false
		return
	}
	proven := false
	for _, principal := range want.Principals {
		paths, complete := principalPaths(principal, policy, b.evidence)
		b.result.Complete = b.result.Complete && complete
		proven = proven || len(paths) > 0
		for _, path := range paths {
			path.Permission = p.Name
			path.Resource = resource
			path.Action = action
			b.addPath(path)
		}
	}
	if !proven && len(policy.Principals) > 0 {
		b.result.Complete = false
	}
}

// Keep a deterministic top-256 set while traversing bounded observations rather
// than allocating the complete resource/action/provenance Cartesian expansion.
func (b *explanationBuilder) addPath(path ExplanationPath) {
	if len(path.Ancestry) > 33 || len(path.RoleChain) > 33 || !boundedPath(path) {
		b.result.Complete = false
		b.result.Truncated = true
		return
	}
	key := pathKey(path)
	index, found := slices.BinarySearchFunc(b.result.Paths, key, func(value ExplanationPath, key string) int { return strings.Compare(pathKey(value), key) })
	if found {
		return
	}
	if len(b.result.Paths) >= 256 {
		b.result.Truncated = true
		b.result.Complete = false
		if index >= 256 {
			return
		}
		b.result.Paths = b.result.Paths[:255]
	}
	b.result.Paths = slices.Insert(b.result.Paths, index, path)
}
func principalPaths(p Principal, policy ObservedPolicy, e ExplanationEvidence) ([]ExplanationPath, bool) {
	ref := p.PortableRef
	if ref == "" {
		ref = p.Ref
	}
	base := ExplanationPath{SourceKind: p.Kind, SourceRef: ref, Relationship: "generic"}
	switch p.Kind {
	case "application", "service_account":
		if policy.Type == "client" && slices.Contains(policy.Principals, "client/"+p.Ref) {
			return []ExplanationPath{base}, true
		}
	case "realm_role":
		return rolePrincipalPaths(p, policy, e, base)
	case "organization":
		return organizationPrincipalPaths(p, policy, e, base)
	}
	return nil, true
}
func rolePrincipalPaths(p Principal, policy ObservedPolicy, e ExplanationEvidence, base ExplanationPath) ([]ExplanationPath, bool) {
	if policy.Type != "role" || !slices.Contains(policy.Principals, "realm_role/"+p.Ref+"/required=false") {
		return nil, true
	}
	paths := []ExplanationPath{base}
	for _, binding := range e.Roles {
		if binding.Target != p.Ref {
			continue
		}
		path := base
		path.OrganizationRef = binding.OrganizationRef
		path.RoleChain = slices.Clone(binding.Chain)
		path.Ancestry = slices.Clone(binding.Ancestry)
		path.Relationship = "mapped_role"
		if len(binding.Chain) > 1 {
			path.Relationship = "mapped_composite_role"
		}
		if len(binding.Chain) > 0 && binding.Chain[0].Kind == "client_role" {
			path.Relationship = "mapped_client_role"
		}
		paths = append(paths, path)
	}
	return paths, true
}
func organizationPrincipalPaths(p Principal, policy ObservedPolicy, e ExplanationEvidence, base ExplanationPath) ([]ExplanationPath, bool) {
	if policy.Type != "group" {
		return nil, true
	}
	if policy.GroupsClaimConfigured || p.Organization == nil {
		return nil, false
	}
	paths := []ExplanationPath{}
	for _, group := range p.Organization.Groups {
		if !slices.Contains(policy.Principals, "organization/"+group.Ref+"/extendChildren=false") {
			continue
		}
		path, ok := organizationPath(p, e, base, group.Ref)
		if !ok {
			return paths, false
		}
		paths = append(paths, path)
	}
	return paths, true
}
func organizationPath(p Principal, e ExplanationEvidence, base ExplanationPath, ref string) (ExplanationPath, bool) {
	base.OrganizationRef = ref
	base.Relationship = "direct"
	if ref == p.Ref {
		return base, true
	}
	ancestry, ok := organizationAncestry(e.Organizations, p.Ref, ref)
	if !p.IncludeDescendants || !ok {
		return base, false
	}
	base.Relationship = "descendant"
	base.Ancestry = ancestry
	return base, true
}

func organizationAncestry(groups []VerifiedOrganization, root, ref string) ([]string, bool) {
	for _, o := range groups {
		if o.Group.Ref != ref {
			continue
		}
		ancestry := []string{}
		for _, parent := range o.Ancestors {
			ancestry = append(ancestry, parent.Ref)
		}
		ancestry = append(ancestry, ref)
		for i, name := range ancestry {
			if name == root {
				return slices.Clone(ancestry[i:]), len(ancestry[i:]) <= 33
			}
		}
	}
	return nil, false
}
func pathKey(p ExplanationPath) string {
	ancestry, _ := json.Marshal(p.Ancestry)
	roles, _ := json.Marshal(p.RoleChain)
	return strings.Join([]string{p.Permission, p.Resource, p.Action, p.SourceKind, p.SourceRef, p.OrganizationRef, p.Relationship, string(ancestry), string(roles)}, "\x00")
}
func normalizeExplanation(e Explanation) Explanation {
	valid := []ExplanationPath{}
	for _, p := range e.Paths {
		if len(p.Ancestry) > 33 || len(p.RoleChain) > 33 || !boundedPath(p) {
			e.Complete = false
			e.Truncated = true
			continue
		}
		if len(p.Ancestry) == 0 {
			p.Ancestry = nil
		}
		if len(p.RoleChain) == 0 {
			p.RoleChain = nil
		}
		valid = append(valid, p)
	}
	slices.SortFunc(valid, func(a, b ExplanationPath) int { return strings.Compare(pathKey(a), pathKey(b)) })
	valid = slices.CompactFunc(valid, func(a, b ExplanationPath) bool { return pathKey(a) == pathKey(b) })
	if len(valid) > 256 {
		valid = valid[:256]
		e.Truncated = true
		e.Complete = false
	}
	// The path-count bound alone permits large strings/chains. Keep serialized
	// explanation below 192 KiB so public status stays within API storage budgets.
	bytesUsed := 2048
	sizeBound := 0
	for _, path := range valid {
		bytes, _ := json.Marshal(path)
		if bytesUsed+len(bytes)+1 > 192*1024 {
			e.Truncated = true
			e.Complete = false
			break
		}
		bytesUsed += len(bytes) + 1
		sizeBound++
	}
	e.Paths = valid[:sizeBound]
	e.ExplanationHash = ""
	bytes, _ := json.Marshal(e)
	e.ExplanationHash = string(iamcontract.Hash(iamcontract.Version, "authorization", "explanation", bytes))
	return e
}
func boundedPath(p ExplanationPath) bool {
	for _, s := range append([]string{p.Permission, p.Resource, p.Action, p.SourceRef, p.OrganizationRef}, p.Ancestry...) {
		if len(s) > 255 || strings.ContainsAny(s, "\x00\r\n") {
			return false
		}
	}
	for _, r := range p.RoleChain {
		if len(r.Ref) > 255 || len(r.Client) > 255 || strings.ContainsAny(r.Ref+r.Client, "\x00\r\n") {
			return false
		}
	}
	return true
}

func supportedObservedPolicy(p ObservedPolicy) bool {
	if p.GroupsClaimConfigured {
		return false
	}
	for _, v := range p.Principals {
		switch p.Type {
		case "group":
			if !strings.HasPrefix(v, "organization/") || !strings.HasSuffix(v, "/extendChildren=false") {
				return false
			}
		case "role":
			if !strings.HasPrefix(v, "realm_role/") || !strings.HasSuffix(v, "/required=false") {
				return false
			}
		case "client":
			if !strings.HasPrefix(v, "client/") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func canonicalExplanationEvidence(e ExplanationEvidence) ExplanationEvidence {
	e.Organizations = slices.Clone(e.Organizations)
	slices.SortFunc(e.Organizations, func(a, b VerifiedOrganization) int { return strings.Compare(a.Group.Ref, b.Group.Ref) })
	e.Roles = slices.Clone(e.Roles)
	slices.SortFunc(e.Roles, func(a, b RoleBinding) int {
		aBytes, _ := json.Marshal(a)
		bBytes, _ := json.Marshal(b)
		return strings.Compare(string(aBytes), string(bBytes))
	})
	e.Roles = slices.CompactFunc(e.Roles, func(a, b RoleBinding) bool {
		aBytes, _ := json.Marshal(a)
		bBytes, _ := json.Marshal(b)
		return string(aBytes) == string(bBytes)
	})
	e.Findings = iamcontract.Findings(e.Findings)
	return e
}
