package authorization

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// RoleDeclaration supplies safe declared labels only; it proves no provider edge.
type RoleDeclaration struct {
	Kind, Ref, Name, Client string
	Target                  bool
	ExpectedID              string `json:"-"`
}

// RoleProvenanceReader exposes focused read-only provider chains.
type RoleProvenanceReader interface {
	ReadRoleProvenance(context.Context, string, []VerifiedOrganization, []RoleDeclaration) ([]RoleBinding, []Finding)
}
type declaredRoleIndex struct {
	known              map[string]RoleStep
	ambiguous, targets map[string]bool
	expectedIDs        map[string]string
}

func indexDeclaredRoles(declarations []RoleDeclaration) declaredRoleIndex {
	index := declaredRoleIndex{known: map[string]RoleStep{}, ambiguous: map[string]bool{}, targets: map[string]bool{}, expectedIDs: map[string]string{}}
	for _, r := range declarations {
		if r.Target {
			index.targets[r.Name] = true
			index.expectedIDs[r.Name] = r.ExpectedID
		}
		key := r.Kind + "\x00" + r.Client + "\x00" + r.Name
		step := RoleStep{Kind: r.Kind, Ref: r.Ref, Client: r.Client}
		if old, ok := index.known[key]; ok && old != step {
			index.ambiguous[key] = true
		}
		index.known[key] = step
	}
	return index
}
func (i declaredRoleIndex) chain(path keycloak.GroupRolePath) ([]RoleStep, bool) {
	result := []RoleStep{}
	for _, role := range path.Roles {
		kind, client := "realm_role", ""
		if role.ClientRole {
			if !path.Roles[0].ClientRole || role.ContainerID != path.Roles[0].ContainerID {
				return nil, false
			}
			kind = "client_role"
			client = path.Client
		}
		key := kind + "\x00" + client + "\x00" + role.Name
		step, ok := i.known[key]
		if !ok || i.ambiguous[key] || strings.ContainsAny(step.Ref+step.Client, "\x00\r\n") {
			return nil, false
		}
		result = append(result, step)
	}
	return result, true
}
func groupRoleBindings(group string, paths []keycloak.GroupRolePath, index declaredRoleIndex) ([]RoleBinding, []Finding) {
	result := []RoleBinding{}
	findings := []Finding{}
	for _, path := range paths {
		target := path.Roles[len(path.Roles)-1]
		if target.ClientRole || !index.targets[target.Name] {
			continue
		}
		if index.expectedIDs[target.Name] == "" || index.expectedIDs[target.Name] != target.ID {
			findings = append(findings, ExplanationFinding("RoleProvenanceAmbiguous"))
			continue
		}
		chain, valid := index.chain(path)
		if !valid {
			findings = append(findings, ExplanationFinding("RoleProvenanceAmbiguous"))
			continue
		}
		result = append(result, RoleBinding{OrganizationRef: group, Target: target.Name, Chain: chain})
	}
	return result, findings
}
func (d *KeycloakDriver) ReadRoleProvenance(ctx context.Context, realm string, groups []VerifiedOrganization, declarations []RoleDeclaration) ([]RoleBinding, []Finding) {
	index := indexDeclaredRoles(declarations)
	result := []RoleBinding{}
	findings := []Finding{}
	for _, group := range groups {
		paths, err := d.client.GetGroupRoleProvenance(ctx, realm, group.Group.ID)
		if err != nil {
			code := "ProvenanceReadUnavailable"
			if errors.Is(err, keycloak.ErrRoleProvenanceIncomplete) {
				code = "CompositeClosureIncomplete"
			}
			findings = append(findings, ExplanationFinding(code))
			continue
		}
		bindings, gaps := groupRoleBindings(group.Group.Ref, paths, index)
		result = append(result, bindings...)
		findings = append(findings, gaps...)
	}
	// Declared descendants inherit provider group roles. Retain the observed
	// mapping source in ancestry instead of pretending the child directly maps it.
	if len(result) > 1024 {
		return result[:1024], append(findings, ExplanationFinding("CompositeClosureIncomplete"))
	}
	direct := slices.Clone(result)
	for _, group := range groups {
		result = append(result, inheritedRoleBindings(group, direct)...)
		if len(result) > 1024 {
			return result[:1024], append(findings, ExplanationFinding("CompositeClosureIncomplete"))
		}
	}
	return result, findings
}
func inheritedRoleBindings(group VerifiedOrganization, direct []RoleBinding) []RoleBinding {
	result := []RoleBinding{}
	for i, parent := range group.Ancestors {
		ancestry := []string{}
		for _, v := range group.Ancestors[i:] {
			ancestry = append(ancestry, v.Ref)
		}
		ancestry = append(ancestry, group.Group.Ref)
		for _, binding := range direct {
			if binding.OrganizationRef != parent.Ref {
				continue
			}
			binding.OrganizationRef = group.Group.Ref
			binding.Ancestry = ancestry
			result = append(result, binding)
		}
	}
	return result
}
