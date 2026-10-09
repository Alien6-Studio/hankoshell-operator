package keycloak

import (
	"encoding/json"
	"slices"
	"strings"
)

func observedOrganizationGroupRef(principal AuthorizationPrincipal, id string) string {
	if ref := principal.GroupRefs[id]; ref != "" {
		return ref
	}
	return principal.Ref
}

func authorizationPolicyPayload(policy authorizationPolicyRepresentation, kind string) any {
	if kind != "group" {
		return policy
	}
	// Keycloak PUT retains an existing claim override when this field is
	// omitted. Explicit empty clears it without changing role/client payloads.
	return struct {
		authorizationPolicyRepresentation
		GroupsClaim string `json:"groupsClaim"`
	}{policy, policy.GroupsClaim}
}

func consistentGroupPolicy(generic, typed authorizationPolicyRepresentation) (bool, error) {
	// Test fixtures may expose typed fields on both endpoints. Real Keycloak
	// generic policies encode group bindings in config.groups.
	groups := generic.Groups
	if encoded, exists := generic.Config["groups"]; exists {
		if json.Unmarshal([]byte(encoded), &groups) != nil {
			return false, ErrAuthorizationReadLimit
		}
	}
	if !slices.Equal(canonicalAuthorizationGroups(groups), canonicalAuthorizationGroups(typed.Groups)) {
		return false, nil
	}
	claim := generic.GroupsClaim
	if value, exists := generic.Config["groupsClaim"]; exists {
		claim = value
	}
	if claim != typed.GroupsClaim {
		return false, nil
	}
	return true, nil
}

func mergeTypedAuthorizationPolicies(index *authorizationPolicyIndex, policyType string, typed []authorizationPolicyRepresentation) error {
	seen := map[string]bool{}
	names := map[string]bool{}
	for _, item := range typed {
		if policyType == "group" {
			generic, exists := index.byID[item.ID]
			if seen[item.ID] || names[item.Name] || !exists || generic.Name != item.Name || generic.Type != "group" {
				return ErrAuthorizationReadLimit
			}
			consistent, err := consistentGroupPolicy(generic, item)
			if err != nil {
				return err
			}
			// Keycloak retains a deleted group's UUID in generic config while its
			// typed endpoint drops that binding. This can never prove InSync.
			// Manage may repair only an independently journal-owned identity;
			// complete, consistent read-back remains required after repair.
			item.Incomplete = !consistent
		}
		seen[item.ID] = true
		names[item.Name] = true
		item.Type = policyType
		index.byID[item.ID], index.byName[item.Name] = item, item
	}
	if policyType == "group" {
		for id, item := range index.byID {
			if item.Type == "group" && !seen[id] {
				return ErrAuthorizationReadLimit
			}
		}
	}
	return nil
}

func canonicalAuthorizationGroups(groups []AuthorizationGroupDefinition) []AuthorizationGroupDefinition {
	result := slices.Clone(groups)
	slices.SortFunc(result, func(a, b AuthorizationGroupDefinition) int {
		if n := strings.Compare(a.ID, b.ID); n != 0 {
			return n
		}
		if a.ExtendChildren == b.ExtendChildren {
			return 0
		}
		if a.ExtendChildren {
			return 1
		}
		return -1
	})
	return slices.Compact(result)
}
