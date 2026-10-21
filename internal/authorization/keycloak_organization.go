package authorization

import (
	"context"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
)

func (d *KeycloakDriver) ReadOrganizationGroup(ctx context.Context, realm string, expected OrganizationGroup) (OrganizationGroup, error) {
	group, err := d.client.GetGroup(ctx, realm, expected.ID)
	if err != nil {
		return OrganizationGroup{}, OrganizationFailure("OrganizationReadUnavailable")
	}
	if group.ID != expected.ID || !organization.StrictOwnership(group.Attributes, expected.Ref, expected.Namespace, expected.UID) {
		return OrganizationGroup{}, OrganizationFailure("OrganizationOwnershipConflict")
	}
	if group.Name != expected.Name || group.Path != expected.Path {
		return OrganizationGroup{}, OrganizationFailure("OrganizationHierarchyMismatch")
	}
	byPath, err := d.client.GetGroupByPath(ctx, realm, expected.Path)
	if err != nil {
		return OrganizationGroup{}, OrganizationFailure("OrganizationReadUnavailable")
	}
	if byPath.ID != group.ID || byPath.Name != expected.Name || byPath.Path != expected.Path || !organization.StrictOwnership(byPath.Attributes, expected.Ref, expected.Namespace, expected.UID) {
		return OrganizationGroup{}, OrganizationFailure("OrganizationHierarchyMismatch")
	}
	return expected, nil
}

func keycloakPrincipal(principal Principal) keycloak.AuthorizationPrincipal {
	result := keycloak.AuthorizationPrincipal{Kind: principal.Kind, Ref: principal.Ref}
	if principal.Organization != nil {
		result.GroupRefs = map[string]string{}
		for _, group := range principal.Organization.Groups {
			result.Groups = append(result.Groups, keycloak.AuthorizationGroupDefinition{ID: group.ID, ExtendChildren: false})
			result.GroupRefs[group.ID] = group.Ref
		}
	}
	return result
}
