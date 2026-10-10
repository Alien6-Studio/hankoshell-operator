package keycloak

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
)

// InventoryClient deliberately cannot deserialize client secrets. Presence of
// native certificates is classified later; their bytes never leave projection.
type InventoryClient struct {
	Application
	AuthorizationServicesEnabled bool `json:"authorizationServicesEnabled"`
	UnqualifiedNative            bool `json:"-"`
}

func (c *InventoryClient) UnmarshalJSON(data []byte) error {
	type projection InventoryClient
	var typed projection
	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}
	var native map[string]any
	if err := json.Unmarshal(data, &native); err != nil {
		return err
	}
	delete(native, "secret")
	delete(native, "access")
	*c = InventoryClient(typed)
	c.UnqualifiedNative = !(&ClientOwnershipSnapshot{Application: c.Application, document: native}).QualifiedLeaf()
	return nil
}

// InventoryClients walks the whole bounded collection; a brief first page is
// never proof of full client semantics. Every selected client gets an exact GET.
func (c *Client) InventoryClients(ctx context.Context, realm string) ([]InventoryClient, error) {
	var listed []InventoryClient
	path := adminRealmsPath + url.PathEscape(realm) + "/clients"
	if err := readAuthorizationCollection(ctx, c, path, &listed); err != nil {
		return nil, err
	}
	slices.SortFunc(listed, func(a, b InventoryClient) int {
		if a.ClientID < b.ClientID {
			return -1
		}
		if a.ClientID > b.ClientID {
			return 1
		}
		return 0
	})
	seenIDs, seenNames := map[string]bool{}, map[string]bool{}
	for i, item := range listed {
		if seenIDs[item.ID] || seenNames[item.ClientID] {
			return nil, ErrApplicationPrecondition
		}
		seenIDs[item.ID] = true
		seenNames[item.ClientID] = true
		var full InventoryClient
		if item.ID == "" {
			return nil, ErrApplicationPrecondition
		}
		if err := c.get(ctx, applicationPath(realm, item.ID), &full); err != nil {
			return nil, err
		}
		if full.ID != item.ID || full.ClientID != item.ClientID {
			return nil, ErrApplicationPrecondition
		}
		listed[i] = full
	}
	return listed, nil
}

func (c *Client) InventoryRealmRoles(ctx context.Context, realm string) ([]RealmRole, error) {
	var roles []RealmRole
	err := readAuthorizationCollection(ctx, c, adminRealmsPath+url.PathEscape(realm)+"/roles?briefRepresentation=false", &roles)
	return roles, err
}

func (c *Client) InventoryClientRoles(ctx context.Context, realm, id string) ([]RealmRole, error) {
	var roles []RealmRole
	err := readAuthorizationCollection(ctx, c, applicationPath(realm, id)+"/roles?briefRepresentation=false", &roles)
	return roles, err
}

// InventoryRoleChildren returns direct typed identities, including client-role
// children. The observer bounds depth and nodes separately from HTTP bytes.
func (c *Client) InventoryRoleChildren(ctx context.Context, realm string, role RealmRole) ([]RealmRole, error) {
	path := adminRealmsPath + url.PathEscape(realm) + rolesSegment + url.PathEscape(role.Name)
	if role.ClientRole {
		path = applicationPath(realm, role.ContainerID) + rolesSegment + url.PathEscape(role.Name)
	}
	var children []RealmRole
	err := c.get(ctx, path+"/composites", &children)
	return children, err
}

func (c *Client) InventoryGroups(ctx context.Context, realm, parent string) ([]Group, error) {
	path := adminRealmsPath + url.PathEscape(realm) + "/groups?briefRepresentation=false&populateHierarchy=false"
	if parent != "" {
		path = adminRealmsPath + url.PathEscape(realm) + groupsSegment + url.PathEscape(parent) + "/children?briefRepresentation=false"
	}
	var groups []Group
	err := readAuthorizationCollection(ctx, c, path, &groups)
	return groups, err
}

// InventoryGroupRoles reads mappings only, never group members or users.
func (c *Client) InventoryGroupRoles(ctx context.Context, realm, id string) ([]RealmRole, error) {
	mappings, err := c.groupRoleMappings(ctx, realm, id)
	if err != nil {
		return nil, err
	}
	roles := append([]RealmRole(nil), mappings.RealmMappings...)
	for id, mapping := range mappings.ClientMappings {
		for _, role := range mapping.Mappings {
			role.ClientRole = true
			role.ContainerID = id
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func (c *Client) InventoryOrganizations(ctx context.Context, realm string) ([]Organization, error) {
	var organizations []Organization
	err := readAuthorizationCollection(ctx, c, adminRealmsPath+url.PathEscape(realm)+"/organizations", &organizations)
	return organizations, err
}

// InventoryAuthorizationGraph reuses the qualified paginated and typed graph
// readers. It does not load/write an ownership journal or infer graph ownership.
type InventoryAuthorizationGraph struct {
	Scopes      []InventoryAuthorizationScope
	Resources   []InventoryAuthorizationResource
	Policies    []InventoryAuthorizationPolicy
	Permissions []InventoryAuthorizationPermission
}
type InventoryAuthorizationScope = authorizationScopeRepresentation
type InventoryAuthorizationResource = authorizationResourceRepresentation
type InventoryAuthorizationPolicy = authorizationPolicyRepresentation
type InventoryAuthorizationPermission = authorizationPermissionRepresentation

func (c *Client) InventoryAuthorization(ctx context.Context, realm, id string) (InventoryAuthorizationGraph, error) {
	base := authorizationBase(realm, id)
	g := InventoryAuthorizationGraph{}
	if err := readAuthorizationCollection(ctx, c, base+authorizationScopePath, &g.Scopes); err != nil {
		return g, err
	}
	if len(g.Scopes) > 64 {
		return g, ErrAuthorizationReadLimit
	}
	if err := readAuthorizationCollection(ctx, c, base+authorizationResourcePath, &g.Resources); err != nil {
		return g, err
	}
	if len(g.Resources) > 64 {
		return g, ErrAuthorizationReadLimit
	}
	policies, err := c.loadAuthorizationPolicies(ctx, base)
	if err != nil {
		return g, err
	}
	if len(policies.byID) > 256 {
		return g, ErrAuthorizationReadLimit
	}
	for _, p := range policies.byID {
		var associated []struct {
			ID string `json:"id"`
		}
		if err := c.get(ctx, base+authorizationPolicyPath+"/"+url.PathEscape(p.ID)+"/associatedPolicies", &associated); err != nil {
			return g, err
		}
		if len(associated) > 1024 {
			return g, ErrAuthorizationReadLimit
		}
		for _, child := range associated {
			if child.ID == "" {
				return g, ErrAuthorizationReadLimit
			}
			p.AssociatedPolicies = append(p.AssociatedPolicies, child.ID)
		}
		g.Policies = append(g.Policies, p)
	}
	_, permissions, err := c.loadAuthorizationPermissions(ctx, base)
	if err != nil {
		return g, err
	}
	if len(permissions) > 128 {
		return g, ErrAuthorizationReadLimit
	}
	for _, p := range permissions {
		g.Permissions = append(g.Permissions, p)
	}
	return g, nil
}

// InventoryOrganizationsEnabled avoids a misleading 404 when the optional
// Keycloak Organizations feature is disabled. No realm mutation is performed.
func (c *Client) InventoryOrganizationsEnabled(ctx context.Context, realm string) (bool, error) {
	var rep struct {
		OrganizationsEnabled bool `json:"organizationsEnabled"`
	}
	err := c.get(ctx, adminRealmsPath+url.PathEscape(realm), &rep)
	return rep.OrganizationsEnabled, err
}
