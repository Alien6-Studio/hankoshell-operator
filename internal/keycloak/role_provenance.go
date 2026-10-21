package keycloak

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// ErrRoleProvenanceIncomplete is local evidence, never a provider payload.
var ErrRoleProvenanceIncomplete = errors.New("role provenance graph is incomplete or exceeds its budget")

// GroupRolePath retains direct mapping origin and every observed composite edge.
// Provider IDs are private locators and must not be projected into public status.
type GroupRolePath struct {
	Client string
	Roles  []RealmRole
}

func roleKey(r RealmRole) string { return strings.Join([]string{r.ContainerID, r.Name}, "\x00") }
func (c *Client) roleChildren(ctx context.Context, realm string, role RealmRole) ([]RealmRole, error) {
	if !role.Composite {
		return nil, nil
	}
	path, err := roleResourcePath(realm, role)
	if err != nil {
		return nil, err
	}
	var children []RealmRole
	if err := c.get(ctx, path+"/composites", &children); err != nil {
		return nil, err
	}
	if len(children) > 512 {
		return nil, ErrRoleProvenanceIncomplete
	}
	slices.SortFunc(children, func(a, b RealmRole) int { return strings.Compare(roleKey(a), roleKey(b)) })
	return children, nil
}

// GetGroupRoleProvenance is a bounded read-only counterpart to the effective
// closure, sharing its endpoint helpers while retaining direct origin and edges.
func (c *Client) GetGroupRoleProvenance(ctx context.Context, realm, groupID string) ([]GroupRolePath, error) {
	mappings, err := c.groupRoleMappings(ctx, realm, groupID)
	if err != nil {
		return nil, err
	}
	roots, err := c.provenanceRoots(ctx, realm, mappings)
	if err != nil {
		return nil, err
	}
	graph := roleProvenanceGraph{client: c, ctx: ctx, realm: realm, nodes: map[string][]RealmRole{}}
	for _, root := range roots {
		if err := graph.walk(root); err != nil {
			return nil, err
		}
	}
	return graph.result, nil
}
func (c *Client) provenanceRoots(ctx context.Context, realm string, mappings groupRoleMappings) ([]GroupRolePath, error) {
	if len(mappings.RealmMappings) > 512 || len(mappings.ClientMappings) > 128 {
		return nil, ErrRoleProvenanceIncomplete
	}
	result := []GroupRolePath{}
	for _, mapping := range mappings.RealmMappings {
		role, err := c.GetRealmRole(ctx, realm, mapping.Name)
		if err != nil {
			return nil, err
		}
		if role.ID == "" || role.ID != mapping.ID || role.Name != mapping.Name || role.ClientRole {
			return nil, ErrRoleProvenanceIncomplete
		}
		result = append(result, GroupRolePath{Roles: []RealmRole{*role}})
	}
	for _, mapping := range mappings.ClientMappings {
		paths, err := c.provenanceClientRoots(ctx, realm, mapping)
		if err != nil {
			return nil, err
		}
		result = append(result, paths...)
	}
	if len(result) > 512 {
		return nil, ErrRoleProvenanceIncomplete
	}
	slices.SortFunc(result, func(a, b GroupRolePath) int { return strings.Compare(roleKey(a.Roles[0]), roleKey(b.Roles[0])) })
	return result, nil
}
func (c *Client) provenanceClientRoots(ctx context.Context, realm string, mapping groupClientRoleMapping) ([]GroupRolePath, error) {
	if mapping.ID == "" || mapping.Client == "" || len(mapping.Mappings) > 512 {
		return nil, ErrRoleProvenanceIncomplete
	}
	result := []GroupRolePath{}
	for _, value := range mapping.Mappings {
		path, err := roleResourcePath(realm, RealmRole{ClientRole: true, ContainerID: mapping.ID, Name: value.Name})
		if err != nil {
			return nil, err
		}
		var root RealmRole
		if err := c.get(ctx, path, &root); err != nil {
			return nil, err
		}
		if root.ID == "" || root.ID != value.ID || root.Name != value.Name || !root.ClientRole || root.ContainerID != mapping.ID {
			return nil, ErrRoleProvenanceIncomplete
		}
		result = append(result, GroupRolePath{Client: mapping.Client, Roles: []RealmRole{root}})
	}
	return result, nil
}

type roleProvenanceGraph struct {
	client *Client
	ctx    context.Context
	realm  string
	nodes  map[string][]RealmRole
	edges  int
	result []GroupRolePath
}

func (g *roleProvenanceGraph) walk(path GroupRolePath) error {
	if len(path.Roles) > 33 || len(g.result) >= 1024 {
		return ErrRoleProvenanceIncomplete
	}
	role := path.Roles[len(path.Roles)-1]
	if role.ID == "" || role.Name == "" {
		return ErrRoleProvenanceIncomplete
	}
	for _, ancestor := range path.Roles[:len(path.Roles)-1] {
		if roleKey(ancestor) == roleKey(role) {
			return ErrRoleProvenanceIncomplete
		}
	}
	children, err := g.children(role)
	if err != nil {
		return err
	}
	g.result = append(g.result, path)
	for _, child := range children {
		if err := g.walk(GroupRolePath{Client: path.Client, Roles: append(slices.Clone(path.Roles), child)}); err != nil {
			return err
		}
	}
	return nil
}
func (g *roleProvenanceGraph) children(role RealmRole) ([]RealmRole, error) {
	key := roleKey(role)
	if children, ok := g.nodes[key]; ok {
		return children, nil
	}
	if len(g.nodes) >= 512 {
		return nil, ErrRoleProvenanceIncomplete
	}
	children, err := g.client.roleChildren(g.ctx, g.realm, role)
	if err != nil {
		return nil, err
	}
	g.edges += len(children)
	if g.edges > 1024 {
		return nil, ErrRoleProvenanceIncomplete
	}
	g.nodes[key] = children
	return children, nil
}
