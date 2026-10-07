package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

var ErrGroupOwnershipConflict = errors.New("keycloak group ownership conflict")

const (
	groupsPath       = "/groups"
	groupsSegment    = "/groups/"
	groupByPathBase  = "/group-by-path"
	realmRoleMapSeg  = "/role-mappings/realm"
	clientRoleMapSeg = "/role-mappings/clients/"
	childrenSegment  = "/children"
)

// Group is the subset of the Keycloak group representation hankoShell manages.
// It models an organization node: a named group under a realm, optionally
// nested under a parent group, carrying realm-role mappings that become the
// member's effective roles in issued tokens.
type Group struct {
	// ID is the Keycloak-assigned group UUID.
	ID string `json:"id,omitempty"`
	// Name is the group's short name (last path segment).
	Name string `json:"name"`
	// Path is the full slash-separated group path, e.g. "/alien6/demo".
	Path string `json:"path,omitempty"`
	// Attributes holds arbitrary key/value metadata, Keycloak's list-valued form.
	Attributes map[string][]string `json:"attributes,omitempty"`
	// SubGroups are the immediate children returned by Keycloak on reads.
	SubGroups []Group `json:"subGroups,omitempty"`
}

// GroupSpec is the desired state of a single Keycloak group managed by the
// operator. ParentID and ParentPath are both empty for a top-level group; when
// set they must reference an already-reconciled parent group.
type GroupSpec struct {
	// Name is the group's short name.
	Name string
	// ParentID is the Keycloak UUID of the parent group, empty for top-level.
	ParentID string
	// ParentPath is the parent group's full path, empty for top-level. It is
	// used only to resolve the child's path for idempotent lookups.
	ParentPath string
	// Attributes holds group metadata to set on creation.
	Attributes map[string][]string
	// OwnershipAttributes identify the Kubernetes object allowed to adopt an
	// existing group. They are included in Attributes by the caller and checked
	// before returning an existing group when RequireOwnership is true.
	OwnershipAttributes map[string][]string
	// LegacyOwnedID allows a group already recorded in status by an older
	// operator version to be adopted once even when it predates ownership
	// attributes. Keycloak group IDs are immutable and globally unique in a
	// realm, so this does not permit path-based adoption.
	LegacyOwnedID string
	// RequireOwnership makes existing groups fail closed unless their ownership
	// attributes (or LegacyOwnedID) match this spec.
	RequireOwnership bool
}

// groupPath returns the full Keycloak path a GroupSpec resolves to.
func (s GroupSpec) groupPath() string {
	if s.ParentPath == "" {
		return "/" + s.Name
	}
	return strings.TrimRight(s.ParentPath, "/") + "/" + s.Name
}

// GetGroupByPath resolves a group by its full path (e.g. "/alien6/demo").
// It returns a not-found error (see IsNotFound) when the path is unknown.
func (c *Client) GetGroupByPath(ctx context.Context, realm, groupPath string) (*Group, error) {
	// Keycloak expects the path with a leading slash; each segment is escaped.
	segments := strings.Split(strings.Trim(groupPath, "/"), "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	path := adminRealmsPath + realm + groupByPathBase + "/" + strings.Join(segments, "/")
	var g Group
	if err := c.get(ctx, path, &g); err != nil {
		return nil, fmt.Errorf("get group %q in realm %q: %w", groupPath, realm, err)
	}
	return &g, nil
}

// GetGroup returns one group by its immutable Keycloak UUID.
func (c *Client) GetGroup(ctx context.Context, realm, groupID string) (*Group, error) {
	var group Group
	path := adminRealmsPath + realm + groupsSegment + url.PathEscape(groupID)
	if err := c.get(ctx, path, &group); err != nil {
		return nil, fmt.Errorf("get group %q in realm %q: %w", groupID, realm, err)
	}
	return &group, nil
}

// GroupMatchesOwnership reports whether a provider group carries all expected
// ownership attributes. Markerless groups are accepted only when their
// immutable ID was already persisted in the owning CR status by an older
// operator version. A partial or conflicting marker never falls back to the
// legacy ID.
func GroupMatchesOwnership(group *Group, expected map[string][]string, legacyOwnedID string) bool {
	if group == nil {
		return false
	}
	markerPresent := false
	for key := range expected {
		if _, ok := group.Attributes[key]; ok {
			markerPresent = true
			break
		}
	}
	if markerPresent {
		for key, values := range expected {
			actual, ok := group.Attributes[key]
			if !ok {
				return false
			}
			for _, value := range values {
				if !slices.Contains(actual, value) {
					return false
				}
			}
		}
		return len(expected) != 0
	}
	return legacyOwnedID != "" && group.ID == legacyOwnedID
}

// EnsureGroup creates the group when absent and returns its Keycloak UUID. In
// strict ownership mode an existing group is adopted only when its owner
// marker or immutable legacy status ID matches, and a concurrent 409 fails
// closed so a later reconcile can preflight that group's effective roles.
func (c *Client) EnsureGroup(ctx context.Context, realm string, spec GroupSpec) (string, error) {
	existing, err := c.GetGroupByPath(ctx, realm, spec.groupPath())
	if err == nil {
		if spec.RequireOwnership && !GroupMatchesOwnership(existing, spec.OwnershipAttributes, spec.LegacyOwnedID) {
			return "", fmt.Errorf("%w: existing group %q in realm %q is not owned by this HankoOrganization", ErrGroupOwnershipConflict, spec.groupPath(), realm)
		}
		return existing.ID, nil
	}
	if !IsNotFound(err) {
		return "", err
	}

	createPath := adminRealmsPath + realm + groupsPath
	if spec.ParentID != "" {
		createPath = adminRealmsPath + realm + groupsSegment + spec.ParentID + childrenSegment
	}
	payload := Group{Name: spec.Name, Attributes: spec.Attributes}
	location, status, err := c.postJSONLocation(ctx, createPath, payload)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusCreated:
		if id := idFromLocation(location); id != "" {
			return id, nil
		}
		// Fall through to a read when Keycloak omits a usable Location.
	case http.StatusConflict:
		if spec.RequireOwnership {
			// Never adopt a group that appeared between the preflight and create.
			// A later reconcile will read, validate its effective roles and prove
			// ownership before using it.
			return "", fmt.Errorf("%w: group %q appeared concurrently in realm %q", ErrGroupOwnershipConflict, spec.groupPath(), realm)
		}
		// Legacy non-protected realms retain idempotent path adoption.
	default:
		return "", fmt.Errorf("create group %q in realm %q: keycloak %d", spec.Name, realm, status)
	}

	adopted, err := c.GetGroupByPath(ctx, realm, spec.groupPath())
	if err != nil {
		return "", fmt.Errorf("resolve group %q after create: %w", spec.Name, err)
	}
	if spec.RequireOwnership && !GroupMatchesOwnership(adopted, spec.OwnershipAttributes, spec.LegacyOwnedID) {
		return "", fmt.Errorf("%w: created group %q in realm %q does not carry the expected owner", ErrGroupOwnershipConflict, spec.groupPath(), realm)
	}
	return adopted.ID, nil
}

type groupRoleMappings struct {
	RealmMappings  []RealmRole                       `json:"realmMappings"`
	ClientMappings map[string]groupClientRoleMapping `json:"clientMappings"`
}

type groupClientRoleMapping struct {
	ID       string      `json:"id"`
	Client   string      `json:"client"`
	Mappings []RealmRole `json:"mappings"`
}

// GetGroupEffectiveRoleClosure expands every direct realm and client role of a
// group. Looking only at Keycloak's realm/composite endpoint is insufficient:
// a directly mapped client role may itself be composite to a reserved realm
// role. Every provider lookup and composite edge therefore fails closed.
func (c *Client) GetGroupEffectiveRoleClosure(ctx context.Context, realm, groupID string) ([]RealmRole, error) {
	path := adminRealmsPath + realm + groupsSegment + url.PathEscape(groupID) + "/role-mappings"
	var mappings groupRoleMappings
	if err := c.get(ctx, path, &mappings); err != nil {
		return nil, fmt.Errorf("get role mappings for group %q in realm %q: %w", groupID, realm, err)
	}

	closure := make([]RealmRole, 0, len(mappings.RealmMappings))
	seen := make(map[string]struct{})
	appendClosure := func(roles []RealmRole) {
		for _, role := range roles {
			key := fmt.Sprintf("%t\x00%s\x00%s", role.ClientRole, role.ContainerID, role.Name)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			closure = append(closure, role)
		}
	}

	for _, mapping := range mappings.RealmMappings {
		roles, err := c.GetRealmRoleClosure(ctx, realm, mapping.Name)
		if err != nil {
			return nil, fmt.Errorf("expand realm role %q for group %q: %w", mapping.Name, groupID, err)
		}
		appendClosure(roles)
	}
	for _, clientMapping := range mappings.ClientMappings {
		if strings.TrimSpace(clientMapping.ID) == "" {
			return nil, fmt.Errorf("expand client roles for group %q: client mapping %q has no provider ID", groupID, clientMapping.Client)
		}
		for _, mapping := range clientMapping.Mappings {
			var root RealmRole
			rolePath := adminRealmsPath + realm + clientsPath + url.PathEscape(clientMapping.ID) + rolesPath + "/" + url.PathEscape(mapping.Name)
			if err := c.get(ctx, rolePath, &root); err != nil {
				return nil, fmt.Errorf("get client role %q of %q for group %q: %w", mapping.Name, clientMapping.Client, groupID, err)
			}
			root.ClientRole = true
			root.ContainerID = clientMapping.ID
			roles, err := c.getRoleClosure(ctx, realm, root)
			if err != nil {
				return nil, fmt.Errorf("expand client role %q of %q for group %q: %w", mapping.Name, clientMapping.Client, groupID, err)
			}
			appendClosure(roles)
		}
	}
	return closure, nil
}

// AssignRealmRolesToGroup additively attaches realm roles to a group. Roles
// already mapped are left untouched; roles declared elsewhere but not listed
// here are intentionally preserved. Referenced roles must already exist.
func (c *Client) AssignRealmRolesToGroup(ctx context.Context, realm, groupID string, roleNames []string) error {
	if len(roleNames) == 0 {
		return nil
	}
	mapPath := adminRealmsPath + realm + groupsSegment + groupID + realmRoleMapSeg
	var current []RealmRole
	if err := c.get(ctx, mapPath, &current); err != nil {
		return fmt.Errorf("list realm-role mappings for group %q: %w", groupID, err)
	}
	present := make(map[string]struct{}, len(current))
	for _, role := range current {
		present[role.Name] = struct{}{}
	}

	missing := make([]RealmRole, 0, len(roleNames))
	for _, name := range roleNames {
		if _, ok := present[name]; ok {
			continue
		}
		role, err := c.GetRealmRole(ctx, realm, name)
		if err != nil {
			return fmt.Errorf("resolve realm role %q for group mapping: %w", name, err)
		}
		missing = append(missing, *role)
	}
	if len(missing) == 0 {
		return nil
	}
	if _, err := c.postJSONExpect(ctx, mapPath, missing, http.StatusNoContent); err != nil {
		return fmt.Errorf("map realm roles to group %q: %w", groupID, err)
	}
	return nil
}

// clientRoleRef is the id-bearing role representation Keycloak requires in
// client-level role-mapping payloads.
type clientRoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AssignClientRolesToGroup additively attaches client-scoped roles to a group.
// Roles already mapped are left untouched; mappings declared elsewhere but not
// listed here are intentionally preserved, mirroring AssignRealmRolesToGroup.
// The referenced client and roles must already exist: a missing client is an
// error, not a silent no-op, so a mistyped clientID stays visible in status.
func (c *Client) AssignClientRolesToGroup(ctx context.Context, realm, groupID, clientID string, roleNames []string) error {
	if len(roleNames) == 0 {
		return nil
	}
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve client %q for group role mapping: %w", clientID, err)
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}

	mapPath := adminRealmsPath + realm + groupsSegment + groupID + clientRoleMapSeg + uuid
	var current []clientRoleRef
	if err := c.get(ctx, mapPath, &current); err != nil {
		return fmt.Errorf("list client-role mappings for group %q: %w", groupID, err)
	}
	present := make(map[string]struct{}, len(current))
	for _, role := range current {
		present[role.Name] = struct{}{}
	}

	missing := make([]clientRoleRef, 0, len(roleNames))
	for _, name := range roleNames {
		if _, ok := present[name]; ok {
			continue
		}
		var role clientRoleRef
		rolePath := adminRealmsPath + realm + clientsPath + uuid + rolesPath + "/" + url.PathEscape(name)
		if err := c.get(ctx, rolePath, &role); err != nil {
			return fmt.Errorf("resolve client role %q of %q for group mapping: %w", name, clientID, err)
		}
		missing = append(missing, role)
	}
	if len(missing) == 0 {
		return nil
	}
	if _, err := c.postJSONExpect(ctx, mapPath, missing, http.StatusNoContent); err != nil {
		return fmt.Errorf("map client roles of %q to group %q: %w", clientID, groupID, err)
	}
	return nil
}

// DeleteGroup removes a group by UUID. A missing group is treated as success.
func (c *Client) DeleteGroup(ctx context.Context, realm, groupID string) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realm+groupsSegment+groupID, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete group %q in realm %q: keycloak %d: %s", groupID, realm, resp.StatusCode, body)
}

// postJSONLocation POSTs a JSON payload and returns the Location header and
// status without treating a non-2xx as an error, so callers can branch on
// 201/409 explicitly.
func (c *Client) postJSONLocation(ctx context.Context, path string, payload any) (string, int, error) {
	resp, err := c.doJSON(ctx, http.MethodPost, path, payload)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header.Get("Location"), resp.StatusCode, nil
}

// postJSONExpect POSTs a JSON payload and returns an error unless the response
// status is one of the accepted codes.
func (c *Client) postJSONExpect(ctx context.Context, path string, payload any, accepted ...int) (int, error) {
	resp, err := c.doJSON(ctx, http.MethodPost, path, payload)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if slices.Contains(accepted, resp.StatusCode) {
		return resp.StatusCode, nil
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, fmt.Errorf("keycloak %s %s: %d: %s", http.MethodPost, path, resp.StatusCode, body)
}

// doJSON issues an authenticated JSON request and returns the raw response for
// the caller to inspect. The caller owns closing the body.
func (c *Client) doJSON(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", path, err)
	}
	body := bytes.NewReader(raw)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	return c.do(req)
}

// idFromLocation extracts the trailing UUID from a Keycloak Location header.
func idFromLocation(location string) string {
	if location == "" {
		return ""
	}
	return location[strings.LastIndex(location, "/")+1:]
}
