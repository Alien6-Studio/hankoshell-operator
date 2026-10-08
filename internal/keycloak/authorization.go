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
	"sort"
	"strings"
)

var ErrAuthorizationOwnershipConflict = errors.New("keycloak authorization object is not owned by Hanko")

type AuthorizationModel struct {
	Name           string
	Realm          string
	Audience       string
	DisplayName    string
	ApplicationRef string
	Scopes         []AuthorizationScope
	Resources      []AuthorizationResource
	Permissions    []AuthorizationPermission
}

type AuthorizationScope struct {
	Name        string
	Description string
}

type AuthorizationResource struct {
	Name        string
	DisplayName string
	URIs        []string
	Type        string
	Scopes      []string
}

type AuthorizationPermission struct {
	Name       string
	Resources  []string
	Scopes     []string
	Principals []AuthorizationPrincipal
}

type AuthorizationPrincipal struct {
	Kind string
	Ref  string
}

type AuthorizationManagedObjects struct {
	ResourceServerID string
	Scopes           []AuthorizationManagedReference
	Resources        []AuthorizationManagedReference
	Policies         []AuthorizationManagedReference
	Permissions      []AuthorizationManagedReference
}

type AuthorizationManagedReference struct {
	Name string
	ID   string
}

type AuthorizationState struct {
	ResourceServerID string
	ManagedObjects   AuthorizationManagedObjects
	NativeObjects    []AuthorizationNativeObject
}

type AuthorizationNativeObject struct {
	Kind string
	Name string
}

type authorizationScopeRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

type authorizationResourceRepresentation struct {
	ID          string                             `json:"_id,omitempty"`
	Name        string                             `json:"name"`
	DisplayName string                             `json:"displayName,omitempty"`
	URIs        []string                           `json:"uris,omitempty"`
	Type        string                             `json:"type,omitempty"`
	Scopes      []authorizationScopeRepresentation `json:"scopes,omitempty"`
}

type authorizationPolicyRepresentation struct {
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name"`
	Type             string            `json:"type,omitempty"`
	Logic            string            `json:"logic,omitempty"`
	DecisionStrategy string            `json:"decisionStrategy,omitempty"`
	Config           map[string]string `json:"config,omitempty"`
	Roles            []policyRole      `json:"roles,omitempty"`
	Clients          []string          `json:"clients,omitempty"`
}

type policyRole struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type authorizationPermissionRepresentation struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Type             string   `json:"type,omitempty"`
	Logic            string   `json:"logic,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	Scopes           []string `json:"scopes"`
	Policies         []string `json:"policies"`
}

type authorizationResourceIndex struct {
	byID   map[string]authorizationResourceRepresentation
	byName map[string]authorizationResourceRepresentation
}

type authorizationPolicyIndex struct {
	byID   map[string]authorizationPolicyRepresentation
	byName map[string]authorizationPolicyRepresentation
}

type desiredAuthorizationPolicy struct {
	logical string
	kind    string
	payload authorizationPolicyRepresentation
}

// ObserveAuthorization reads the authorization service without performing any
// mutation. Provider-native objects are returned for read-only gap reporting.
func (c *Client) ObserveAuthorization(ctx context.Context, model AuthorizationModel) (AuthorizationState, error) {
	clientID, enabled, _, err := c.authorizationClientState(ctx, model.Realm, model.ApplicationRef)
	if err != nil {
		return AuthorizationState{}, err
	}
	state := AuthorizationState{ResourceServerID: clientID}
	if !enabled {
		return state, nil
	}
	base := authorizationBase(model.Realm, clientID)
	var scopes []authorizationScopeRepresentation
	if err := c.get(ctx, base+authorizationScopePath, &scopes); err != nil {
		return AuthorizationState{}, fmt.Errorf("observe authorization scopes: %w", err)
	}
	var resources []authorizationResourceRepresentation
	if err := c.get(ctx, base+authorizationResourcePath, &resources); err != nil {
		return AuthorizationState{}, fmt.Errorf("observe authorization resources: %w", err)
	}
	var policies []authorizationPolicyRepresentation
	if err := c.get(ctx, base+authorizationPolicyPath, &policies); err != nil {
		return AuthorizationState{}, fmt.Errorf("observe authorization policies: %w", err)
	}
	var permissions []authorizationPermissionRepresentation
	if err := c.get(ctx, base+authorizationPermissionPath, &permissions); err != nil {
		return AuthorizationState{}, fmt.Errorf("observe authorization permissions: %w", err)
	}
	for _, scope := range scopes {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "scope", Name: scope.Name})
	}
	for _, resource := range resources {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "resource", Name: resource.Name})
	}
	for _, policy := range policies {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "policy", Name: policy.Name})
	}
	for _, permission := range permissions {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "permission", Name: permission.Name})
	}
	return state, nil
}

// ReconcileAuthorization converges the Keycloak Authorization Services graph.
// Existing same-named objects are rejected unless their IDs are present in the
// supplied ownership set.
//
//nolint:gocognit,cyclop // Dependency-ordered reconciliation is intentionally explicit.
func (c *Client) ReconcileAuthorization(ctx context.Context, model AuthorizationModel, owned AuthorizationManagedObjects) (AuthorizationState, error) { // NOSONAR -- every ownership boundary remains visible.
	clientID, enabled, serviceAccountEnabled, err := c.authorizationClientState(ctx, model.Realm, model.ApplicationRef)
	if err != nil {
		return AuthorizationState{}, err
	}
	if !enabled && !serviceAccountEnabled {
		return AuthorizationState{}, fmt.Errorf("backing application %q must enable a service account; use HankoApplication type m2m", model.ApplicationRef)
	}
	if owned.ResourceServerID != "" && owned.ResourceServerID != clientID {
		return AuthorizationState{}, fmt.Errorf("%w: backing application changed", ErrAuthorizationOwnershipConflict)
	}
	if !enabled {
		if err := c.setAuthorizationEnabled(ctx, model.Realm, clientID, true); err != nil {
			return AuthorizationState{}, err
		}
	} else if owned.ResourceServerID == "" {
		return AuthorizationState{}, fmt.Errorf("%w: authorization is already enabled for application %q", ErrAuthorizationOwnershipConflict, model.ApplicationRef)
	}

	base := authorizationBase(model.Realm, clientID)
	scopeRefs, scopeIDs, err := c.reconcileAuthorizationScopes(ctx, base, model.Scopes, owned.Scopes)
	if err != nil {
		return AuthorizationState{}, err
	}
	resourceRefs, resourceIDs, err := c.reconcileAuthorizationResources(ctx, base, model.Resources, scopeIDs, owned.Resources)
	if err != nil {
		return AuthorizationState{}, err
	}
	policyRefs, policiesByPermission, err := c.reconcileAuthorizationPolicies(ctx, base, model, owned.Policies)
	if err != nil {
		return AuthorizationState{}, err
	}
	permissionRefs, err := c.reconcileAuthorizationPermissions(ctx, base, model.Permissions, scopeIDs, resourceIDs, policiesByPermission, owned.Permissions)
	if err != nil {
		return AuthorizationState{}, err
	}
	for _, stale := range []struct {
		collection string
		owned      []AuthorizationManagedReference
		keep       []AuthorizationManagedReference
	}{
		{collection: base + authorizationPermissionPath, owned: owned.Permissions, keep: permissionRefs},
		{collection: base + authorizationPolicyPath, owned: owned.Policies, keep: policyRefs},
		{collection: base + authorizationResourcePath, owned: owned.Resources, keep: resourceRefs},
		{collection: base + authorizationScopePath, owned: owned.Scopes, keep: scopeRefs},
	} {
		if err := c.deleteStaleAuthorizationRefs(ctx, stale.collection, stale.owned, keepAuthorizationIDs(stale.keep)); err != nil {
			return AuthorizationState{}, err
		}
	}

	return AuthorizationState{
		ResourceServerID: clientID,
		ManagedObjects: AuthorizationManagedObjects{
			ResourceServerID: clientID, Scopes: scopeRefs, Resources: resourceRefs, Policies: policyRefs, Permissions: permissionRefs,
		},
	}, nil
}

// DeleteAuthorizationOwned removes only status-owned objects, in reverse
// dependency order, and disables authorization only on the recorded backing client.
func (c *Client) DeleteAuthorizationOwned(ctx context.Context, model AuthorizationModel, resourceServerID string, owned AuthorizationManagedObjects) error {
	if resourceServerID == "" || owned.ResourceServerID != resourceServerID {
		return fmt.Errorf("%w: resource server ID is not owned", ErrAuthorizationOwnershipConflict)
	}
	clientPath := adminRealmsPath + url.PathEscape(model.Realm) + clientsPath + url.PathEscape(resourceServerID)
	var representation map[string]any
	if err := c.get(ctx, clientPath, &representation); err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	base := authorizationBase(model.Realm, resourceServerID)
	for _, collection := range []struct {
		path string
		refs []AuthorizationManagedReference
	}{
		{path: authorizationPermissionPath, refs: owned.Permissions},
		{path: authorizationPolicyPath, refs: owned.Policies},
		{path: authorizationResourcePath, refs: owned.Resources},
		{path: authorizationScopePath, refs: owned.Scopes},
	} {
		for _, ref := range collection.refs {
			if ref.ID == "" {
				continue
			}
			if err := c.authorizationDelete(ctx, base+collection.path+"/"+url.PathEscape(ref.ID)); err != nil && !IsNotFound(err) {
				return err
			}
		}
	}
	representation["authorizationServicesEnabled"] = false
	return c.putJSON(ctx, clientPath, representation)
}

func authorizationBase(realm, clientID string) string {
	return adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(clientID) + "/authz/resource-server"
}

func (c *Client) authorizationClientState(ctx context.Context, realm, applicationRef string) (string, bool, bool, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, applicationRef)
	if err != nil {
		return "", false, false, err
	}
	if uuid == "" {
		return "", false, false, fmt.Errorf("backing application %q not found in realm %q", applicationRef, realm)
	}
	var representation map[string]any
	if err := c.get(ctx, adminRealmsPath+url.PathEscape(realm)+clientsPath+url.PathEscape(uuid), &representation); err != nil {
		return "", false, false, err
	}
	enabled, _ := representation["authorizationServicesEnabled"].(bool)
	serviceAccountEnabled, _ := representation["serviceAccountsEnabled"].(bool)
	return uuid, enabled, serviceAccountEnabled, nil
}

func (c *Client) setAuthorizationEnabled(ctx context.Context, realm, clientID string, enabled bool) error {
	path := adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(clientID)
	var representation map[string]any
	if err := c.get(ctx, path, &representation); err != nil {
		return err
	}
	if current, _ := representation["authorizationServicesEnabled"].(bool); current == enabled {
		return nil
	}
	representation["authorizationServicesEnabled"] = enabled
	return c.putJSON(ctx, path, representation)
}

func (c *Client) reconcileAuthorizationScopes(ctx context.Context, base string, desired []AuthorizationScope, owned []AuthorizationManagedReference) ([]AuthorizationManagedReference, map[string]string, error) {
	var current []authorizationScopeRepresentation
	if err := c.get(ctx, base+authorizationScopePath, &current); err != nil {
		return nil, nil, err
	}
	currentByID, currentByName := indexScopes(current)
	ownedByName := refsByName(owned)
	refs := make([]AuthorizationManagedReference, 0, len(desired))
	ids := make(map[string]string, len(desired))
	for _, scope := range desired {
		want := authorizationScopeRepresentation{Name: scope.Name, DisplayName: scope.Description}
		ref, err := c.ensureAuthorizationScope(ctx, base, want, ownedByName[scope.Name], currentByID, currentByName)
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, ref)
		ids[scope.Name] = ref.ID
	}
	return refs, ids, nil
}

func (c *Client) ensureAuthorizationScope(ctx context.Context, base string, want authorizationScopeRepresentation, owned AuthorizationManagedReference, byID, byName map[string]authorizationScopeRepresentation) (AuthorizationManagedReference, error) {
	if owned.ID == "" {
		if _, exists := byName[want.Name]; exists {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: scope %q already exists", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, base+authorizationScopePath, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	got, exists := byID[owned.ID]
	if !exists {
		if _, collision := byName[want.Name]; collision {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: scope %q ownership ID disappeared", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, base+authorizationScopePath, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	if got.Name != want.Name {
		return AuthorizationManagedReference{}, fmt.Errorf("%w: scope ID %q now names %q", ErrAuthorizationOwnershipConflict, owned.ID, got.Name)
	}
	if got.DisplayName != want.DisplayName {
		want.ID = owned.ID
		if err := c.authorizationUpdate(ctx, base+"/scope/"+url.PathEscape(owned.ID), want); err != nil {
			return AuthorizationManagedReference{}, err
		}
	}
	return AuthorizationManagedReference{Name: want.Name, ID: owned.ID}, nil
}

func (c *Client) reconcileAuthorizationResources(ctx context.Context, base string, desired []AuthorizationResource, scopeIDs map[string]string, owned []AuthorizationManagedReference) ([]AuthorizationManagedReference, map[string]string, error) {
	var current []authorizationResourceRepresentation
	if err := c.get(ctx, base+authorizationResourcePath, &current); err != nil {
		return nil, nil, err
	}
	index := indexAuthorizationResources(current)
	ownedByName := refsByName(owned)
	refs := make([]AuthorizationManagedReference, 0, len(desired))
	ids := make(map[string]string, len(desired))
	for _, resource := range desired {
		want := buildAuthorizationResource(resource, scopeIDs)
		ref, err := c.ensureAuthorizationResource(ctx, base, want, ownedByName[resource.Name], index)
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, ref)
		ids[resource.Name] = ref.ID
	}
	return refs, ids, nil
}

func indexAuthorizationResources(current []authorizationResourceRepresentation) authorizationResourceIndex {
	index := authorizationResourceIndex{
		byID:   make(map[string]authorizationResourceRepresentation, len(current)),
		byName: make(map[string]authorizationResourceRepresentation, len(current)),
	}
	for _, item := range current {
		index.byID[item.ID], index.byName[item.Name] = item, item
	}
	return index
}

func buildAuthorizationResource(resource AuthorizationResource, scopeIDs map[string]string) authorizationResourceRepresentation {
	want := authorizationResourceRepresentation{Name: resource.Name, DisplayName: resource.DisplayName, URIs: sorted(resource.URIs), Type: resource.Type}
	for _, scopeName := range resource.Scopes {
		want.Scopes = append(want.Scopes, authorizationScopeRepresentation{ID: scopeIDs[scopeName], Name: scopeName})
	}
	sort.Slice(want.Scopes, func(i, j int) bool { return want.Scopes[i].Name < want.Scopes[j].Name })
	return want
}

func (c *Client) ensureAuthorizationResource(ctx context.Context, base string, want authorizationResourceRepresentation, owned AuthorizationManagedReference, index authorizationResourceIndex) (AuthorizationManagedReference, error) {
	if owned.ID == "" {
		if _, exists := index.byName[want.Name]; exists {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: resource %q already exists", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, base+authorizationResourcePath, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	got, exists := index.byID[owned.ID]
	if !exists {
		if _, collision := index.byName[want.Name]; collision {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: resource %q ownership ID disappeared", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, base+authorizationResourcePath, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	if got.Name != want.Name {
		return AuthorizationManagedReference{}, fmt.Errorf("%w: resource ID %q changed name", ErrAuthorizationOwnershipConflict, owned.ID)
	}
	if !resourceEqual(got, want) {
		want.ID = owned.ID
		if err := c.authorizationUpdate(ctx, base+authorizationResourcePath+"/"+url.PathEscape(owned.ID), want); err != nil {
			return AuthorizationManagedReference{}, err
		}
	}
	return AuthorizationManagedReference{Name: want.Name, ID: owned.ID}, nil
}

func (c *Client) reconcileAuthorizationPolicies(ctx context.Context, base string, model AuthorizationModel, owned []AuthorizationManagedReference) ([]AuthorizationManagedReference, map[string][]string, error) {
	index, err := c.loadAuthorizationPolicies(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	ownedByName := refsByName(owned)
	refs := make([]AuthorizationManagedReference, 0)
	byPermission := make(map[string][]string)
	for _, permission := range model.Permissions {
		roleRefs, clientRefs, err := c.resolveAuthorizationPrincipals(ctx, model.Realm, permission.Principals)
		if err != nil {
			return nil, nil, err
		}
		wants := desiredAuthorizationPolicies(model.Name, permission.Name, roleRefs, clientRefs)
		for _, want := range wants {
			ref, err := c.ensureAuthorizationPolicy(ctx, base, want, ownedByName[want.logical], index)
			if err != nil {
				return nil, nil, err
			}
			refs = append(refs, ref)
			byPermission[permission.Name] = append(byPermission[permission.Name], ref.ID)
		}
	}
	return refs, byPermission, nil
}

func (c *Client) loadAuthorizationPolicies(ctx context.Context, base string) (authorizationPolicyIndex, error) {
	var allPolicies []authorizationPolicyRepresentation
	if err := c.get(ctx, base+authorizationPolicyPath, &allPolicies); err != nil {
		return authorizationPolicyIndex{}, err
	}
	index := authorizationPolicyIndex{
		byID:   make(map[string]authorizationPolicyRepresentation, len(allPolicies)),
		byName: make(map[string]authorizationPolicyRepresentation, len(allPolicies)),
	}
	for _, item := range allPolicies {
		index.byName[item.Name] = item
	}
	// Generic representations omit type-specific bindings; typed reads are
	// required for semantic drift comparison.
	for _, policyType := range []string{"role", "client"} {
		var typed []authorizationPolicyRepresentation
		if err := c.get(ctx, base+authorizationPolicyPath+"/"+policyType, &typed); err != nil {
			return authorizationPolicyIndex{}, err
		}
		for _, item := range typed {
			item.Type = policyType
			index.byID[item.ID], index.byName[item.Name] = item, item
		}
	}
	return index, nil
}

func (c *Client) resolveAuthorizationPrincipals(ctx context.Context, realm string, principals []AuthorizationPrincipal) ([]policyRole, []string, error) {
	roleRefs := make([]policyRole, 0)
	clientRefs := make([]string, 0)
	for _, principal := range principals {
		switch principal.Kind {
		case "realm_role":
			role, err := c.GetRealmRole(ctx, realm, principal.Ref)
			if err != nil {
				return nil, nil, err
			}
			if role.ID == "" {
				return nil, nil, fmt.Errorf("realm role %q has no provider ID", principal.Ref)
			}
			roleRefs = append(roleRefs, policyRole{ID: role.ID, Required: false})
		case "application", "service_account":
			id, err := c.resolveClientUUID(ctx, realm, principal.Ref)
			if err != nil || id == "" {
				return nil, nil, fmt.Errorf("resolve principal %q: %w", principal.Ref, err)
			}
			clientRefs = append(clientRefs, id)
		default:
			return nil, nil, fmt.Errorf("unsupported principal kind %q", principal.Kind)
		}
	}
	sort.Slice(roleRefs, func(i, j int) bool { return roleRefs[i].ID < roleRefs[j].ID })
	sort.Strings(clientRefs)
	return roleRefs, clientRefs, nil
}

func desiredAuthorizationPolicies(modelName, permissionName string, roleRefs []policyRole, clientRefs []string) []desiredAuthorizationPolicy {
	wants := make([]desiredAuthorizationPolicy, 0, 2)
	if len(roleRefs) > 0 {
		logical := permissionName + "#realm_roles"
		wants = append(wants, desiredAuthorizationPolicy{logical: logical, kind: "role", payload: authorizationPolicyRepresentation{Name: managedPolicyName(modelName, logical), Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Roles: roleRefs}})
	}
	if len(clientRefs) > 0 {
		logical := permissionName + "#clients"
		wants = append(wants, desiredAuthorizationPolicy{logical: logical, kind: "client", payload: authorizationPolicyRepresentation{Name: managedPolicyName(modelName, logical), Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Clients: clientRefs}})
	}
	return wants
}

func (c *Client) ensureAuthorizationPolicy(ctx context.Context, base string, desired desiredAuthorizationPolicy, owned AuthorizationManagedReference, index authorizationPolicyIndex) (AuthorizationManagedReference, error) {
	collection := base + authorizationPolicyPath + "/" + desired.kind
	want := desired.payload
	if owned.ID == "" {
		if _, exists := index.byName[want.Name]; exists {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: policy %q already exists", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, collection, want)
		return AuthorizationManagedReference{Name: desired.logical, ID: id}, err
	}
	got, exists := index.byID[owned.ID]
	if !exists {
		if _, collision := index.byName[want.Name]; collision {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: policy %q ownership ID disappeared", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, collection, want)
		return AuthorizationManagedReference{Name: desired.logical, ID: id}, err
	}
	if got.Name != want.Name || (got.Type != "" && got.Type != desired.kind) {
		return AuthorizationManagedReference{}, fmt.Errorf("%w: policy ID %q changed identity", ErrAuthorizationOwnershipConflict, owned.ID)
	}
	if !policyEqual(got, want, desired.kind) {
		want.ID = owned.ID
		if err := c.authorizationUpdate(ctx, collection+"/"+url.PathEscape(owned.ID), want); err != nil {
			return AuthorizationManagedReference{}, err
		}
	}
	return AuthorizationManagedReference{Name: desired.logical, ID: owned.ID}, nil
}

func (c *Client) reconcileAuthorizationPermissions(ctx context.Context, base string, desired []AuthorizationPermission, scopeIDs, resourceIDs map[string]string, policyIDs map[string][]string, owned []AuthorizationManagedReference) ([]AuthorizationManagedReference, error) {
	byID, byName, err := c.loadAuthorizationPermissions(ctx, base)
	if err != nil {
		return nil, err
	}
	ownedByName := refsByName(owned)
	refs := make([]AuthorizationManagedReference, 0, len(desired))
	for _, permission := range desired {
		want := buildAuthorizationPermission(permission, scopeIDs, resourceIDs, policyIDs)
		ref, err := c.ensureAuthorizationPermission(ctx, base, want, ownedByName[permission.Name], byID, byName)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (c *Client) loadAuthorizationPermissions(ctx context.Context, base string) (map[string]authorizationPermissionRepresentation, map[string]authorizationPermissionRepresentation, error) {
	var allPermissions []authorizationPermissionRepresentation
	if err := c.get(ctx, base+authorizationPermissionPath, &allPermissions); err != nil {
		return nil, nil, err
	}
	byID := make(map[string]authorizationPermissionRepresentation, len(allPermissions))
	byName := make(map[string]authorizationPermissionRepresentation, len(allPermissions))
	for _, item := range allPermissions {
		byName[item.Name] = item
	}
	var current []authorizationPermissionRepresentation
	if err := c.get(ctx, base+authorizationPermissionPath+authorizationScopePath, &current); err != nil {
		return nil, nil, err
	}
	for _, item := range current {
		item.Type = "scope"
		byID[item.ID], byName[item.Name] = item, item
	}
	return byID, byName, nil
}

func buildAuthorizationPermission(permission AuthorizationPermission, scopeIDs, resourceIDs map[string]string, policyIDs map[string][]string) authorizationPermissionRepresentation {
	want := authorizationPermissionRepresentation{Name: permission.Name, Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE"}
	for _, name := range permission.Scopes {
		want.Scopes = append(want.Scopes, scopeIDs[name])
	}
	for _, name := range permission.Resources {
		want.Resources = append(want.Resources, resourceIDs[name])
	}
	want.Policies = append(want.Policies, policyIDs[permission.Name]...)
	want.Scopes, want.Resources, want.Policies = sorted(want.Scopes), sorted(want.Resources), sorted(want.Policies)
	return want
}

func (c *Client) ensureAuthorizationPermission(ctx context.Context, base string, want authorizationPermissionRepresentation, owned AuthorizationManagedReference, byID, byName map[string]authorizationPermissionRepresentation) (AuthorizationManagedReference, error) {
	collection := base + authorizationPermissionPath + authorizationScopePath
	if owned.ID == "" {
		if _, exists := byName[want.Name]; exists {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: permission %q already exists", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, collection, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	got, exists := byID[owned.ID]
	if !exists {
		if _, collision := byName[want.Name]; collision {
			return AuthorizationManagedReference{}, fmt.Errorf("%w: permission %q ownership ID disappeared", ErrAuthorizationOwnershipConflict, want.Name)
		}
		id, err := c.authorizationCreate(ctx, collection, want)
		return AuthorizationManagedReference{Name: want.Name, ID: id}, err
	}
	if got.Name != want.Name {
		return AuthorizationManagedReference{}, fmt.Errorf("%w: permission ID %q changed name", ErrAuthorizationOwnershipConflict, owned.ID)
	}
	if !permissionEqual(got, want) {
		want.ID = owned.ID
		if err := c.authorizationUpdate(ctx, collection+"/"+url.PathEscape(owned.ID), want); err != nil {
			return AuthorizationManagedReference{}, err
		}
	}
	return AuthorizationManagedReference{Name: want.Name, ID: owned.ID}, nil
}

func (c *Client) authorizationCreate(ctx context.Context, path string, payload any) (string, error) {
	response, err := c.authorizationRequest(ctx, http.MethodPost, path, payload, http.StatusCreated, http.StatusNoContent)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" {
		// Keycloak authorization APIs return the created representation rather
		// than Location on supported versions. Both resource ID spellings occur.
		body, err := io.ReadAll(response.Body) // do returned a complete bounded buffer.
		if err != nil {
			return "", ErrResponseRead
		}
		var created struct {
			ID         string `json:"id"`
			ResourceID string `json:"_id"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			return "", fmt.Errorf("keycloak authorization create response invalid")
		}
		if created.ID != "" {
			return created.ID, nil
		}
		if created.ResourceID != "" {
			return created.ResourceID, nil
		}
		return "", fmt.Errorf("keycloak %s create response omitted object ID", path)
	}
	location = strings.TrimSuffix(location, "/")
	return location[strings.LastIndex(location, "/")+1:], nil
}

func (c *Client) authorizationUpdate(ctx context.Context, path string, payload any) error {
	response, err := c.authorizationRequest(ctx, http.MethodPut, path, payload, http.StatusNoContent, http.StatusOK, http.StatusCreated)
	if response != nil {
		response.Body.Close()
	}
	return err
}

func (c *Client) authorizationDelete(ctx context.Context, path string) error {
	response, err := c.authorizationRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	return err
}

func (c *Client) authorizationRequest(ctx context.Context, method, path string, payload any, accepted ...int) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	token, err := c.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set(authorizationHeader, bearerPrefix+token)
	request.Header.Set(contentTypeHeader, jsonMediaType)
	request.Header.Set(forwardedProtoHeader, httpsScheme)
	response, err := c.do(request)
	if err != nil {
		return nil, err
	}
	if slices.Contains(accepted, response.StatusCode) {
		return response, nil
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)
	return nil, fmt.Errorf(keycloakPathErrorFormat, path, response.StatusCode, responseBody)
}

func (c *Client) deleteStaleAuthorizationRefs(ctx context.Context, collection string, owned []AuthorizationManagedReference, keep map[string]bool) error {
	for _, ref := range owned {
		if ref.ID == "" || keep[ref.ID] {
			continue
		}
		if err := c.authorizationDelete(ctx, collection+"/"+url.PathEscape(ref.ID)); err != nil && !IsNotFound(err) {
			return err
		}
	}
	return nil
}

func refsByName(refs []AuthorizationManagedReference) map[string]AuthorizationManagedReference {
	result := make(map[string]AuthorizationManagedReference, len(refs))
	for _, ref := range refs {
		result[ref.Name] = ref
	}
	return result
}

func keepAuthorizationIDs(refs []AuthorizationManagedReference) map[string]bool {
	result := make(map[string]bool, len(refs))
	for _, ref := range refs {
		result[ref.ID] = true
	}
	return result
}

func indexScopes(scopes []authorizationScopeRepresentation) (map[string]authorizationScopeRepresentation, map[string]authorizationScopeRepresentation) {
	byID := make(map[string]authorizationScopeRepresentation, len(scopes))
	byName := make(map[string]authorizationScopeRepresentation, len(scopes))
	for _, scope := range scopes {
		byID[scope.ID], byName[scope.Name] = scope, scope
	}
	return byID, byName
}

func managedPolicyName(modelName, logical string) string {
	return "hanko:" + modelName + ":" + strings.ReplaceAll(logical, "#", ":")
}

func sorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func resourceEqual(got, want authorizationResourceRepresentation) bool {
	gotScopes := make([]string, 0, len(got.Scopes))
	wantScopes := make([]string, 0, len(want.Scopes))
	for _, scope := range got.Scopes {
		gotScopes = append(gotScopes, scope.ID)
	}
	for _, scope := range want.Scopes {
		wantScopes = append(wantScopes, scope.ID)
	}
	return got.Name == want.Name && got.DisplayName == want.DisplayName && got.Type == want.Type &&
		slices.Equal(sorted(got.URIs), sorted(want.URIs)) && slices.Equal(sorted(gotScopes), sorted(wantScopes))
}

func policyEqual(got, want authorizationPolicyRepresentation, kind string) bool {
	if got.Name != want.Name || (got.Logic != "" && got.Logic != want.Logic) || (got.DecisionStrategy != "" && got.DecisionStrategy != want.DecisionStrategy) {
		return false
	}
	if kind == "client" {
		return slices.Equal(sorted(got.Clients), sorted(want.Clients))
	}
	gotRoles, wantRoles := make([]string, 0, len(got.Roles)), make([]string, 0, len(want.Roles))
	for _, role := range got.Roles {
		gotRoles = append(gotRoles, role.ID)
	}
	for _, role := range want.Roles {
		wantRoles = append(wantRoles, role.ID)
	}
	return slices.Equal(sorted(gotRoles), sorted(wantRoles))
}

func permissionEqual(got, want authorizationPermissionRepresentation) bool {
	return got.Name == want.Name &&
		(got.Logic == "" || got.Logic == want.Logic) &&
		(got.DecisionStrategy == "" || got.DecisionStrategy == want.DecisionStrategy) &&
		slices.Equal(sorted(got.Resources), sorted(want.Resources)) &&
		slices.Equal(sorted(got.Scopes), sorted(want.Scopes)) &&
		slices.Equal(sorted(got.Policies), sorted(want.Policies))
}
