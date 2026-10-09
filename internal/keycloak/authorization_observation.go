package keycloak

import (
	"context"
	"slices"
	"strconv"
)

// AuthorizationObservation is an explicit semantic projection, not a provider
// representation. IDs select bindings and ownership but never enter identity.
// Only the adapter hashes this private execution result; no inventory is public.
type AuthorizationObservation struct {
	Enabled     bool
	Complete    bool
	Scopes      []ObservedAuthorizationScope
	Resources   []ObservedAuthorizationResource
	Policies    []ObservedAuthorizationPolicy
	Permissions []ObservedAuthorizationPermission
}
type ObservedAuthorizationScope struct {
	Name, Description string
	Present, Owned    bool
}
type ObservedAuthorizationResource struct {
	Name, DisplayName, Type string
	Present, Owned          bool
	URIs, Scopes            []string
	UnknownScopes           int
}
type ObservedAuthorizationPolicy struct {
	Name, Type, Logic, DecisionStrategy string
	Present, Owned                      bool
	Principals                          []string
	UnknownPrincipals                   int
	GroupsClaimConfigured               bool `json:",omitempty"`
}
type ObservedAuthorizationPermission struct {
	Name, Type, Logic, DecisionStrategy string
	Present, Owned                      bool
	Resources, Scopes, Policies         []string
	UnknownBindings                     int
}

func semanticSet(values []string) []string {
	values = append([]string{}, values...)
	slices.Sort(values)
	return slices.Compact(values)
}
func observedBindings(ids []string, names map[string]string) ([]string, int) {
	result := []string{}
	unknown := 0
	for _, id := range semanticSet(ids) {
		if name, ok := names[id]; ok {
			result = append(result, name)
		} else {
			unknown++
		}
	}
	return semanticSet(result), unknown
}
func ownsObservation(refs []AuthorizationManagedReference, name, id string) bool {
	return id != "" && refsByName(refs)[name].ID == id
}

// observeAuthorizationGraph uses all the typed/binding reads already qualified
// by the permission contract. Unknown principals are counts, never raw IDs.
func (c *Client) observeAuthorizationGraph(ctx context.Context, model AuthorizationModel, state *AuthorizationState, owned AuthorizationManagedObjects, base string) error {
	var scopes []authorizationScopeRepresentation
	if err := readAuthorizationCollection(ctx, c, base+authorizationScopePath, &scopes); err != nil {
		return err
	}
	var resources []authorizationResourceRepresentation
	if err := readAuthorizationCollection(ctx, c, base+authorizationResourcePath, &resources); err != nil {
		return err
	}
	policies, err := c.loadAuthorizationPolicies(ctx, base)
	if err != nil {
		return err
	}
	_, permissions, err := c.loadAuthorizationPermissions(ctx, base)
	if err != nil {
		return err
	}
	semanticScopes, wantScopeIDs := observeAuthorizationScopes(model, state, owned, scopes)
	semanticResources, wantResourceIDs := observeAuthorizationResources(model, state, owned, resources, wantScopeIDs, semanticScopes)
	semanticPolicies, wantPolicyIDs, err := c.observeAuthorizationPolicies(ctx, model, state, owned, policies)
	if err != nil {
		return err
	}
	observeAuthorizationPermissions(model, state, owned, permissions, semanticScopes, semanticResources, semanticPolicies, wantScopeIDs, wantResourceIDs, wantPolicyIDs)
	// Summaries reveal kind only, never arbitrary provider-native names/data.
	if len(scopes) > len(model.Scopes) {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "scope"})
	}
	if len(resources) > len(model.Resources) {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "resource"})
	}
	if hasNativeAuthorizationPolicy(policies, permissions, semanticPolicies, owned) {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "policy"})
	}
	if len(permissions) > len(model.Permissions) {
		state.NativeObjects = append(state.NativeObjects, AuthorizationNativeObject{Kind: "permission"})
	}
	return nil
}

func normalizedLogic(value string) string {
	if value == "" {
		return "POSITIVE"
	}
	return value
}
func (c *Client) authorizationPrincipalNames(ctx context.Context, model AuthorizationModel, roleIDs map[string]string) (map[string]string, error) {
	names := map[string]string{}
	for _, permission := range model.Permissions {
		for _, principal := range permission.Principals {
			switch principal.Kind {
			case "realm_role":
				role, err := c.GetRealmRole(ctx, model.Realm, principal.Ref)
				if err != nil {
					return nil, err
				}
				names[role.ID] = "realm_role/" + principal.Ref
				roleIDs[principal.Ref] = role.ID
			case "organization":
				for _, g := range principal.Groups {
					names[g.ID] = "organization/" + observedOrganizationGroupRef(principal, g.ID)
				}
			default:
				id, err := c.resolveClientUUID(ctx, model.Realm, principal.Ref)
				if err != nil {
					return nil, err
				}
				// Application/service-account principals share Keycloak client policy semantics.
				names[id] = "client/" + principal.Ref
			}
		}
	}
	return names, nil
}

func observeAuthorizationScopes(model AuthorizationModel, state *AuthorizationState, owned AuthorizationManagedObjects, scopes []authorizationScopeRepresentation) (map[string]string, map[string]string) {
	o := &state.Observation
	scopeIDs, scopeNames := indexScopes(scopes)
	semanticScopes := map[string]string{}
	for id, scope := range scopeIDs {
		semanticScopes[id] = scope.Name
	}
	wantScopeIDs := map[string]string{}
	for _, want := range model.Scopes {
		got, exists := scopeNames[want.Name]
		item := ObservedAuthorizationScope{Name: want.Name, Present: exists, Owned: ownsObservation(owned.Scopes, want.Name, got.ID), Description: got.DisplayName}
		o.Scopes = append(o.Scopes, item)
		wantScopeIDs[want.Name] = got.ID
		state.Drifted = state.Drifted || !exists || !item.Owned || got.DisplayName != want.Description
	}
	return semanticScopes, wantScopeIDs
}

func observeAuthorizationResources(model AuthorizationModel, state *AuthorizationState, owned AuthorizationManagedObjects, resources []authorizationResourceRepresentation, wantScopeIDs, semanticScopes map[string]string) (map[string]string, map[string]string) {
	o := &state.Observation
	resourceIndex := indexAuthorizationResources(resources)
	semanticResources, wantResourceIDs := map[string]string{}, map[string]string{}
	for id, resource := range resourceIndex.byID {
		semanticResources[id] = resource.Name
	}
	for _, want := range model.Resources {
		got, exists := resourceIndex.byName[want.Name]
		ids := []string{}
		for _, scope := range got.Scopes {
			ids = append(ids, scope.ID)
		}
		names, unknown := observedBindings(ids, semanticScopes)
		item := ObservedAuthorizationResource{Name: want.Name, Present: exists, Owned: ownsObservation(owned.Resources, want.Name, got.ID), DisplayName: got.DisplayName, Type: got.Type, URIs: semanticSet(got.URIs), Scopes: names, UnknownScopes: unknown}
		o.Resources = append(o.Resources, item)
		wantResourceIDs[want.Name] = got.ID
		o.Complete = o.Complete && unknown == 0
		state.Drifted = state.Drifted || !exists || !item.Owned || !resourceEqual(got, buildAuthorizationResource(want, wantScopeIDs))
	}
	return semanticResources, wantResourceIDs
}

func (c *Client) observeAuthorizationPolicies(ctx context.Context, model AuthorizationModel, state *AuthorizationState, owned AuthorizationManagedObjects, policies authorizationPolicyIndex) (map[string]string, map[string][]string, error) {
	o := &state.Observation
	semanticPolicies := map[string]string{}
	wantPolicyIDs := map[string][]string{}
	state.RealmRoleIDs = map[string]string{}
	principalNames, err := c.authorizationPrincipalNames(ctx, model, state.RealmRoleIDs)
	if err != nil {
		return nil, nil, err
	}
	for _, permission := range model.Permissions {
		roles, clients, groups, err := c.resolveAuthorizationPrincipals(ctx, model.Realm, permission.Principals)
		if err != nil {
			return nil, nil, err
		}
		for _, want := range desiredAuthorizationPolicies(model.Name, permission.Name, roles, clients, groups) {
			got, exists := policies.byName[want.payload.Name]
			item := ObservedAuthorizationPolicy{Name: want.logical, Present: exists, Owned: ownsObservation(owned.Policies, want.logical, got.ID), Type: got.Type, Logic: normalizedLogic(got.Logic), DecisionStrategy: got.DecisionStrategy, Principals: []string{}}
			observePolicyPrincipals(got, principalNames, &item)
			item.Principals = semanticSet(item.Principals)
			o.Policies = append(o.Policies, item)
			o.Complete = o.Complete && !got.Incomplete && item.UnknownPrincipals == 0 && (!exists || got.DecisionStrategy != "")
			state.Drifted = state.Drifted || !exists || !item.Owned || !policyEqual(got, want.payload, want.kind)
			if exists {
				semanticPolicies[got.ID] = want.logical
				wantPolicyIDs[permission.Name] = append(wantPolicyIDs[permission.Name], got.ID)
			}
		}
	}
	return semanticPolicies, wantPolicyIDs, nil
}

func observeAuthorizationPermissions(model AuthorizationModel, state *AuthorizationState, owned AuthorizationManagedObjects, permissions map[string]authorizationPermissionRepresentation, semanticScopes, semanticResources, semanticPolicies, wantScopeIDs, wantResourceIDs map[string]string, wantPolicyIDs map[string][]string) {
	o := &state.Observation
	for _, want := range model.Permissions {
		got, exists := permissions[want.Name]
		r, ur := observedBindings(got.Resources, semanticResources)
		s, us := observedBindings(got.Scopes, semanticScopes)
		p, up := observedBindings(got.Policies, semanticPolicies)
		item := ObservedAuthorizationPermission{Name: want.Name, Present: exists, Owned: ownsObservation(owned.Permissions, want.Name, got.ID), Type: got.Type, Logic: normalizedLogic(got.Logic), DecisionStrategy: got.DecisionStrategy, Resources: r, Scopes: s, Policies: p, UnknownBindings: ur + us + up}
		o.Permissions = append(o.Permissions, item)
		o.Complete = o.Complete && item.UnknownBindings == 0 && (!exists || got.DecisionStrategy != "")
		state.Drifted = state.Drifted || !exists || !item.Owned || !permissionEqual(got, buildAuthorizationPermission(want, wantScopeIDs, wantResourceIDs, wantPolicyIDs))
	}
}

func observePolicyPrincipals(got authorizationPolicyRepresentation, principalNames map[string]string, item *ObservedAuthorizationPolicy) {
	for _, role := range got.Roles {
		if name, ok := principalNames[role.ID]; ok {
			item.Principals = append(item.Principals, name+"/required="+strconv.FormatBool(role.Required))
		} else {
			item.UnknownPrincipals++
		}
	}
	item.GroupsClaimConfigured = got.GroupsClaim != ""
	for _, g := range got.Groups {
		if name, ok := principalNames[g.ID]; ok {
			item.Principals = append(item.Principals, name+"/extendChildren="+strconv.FormatBool(g.ExtendChildren))
		} else {
			item.UnknownPrincipals++
		}
	}
	for _, client := range got.Clients {
		if name, ok := principalNames[client]; ok {
			item.Principals = append(item.Principals, name)
		} else {
			item.UnknownPrincipals++
		}
	}
}

// Keycloak's generic policy collection also contains scope permissions. An
// independently observed journal-owned permission is not a native policy gap.
func hasNativeAuthorizationPolicy(policies authorizationPolicyIndex, permissions map[string]authorizationPermissionRepresentation, known map[string]string, owned AuthorizationManagedObjects) bool {
	for id, policy := range policies.byID {
		if _, ok := known[id]; ok {
			continue
		}
		permission, ok := permissions[policy.Name]
		if ok && policy.Type == "scope" && permission.ID == id && ownsObservation(owned.Permissions, policy.Name, id) {
			continue
		}
		return true
	}
	return false
}
