package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// KeycloakDriver adapts Keycloak Authorization Services to the neutral Driver.
type KeycloakDriver struct {
	client *keycloak.Client
}

func NewKeycloakDriver(client *keycloak.Client) *KeycloakDriver {
	return &KeycloakDriver{client: client}
}

func (*KeycloakDriver) Capabilities(context.Context, string) (Capabilities, error) {
	return Capabilities{
		ScopeGrants: true, RolePrincipals: true, ApplicationPrincipals: true,
		ServiceAccountPrincipals: true, ResourceObjects: true, OrganizationPrincipals: true, OrganizationDescendants: true,
		ResourceURIMatching: true, UMARPT: true, NativePermissionClaim: true,
	}, nil
}

func (d *KeycloakDriver) Observe(ctx context.Context, plan Plan) (State, error) {
	if err := plan.Validate(plan); err != nil {
		return State{}, err
	}
	model := plan.resolved.model
	state, err := d.client.ObserveAuthorization(ctx, modelForPlan(plan))
	if err != nil {
		return State{}, boundedAuthorizationError(err)
	}
	capabilities, _ := d.Capabilities(ctx, model.Realm)
	result := observationState(state, capabilities)
	result.Structure = structuralObservation(state)
	result.RealmRoleIDs = state.RealmRoleIDs
	seen := map[string]bool{}
	for _, object := range state.NativeObjects {
		if seen[object.Kind] {
			continue
		}
		seen[object.Kind] = true
		result.Findings = append(result.Findings, iamcontract.Bound(Finding{
			Classification: iamcontract.Unsupported, ObjectKind: object.Kind,
			Code: "provider_native_observation", Message: "provider object is visible but outside managed desired state", ReadOnly: true,
		}))
	}
	result.Findings = iamcontract.Findings(result.Findings)
	return result, nil
}

func (d *KeycloakDriver) Reconcile(ctx context.Context, plan Plan, owned ManagedObjects) (State, error) {
	if err := plan.Validate(plan); err != nil {
		return State{}, err
	}
	model := plan.resolved.model
	if plan.preconditions.ResourceUID == "" {
		return State{}, iamcontract.ErrRejected
	}
	capabilities, err := d.Capabilities(ctx, model.Realm)
	if err != nil {
		return State{}, iamcontract.SafeError(err)
	}
	if err := ValidateCapabilities(model, capabilities); err != nil {
		return State{}, iamcontract.SafeError(err)
	}
	state, err := d.client.ReconcileAuthorization(ctx, modelForPlan(plan), toKeycloakManaged(owned))
	if err != nil {
		if errors.Is(err, keycloak.ErrAuthorizationReadBack) {
			return State{ProviderResourceServerID: state.ResourceServerID, ManagedObjects: fromKeycloakManaged(state.ManagedObjects)}, errors.Join(iamcontract.ErrDrift, iamcontract.SafeError(err))
		}
		if errors.Is(err, keycloak.ErrAuthorizationOwnershipConflict) {
			return State{ProviderResourceServerID: state.ResourceServerID, ManagedObjects: fromKeycloakManaged(state.ManagedObjects)}, errors.Join(ErrOwnershipConflict, iamcontract.SafeError(err))
		}
		return State{ProviderResourceServerID: state.ResourceServerID, ManagedObjects: fromKeycloakManaged(state.ManagedObjects)}, boundedAuthorizationError(err)
	}
	result, err := d.Observe(ctx, plan)
	result.ProviderResourceServerID = state.ResourceServerID
	result.ManagedObjects = fromKeycloakManaged(state.ManagedObjects)
	if err != nil {
		return result, err
	}
	return result, nil
}

func (d *KeycloakDriver) DeleteOwned(ctx context.Context, model Model, owned ManagedObjects, ownerUID string) error {
	if ownerUID == "" {
		return iamcontract.ErrRejected
	}
	native := toKeycloakModel(model)
	native.OwnerUID = ownerUID
	return boundedAuthorizationError(d.client.DeleteAuthorizationOwned(ctx, native, owned.ResourceServerID, toKeycloakManaged(owned)))
}

func boundedAuthorizationError(err error) error {
	if errors.Is(err, keycloak.ErrAuthorizationCleanupConflict) {
		return errors.Join(keycloak.ErrAuthorizationCleanupConflict, iamcontract.SafeError(err))
	}
	if errors.Is(err, keycloak.ErrAuthorizationReadLimit) {
		return errors.Join(iamcontract.ErrObservationIncomplete, iamcontract.SafeError(err))
	}
	return iamcontract.SafeError(err)
}

func toKeycloakModel(model Model) keycloak.AuthorizationModel {
	result := keycloak.AuthorizationModel{
		Name: model.Name, Realm: model.Realm, Audience: model.Audience,
		DisplayName: model.DisplayName, ApplicationRef: model.ApplicationRef,
	}
	for _, scope := range model.Scopes {
		result.Scopes = append(result.Scopes, keycloak.AuthorizationScope{Name: scope.Name, Description: scope.Description})
	}
	for _, resource := range model.Resources {
		result.Resources = append(result.Resources, keycloak.AuthorizationResource{
			Name: resource.Name, DisplayName: resource.DisplayName, URIs: resource.URIs, Type: resource.Type, Scopes: resource.Scopes,
		})
	}
	for _, permission := range model.Permissions {
		converted := keycloak.AuthorizationPermission{Name: permission.Name, Resources: permission.Resources, Scopes: permission.Scopes}
		for _, principal := range permission.Principals {
			converted.Principals = append(converted.Principals, keycloakPrincipal(principal))
		}
		result.Permissions = append(result.Permissions, converted)
	}
	return result
}

// KeycloakAdoptionModel uses the same semantic conversion as reconciliation.
// Provider ownership must be proved separately by the aggregate transaction.
func KeycloakAdoptionModel(model Model, uid string) keycloak.AuthorizationModel {
	result := toKeycloakModel(model)
	result.OwnerUID = uid
	return result
}

func toKeycloakManaged(owned ManagedObjects) keycloak.AuthorizationManagedObjects {
	return keycloak.AuthorizationManagedObjects{
		ResourceServerID: owned.ResourceServerID,
		Scopes:           toKeycloakRefs(owned.Scopes),
		Resources:        toKeycloakRefs(owned.Resources),
		Policies:         toKeycloakRefs(owned.Policies),
		Permissions:      toKeycloakRefs(owned.Permissions),
	}
}

func fromKeycloakManaged(owned keycloak.AuthorizationManagedObjects) ManagedObjects {
	return ManagedObjects{
		ResourceServerID: owned.ResourceServerID,
		Scopes:           fromKeycloakRefs(owned.Scopes),
		Resources:        fromKeycloakRefs(owned.Resources),
		Policies:         fromKeycloakRefs(owned.Policies),
		Permissions:      fromKeycloakRefs(owned.Permissions),
	}
}

func toKeycloakRefs(refs []ManagedReference) []keycloak.AuthorizationManagedReference {
	result := make([]keycloak.AuthorizationManagedReference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, keycloak.AuthorizationManagedReference{Name: ref.Name, ID: ref.ID})
	}
	return result
}

func fromKeycloakRefs(refs []keycloak.AuthorizationManagedReference) []ManagedReference {
	result := make([]ManagedReference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ManagedReference{Name: ref.Name, ID: ref.ID})
	}
	return result
}

func modelForPlan(plan Plan) keycloak.AuthorizationModel {
	model := toKeycloakModel(plan.resolved.model)
	model.OwnerUID = plan.preconditions.ResourceUID
	return model
}
func observationState(state keycloak.AuthorizationState, caps Capabilities) State {
	data, _ := json.Marshal(state.Observation)
	result := State{ProviderResourceServerID: state.ResourceServerID, Capabilities: caps, Drifted: state.Drifted, Observation: iamcontract.Observation{StateHash: iamcontract.Hash(iamcontract.Version, "authorization", "observation", data), Complete: state.Observation.Complete, Drifted: state.Drifted}}
	if !state.Observation.Complete {
		result.Findings = []Finding{{Classification: iamcontract.Unsupported, ObjectKind: "resource_server", Code: "incomplete_observation", Message: "one or more provider bindings cannot be completely identified", ReadOnly: true}}
	}
	return result
}

func structuralObservation(state keycloak.AuthorizationState) *StructuralObservation {
	o := state.Observation
	result := &StructuralObservation{Enabled: o.Enabled, Complete: o.Complete, Native: len(state.NativeObjects) > 0}
	for _, r := range o.Resources {
		result.Resources = append(result.Resources, ObservedResource{Name: r.Name, Present: r.Present, Scopes: r.Scopes, UnknownScopes: r.UnknownScopes})
	}
	for _, p := range o.Policies {
		result.Policies = append(result.Policies, ObservedPolicy{Name: p.Name, Type: p.Type, Logic: p.Logic, DecisionStrategy: p.DecisionStrategy, Present: p.Present, Owned: p.Owned, Principals: p.Principals, UnknownPrincipals: p.UnknownPrincipals, GroupsClaimConfigured: p.GroupsClaimConfigured})
	}
	for _, p := range o.Permissions {
		result.Permissions = append(result.Permissions, ObservedPermission{Name: p.Name, Type: p.Type, Logic: p.Logic, DecisionStrategy: p.DecisionStrategy, Present: p.Present, Owned: p.Owned, Resources: p.Resources, Scopes: p.Scopes, Policies: p.Policies, UnknownBindings: p.UnknownBindings})
	}
	return result
}
