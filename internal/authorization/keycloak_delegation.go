package authorization

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func (d *KeycloakDriver) WithMutationGuard(guard func(context.Context) error) Driver {
	return &KeycloakDriver{client: d.client.WithMutationGuard(guard), boundedDelegation: d.boundedDelegation}
}

func ordinaryDelegationModel(model Model) Model {
	result := model
	result.Permissions = nil
	result.DelegationContext = nil
	for _, permission := range model.Permissions {
		if permission.Delegation == nil {
			result.Permissions = append(result.Permissions, permission)
		}
	}
	return result
}

func (d *KeycloakDriver) PrepareDelegation(ctx context.Context, model Model, owner string) (Model, error) {
	model = canonicalModel(model)
	_, prepared, err := d.prepareBoundedDelegation(ctx, model, owner)
	if err != nil {
		return Model{}, err
	}
	result := canonicalModel(model)
	result.DelegationContext.Runtime = iamcontract.Digest(prepared.Runtime)
	return result, nil
}

func (d *KeycloakDriver) prepareBoundedDelegation(ctx context.Context, model Model, owner string) (keycloak.AuthorizationModel, keycloak.BoundedDelegationPreparation, error) {
	var prepared keycloak.BoundedDelegationPreparation
	if !d.boundedDelegation || d.client == nil || model.DelegationContext == nil || model.DelegationContext.AudienceUID == "" {
		return keycloak.AuthorizationModel{}, prepared, DelegationUnsupported()
	}
	native, err := toKeycloakModel(ordinaryDelegationModel(model))
	if err != nil {
		return native, prepared, err
	}
	native.OwnerUID = owner
	ordinary := map[string][]keycloak.BoundedDelegationPrincipal{}
	permissions := []keycloak.BoundedDelegationPermission{}
	for _, permission := range model.Permissions {
		principals := boundedPrincipals(permission.Principals)
		if permission.Delegation == nil {
			ordinary[permission.Name] = principals
			continue
		}
		delegation := permission.Delegation
		permissions = append(permissions, keycloak.BoundedDelegationPermission{Name: permission.Name, Resources: permission.Resources, Scopes: permission.Scopes,
			Actor: boundedIdentity(delegation.Actor), Subject: boundedIdentity(delegation.Subject), Principals: principals,
			MaxDepth: delegation.MaxDepth, MaxTTLSeconds: delegation.MaxTTLSeconds, TaskAuthorization: delegation.TaskAuthorization})
	}
	prepared, err = d.client.PrepareBoundedDelegation(ctx, native, model.DelegationContext.AudienceUID, permissions, ordinary)
	if err != nil {
		return native, prepared, boundedDelegationError(err)
	}
	return native, prepared, nil
}

func boundedIdentity(principal Principal) keycloak.BoundedDelegationIdentity {
	return keycloak.BoundedDelegationIdentity{Kind: principal.Kind, ClientID: principal.Ref, UID: principal.SoftwareUID}
}

func boundedPrincipals(principals []Principal) []keycloak.BoundedDelegationPrincipal {
	result := []keycloak.BoundedDelegationPrincipal{}
	for _, principal := range principals {
		native := keycloak.BoundedDelegationPrincipal{Kind: principal.Kind, Ref: principal.Ref, UID: principal.SoftwareUID}
		if principal.Organization != nil {
			for _, group := range principal.Organization.Groups {
				native.Groups = append(native.Groups, keycloak.BoundedDelegationBinding{ID: group.ID, Attribute: "hanko.sh/organization-uid", Value: group.UID})
			}
		}
		result = append(result, native)
	}
	return result
}

func (d *KeycloakDriver) reconcileBoundedDelegation(ctx context.Context, plan Plan, owned ManagedObjects) (State, error) {
	model := plan.resolved.model
	native, prepared, err := d.prepareBoundedDelegation(ctx, model, plan.preconditions.ResourceUID)
	if err != nil {
		return State{}, err
	}
	if model.DelegationContext == nil || !iamcontract.ValidDigest(string(model.DelegationContext.Runtime)) || model.DelegationContext.Runtime != iamcontract.Digest(prepared.Runtime) {
		return State{}, iamcontract.ErrStale
	}
	state, err := d.client.ApplyBoundedDelegation(ctx, native, prepared, toKeycloakManaged(owned), string(plan.Identity().Plan))
	if err != nil {
		return State{ProviderResourceServerID: state.ResourceServerID, ManagedObjects: fromKeycloakManaged(state.ManagedObjects)}, boundedDelegationError(err)
	}
	result, err := d.observeBoundedDelegation(ctx, plan)
	result.ManagedObjects = fromKeycloakManaged(state.ManagedObjects)
	return result, err
}

func (d *KeycloakDriver) observeBoundedDelegation(ctx context.Context, plan Plan) (State, error) {
	native, prepared, err := d.prepareBoundedDelegation(ctx, plan.resolved.model, plan.preconditions.ResourceUID)
	if err != nil {
		return State{}, err
	}
	if plan.resolved.model.DelegationContext == nil || plan.resolved.model.DelegationContext.Runtime != iamcontract.Digest(prepared.Runtime) {
		return State{}, iamcontract.ErrStale
	}
	state, err := d.client.ObserveBoundedAuthorization(ctx, native)
	if err != nil {
		return State{}, boundedDelegationError(err)
	}
	verified, identity, err := d.client.ObserveBoundedDelegation(ctx, native, prepared, state.ManagedObjects, string(plan.Identity().Plan))
	if err != nil {
		return State{}, boundedDelegationError(err)
	}
	capabilities, err := d.Capabilities(ctx, native.Realm)
	if err != nil {
		return State{}, err
	}
	result := observationState(state, capabilities)
	result.Structure = structuralObservation(state)
	result.RealmRoleIDs = state.RealmRoleIDs
	result.ManagedObjects = fromKeycloakManaged(state.ManagedObjects)
	result.Drifted = result.Drifted || !verified
	result.Observation.Drifted = result.Observation.Drifted || !verified
	data, _ := json.Marshal([]any{result.Observation.StateHash, identity, verified})
	result.Observation.StateHash = iamcontract.Hash(iamcontract.Version, "authorization", "bounded-delegation-observation", data)
	if verified {
		for _, permission := range plan.resolved.model.Permissions {
			if permission.Delegation != nil {
				result.Structure.Delegations = append(result.Structure.Delegations, permission.Name)
			}
		}
	}
	return result, nil
}

func boundedDelegationError(err error) error {
	var excess keycloak.BoundedDelegationExcessError
	if errors.As(err, &excess) {
		findings := []Finding{{Classification: iamcontract.Unsupported, ObjectKind: "delegation", ObjectName: excess.Permission,
			Code: "DelegationAuthorityExceeded", Message: "permission exceeds the effective authority of its actor or subject"}}
		for _, reference := range []struct{ kind, name string }{{"resource", excess.Resource}, {"scope", excess.Scope}} {
			if reference.name != "" {
				findings = append(findings, Finding{Classification: iamcontract.Unsupported, ObjectKind: reference.kind, ObjectName: reference.name,
					Code: "DelegationAuthorityExceeded", Message: "requested delegated authority is not granted to both actor and subject"})
			}
		}
		return DelegationRejection{Findings: iamcontract.Findings(findings)}
	}
	switch {
	case errors.Is(err, keycloak.ErrBoundedDelegationUnsupported):
		return DelegationUnsupported()
	case errors.Is(err, keycloak.ErrAuthorizationOwnershipConflict):
		return errors.Join(ErrOwnershipConflict, iamcontract.SafeError(err))
	default:
		return boundedAuthorizationError(err)
	}
}
