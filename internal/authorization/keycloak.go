package authorization

import (
	"context"
	"errors"

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
		ServiceAccountPrincipals: true, ResourceObjects: true,
		ResourceURIMatching: true, UMARPT: true, NativePermissionClaim: true,
	}, nil
}

func (d *KeycloakDriver) Observe(ctx context.Context, model Model) (State, error) {
	state, err := d.client.ObserveAuthorization(ctx, toKeycloakModel(model))
	if err != nil {
		return State{}, err
	}
	capabilities, _ := d.Capabilities(ctx, model.Realm)
	result := State{ProviderResourceServerID: state.ResourceServerID, Capabilities: capabilities}
	for _, object := range state.NativeObjects {
		result.Findings = append(result.Findings, Finding{
			Classification: "unsupported", ObjectKind: object.Kind, ObjectName: object.Name,
			Code: "provider_native_observation", Message: "provider object is visible but not managed in Observe mode", ReadOnly: true,
		})
	}
	return result, nil
}

func (d *KeycloakDriver) Reconcile(ctx context.Context, model Model, owned ManagedObjects) (State, error) {
	capabilities, err := d.Capabilities(ctx, model.Realm)
	if err != nil {
		return State{}, err
	}
	if err := ValidateCapabilities(model, capabilities); err != nil {
		return State{}, err
	}
	state, err := d.client.ReconcileAuthorization(ctx, toKeycloakModel(model), toKeycloakManaged(owned))
	if err != nil {
		if errors.Is(err, keycloak.ErrAuthorizationOwnershipConflict) {
			return State{}, errors.Join(ErrOwnershipConflict, err)
		}
		return State{}, err
	}
	return State{
		ProviderResourceServerID: state.ResourceServerID,
		Capabilities:             capabilities,
		ManagedObjects:           fromKeycloakManaged(state.ManagedObjects),
	}, nil
}

func (d *KeycloakDriver) DeleteOwned(ctx context.Context, model Model, owned ManagedObjects) error {
	return d.client.DeleteAuthorizationOwned(ctx, toKeycloakModel(model), owned.ResourceServerID, toKeycloakManaged(owned))
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
			converted.Principals = append(converted.Principals, keycloak.AuthorizationPrincipal{Kind: principal.Kind, Ref: principal.Ref})
		}
		result.Permissions = append(result.Permissions, converted)
	}
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
