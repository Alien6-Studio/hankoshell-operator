package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func currentIdentityMapperID(managed []api.ManagedIdentityMappingReference, previous api.ManagedIdentityMappingReference) bool {
	for _, item := range managed {
		if item.IdentityProvider == previous.IdentityProvider && item.KeycloakID != "" && item.KeycloakID == previous.KeycloakID {
			return true
		}
	}
	return false
}
func currentTokenMapperID(managed []api.ManagedTokenClaimReference, id string) bool {
	for _, item := range managed {
		if id != "" && item.KeycloakID == id {
			return true
		}
	}
	return false
}

// Status IDs are lookup hints. A fresh provider-side UID marker is required for
// mapper deletion, including realm-scoped broker mappers outside the client.
func deleteOwnedApplicationIdentityMapper(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client, alias, id string) error {
	if id == "" || app.UID == "" {
		return nil
	}
	mappers, err := kc.ListIdentityProviderMappers(ctx, app.Spec.RealmRef, alias)
	if err != nil {
		return err
	}
	for _, mapper := range mappers {
		if mapper.ID == id && mapper.Config[applications.OwnerAttribute] == string(app.UID) {
			return kc.DeleteIdentityProviderMapper(ctx, app.Spec.RealmRef, alias, id)
		}
	}
	return nil
}

func deleteOwnedApplicationTokenMapper(ctx context.Context, kc *keycloak.Client, owner tokenClaimOwner, id string) error {
	if id == "" {
		return nil
	}
	// Service-account reconciliation has its independent existing contract.
	if owner.uid == "" {
		return kc.DeleteClientProtocolMapper(ctx, owner.realm, owner.clientID, id)
	}
	mappers, err := kc.ListClientProtocolMappers(ctx, owner.realm, owner.clientID)
	if err != nil {
		return err
	}
	for _, mapper := range mappers {
		if mapper.ID == id && mapper.Config[applications.OwnerAttribute] == owner.uid {
			return kc.DeleteClientProtocolMapper(ctx, owner.realm, owner.clientID, id)
		}
	}
	return nil
}
