package keycloak

import (
	"context"
	"errors"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

var ErrAdoptionCleanupConflict = errors.New("adopted provider cleanup boundary is not proven")

// A client lifecycle does not own every existing role, mapper or native graph.
// Check the full current client before any cleanup, then again before DELETE.
func (c *Client) CheckAdoptedClientCleanup(ctx context.Context, realm, clientID, kind, uid string) error {
	s, err := c.ReadClientOwnership(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	if !validClientAdoptionReceipt(&s.Application, kind, uid) || !s.PreservationQualified() || s.AuthorizationEnabled() || s.Application.Attributes[authorizationOwnerAttribute] != "" {
		return ErrAdoptionCleanupConflict
	}
	if !adoptedClientMappersOwned(s.mappers, kind, uid) {
		return ErrAdoptionCleanupConflict
	}
	roles, err := c.InventoryClientRoles(ctx, realm, s.Application.ID)
	if err != nil {
		return err
	}
	// Even an owned role can have foreign user/group/policy references. The
	// bounded client inventory does not prove their absence, so a parent
	// receipt cannot authorize cascading role deletion.
	if len(roles) > 0 {
		return ErrAdoptionCleanupConflict
	}
	scopes, err := c.GetClientRealmRoleScopes(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if len(scopes) > 0 {
		return ErrAdoptionCleanupConflict
	}
	return nil
}

func adoptedClientMappersOwned(mappers []map[string]any, kind, uid string) bool {
	for _, mapper := range mappers {
		config, ok := mapper["config"].(map[string]any)
		if !ok {
			return false
		}
		if kind == "HankoApplication" {
			if config[adoption.ApplicationOwnerKey] != uid {
				return false
			}
		} else if config[adoption.ClientOwnerKindKey] != kind || config[adoption.ClientOwnerUIDKey] != uid {
			return false
		}
	}
	return true
}
