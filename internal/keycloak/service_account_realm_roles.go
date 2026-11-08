package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

// ErrServiceAccountUnavailable reports a client without an enabled service account.
var ErrServiceAccountUnavailable = errors.New("client has no enabled service account")

type serviceAccountGrantKey struct{}
type serviceAccountGrant struct{ realm, clientUUID, userID string }

// validateServiceAccountGrant pins user role-mapping routes to the service
// account resolved from one owned client UUID. Other users stay unreachable.
func validateServiceAccountGrant(request *http.Request, path string) (bool, error) {
	clientRead := matchAdminPath("/admin/realms/{realm}/clients/{client}/service-account-user", path)
	mappings := matchAdminPath("/admin/realms/{realm}/users/{user}/role-mappings/realm", path)
	witness, ok := request.Context().Value(serviceAccountGrantKey{}).(serviceAccountGrant)
	if !mappings && (!clientRead || !ok) {
		return false, nil
	}
	if !ok || witness.realm == "" || witness.clientUUID == "" {
		return true, errors.New("service-account role mappings require a resolved owned client")
	}
	base := adminRealmsPath + url.PathEscape(witness.realm)
	expected := base + clientsPath + url.PathEscape(witness.clientUUID) + "/service-account-user"
	if mappings {
		if witness.userID == "" {
			return true, errors.New("service-account role mappings lack a verified service account")
		}
		expected = base + "/users/" + url.PathEscape(witness.userID) + realmRoleMapSeg
	} else if request.Method != http.MethodGet {
		return true, errors.New("service-account lookup is read-only")
	}
	if path != expected || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return true, errors.New("service-account role mapping is outside the resolved client")
	}
	return true, nil
}

func (c *Client) serviceAccountRealmRoles(ctx context.Context, realm, clientUUID string) (context.Context, string, []RealmRole, error) {
	ctx = context.WithValue(ctx, serviceAccountGrantKey{}, serviceAccountGrant{realm: realm, clientUUID: clientUUID})
	var user struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.get(ctx, applicationPath(realm, clientUUID)+"/service-account-user", &user); err != nil {
		return nil, "", nil, err
	}
	if user.ID == "" || !user.Enabled {
		return nil, "", nil, ErrServiceAccountUnavailable
	}
	ctx = context.WithValue(ctx, serviceAccountGrantKey{}, serviceAccountGrant{realm: realm, clientUUID: clientUUID, userID: user.ID})
	path := adminRealmsPath + url.PathEscape(realm) + "/users/" + url.PathEscape(user.ID) + realmRoleMapSeg
	var current []RealmRole
	if err := c.get(ctx, path, &current); err != nil {
		return nil, "", nil, err
	}
	return ctx, path, current, nil
}

// ReadServiceAccountRealmRoles returns the direct realm-role mappings of the
// service account behind one exact client representation.
func (c *Client) ReadServiceAccountRealmRoles(ctx context.Context, realm string, app Application) ([]RealmRole, error) {
	if app.ID == "" {
		return nil, ErrApplicationPrecondition
	}
	_, _, current, err := c.serviceAccountRealmRoles(ctx, realm, app.ID)
	return current, err
}

// ReconcileServiceAccountRealmRoles grants desired realm roles to the client's
// service account and revokes previously managed roles no longer desired.
// Mappings outside desired and previous are never changed.
func (c *Client) ReconcileServiceAccountRealmRoles(ctx context.Context, realm, clientID string, desired, previous []string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	ctx, path, current, err := c.serviceAccountRealmRoles(ctx, realm, uuid)
	if err != nil {
		return fmt.Errorf("read service-account realm roles for client %q: %w", clientID, err)
	}
	currentByName := make(map[string]RealmRole, len(current))
	for _, role := range current {
		currentByName[role.Name] = role
	}
	toAdd, _, err := c.resolveRealmRoleScopes(ctx, realm, desired, currentByName)
	if err != nil {
		return err
	}
	var toRemove []RealmRole
	for _, name := range previous {
		if role, mapped := currentByName[name]; mapped && !slices.Contains(desired, name) {
			toRemove = append(toRemove, role)
		}
	}
	if len(toAdd) > 0 {
		if err := c.writeRealmRoleMappings(ctx, http.MethodPost, path, toAdd); err != nil {
			return fmt.Errorf("grant service-account realm roles for client %q: %w", clientID, err)
		}
	}
	if len(toRemove) > 0 {
		if err := c.writeRealmRoleMappings(ctx, http.MethodDelete, path, toRemove); err != nil {
			return fmt.Errorf("revoke service-account realm roles for client %q: %w", clientID, err)
		}
	}
	return nil
}
