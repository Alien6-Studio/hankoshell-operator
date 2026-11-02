package keycloak

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

type oauthClientScope struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// ValidateServiceAccountScopes resolves the complete requested set before a
// controller creates a client or exposes its credential. It never mutates scopes.
func (c *Client) ValidateServiceAccountScopes(ctx context.Context, realm string, names []string) error {
	if names == nil {
		return nil
	}
	if err := validateOAuthScopeNames(names); err != nil {
		return err
	}
	_, err := c.resolveOAuthScopes(ctx, realm, names)
	return err
}

// ReconcileServiceAccountScopes manages only native scope attachments on an
// owned client. Shared realm scopes must already exist and remain administrator
// owned. Nil is unmanaged; an explicit empty list revokes all attachments.
func (c *Client) ReconcileServiceAccountScopes(ctx context.Context, realm, clientID, uid string, names []string, verify func(context.Context) error) error {
	if names == nil {
		return nil
	}
	if err := validateOAuthScopeNames(names); err != nil {
		return err
	}
	app, err := c.ownedScopeClient(ctx, realm, clientID, uid, "", verify)
	if err != nil {
		return err
	}
	desired, err := c.resolveOAuthScopes(ctx, realm, names)
	if err != nil {
		return err
	}
	base := applicationPath(realm, app.ID)
	defaults, err := c.readOAuthScopeAttachments(ctx, base, "default")
	if err != nil {
		return err
	}
	optional, err := c.readOAuthScopeAttachments(ctx, base, "optional")
	if err != nil {
		return err
	}
	// Revoke before granting. An undeclared optional scope would still allow an
	// OAuth caller to request authority outside the declared default set.
	for _, group := range []struct {
		kind   string
		scopes []oauthClientScope
	}{{"optional", optional}, {"default", defaults}} {
		for _, scope := range group.scopes {
			if group.kind == "default" && slices.ContainsFunc(desired, func(want oauthClientScope) bool { return want.ID == scope.ID }) {
				continue
			}
			if _, err := c.ownedScopeClient(ctx, realm, clientID, uid, app.ID, verify); err != nil {
				return err
			}
			if err := c.deleteMapper(ctx, base+"/"+group.kind+"-client-scopes/"+url.PathEscape(scope.ID)); err != nil {
				return fmt.Errorf("detach OAuth client scope: %w", err)
			}
		}
	}
	for _, scope := range desired {
		if slices.ContainsFunc(defaults, func(have oauthClientScope) bool { return have.ID == scope.ID }) {
			continue
		}
		// Pin the definition's UUID and name again at the mutation boundary. A
		// same-name replacement never inherits authority from an earlier lookup.
		var current oauthClientScope
		if err := c.get(ctx, adminRealmsPath+url.PathEscape(realm)+"/client-scopes/"+url.PathEscape(scope.ID), &current); err != nil || current != scope {
			return ErrApplicationPrecondition
		}
		if _, err := c.ownedScopeClient(ctx, realm, clientID, uid, app.ID, verify); err != nil {
			return err
		}
		if err := c.putJSON(ctx, base+"/default-client-scopes/"+url.PathEscape(scope.ID), nil); err != nil {
			return fmt.Errorf("attach OAuth client scope: %w", err)
		}
	}
	if _, err := c.ownedScopeClient(ctx, realm, clientID, uid, app.ID, verify); err != nil {
		return err
	}
	defaults, err = c.readOAuthScopeAttachments(ctx, base, "default")
	if err != nil {
		return err
	}
	optional, err = c.readOAuthScopeAttachments(ctx, base, "optional")
	if err != nil {
		return err
	}
	if len(optional) != 0 || !sameOAuthScopes(defaults, desired) {
		return fmt.Errorf("OAuth client scope attachments were not confirmed")
	}
	return verify(ctx)
}

func validateOAuthScopeNames(names []string) error {
	if len(names) > 64 {
		return fmt.Errorf("OAuth client scopes exceed limit")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !clientScopeReference.MatchString(name) || strings.HasPrefix(name, "eyJ") || seen[name] {
			return fmt.Errorf("invalid or duplicate OAuth client scope")
		}
		seen[name] = true
	}
	return nil
}

func (c *Client) ownedScopeClient(ctx context.Context, realm, clientID, uid, expectedID string, verify func(context.Context) error) (*Application, error) {
	if verify == nil || verify(ctx) != nil {
		return nil, ErrApplicationPrecondition
	}
	app, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return nil, err
	}
	if !ServiceAccountOwned(app, uid) || !m2mAuthenticationEnvelope(app) || app.ClientAuthenticatorType != "client-secret" || (expectedID != "" && app.ID != expectedID) {
		return nil, ErrApplicationPrecondition
	}
	if _, adopted := app.Attributes[adoption.ReceiptKey]; adopted {
		observed, err := c.ReadClientOwnership(ctx, realm, clientID)
		if err != nil || observed == nil || observed.Application.ID != app.ID || !validClientAdoptionReceipt(&observed.Application, "HankoServiceAccount", uid) || !observed.PreservationQualified() {
			return nil, ErrAdoptionPrecondition
		}
	}
	return app, nil
}

func (c *Client) resolveOAuthScopes(ctx context.Context, realm string, names []string) ([]oauthClientScope, error) {
	if len(names) == 0 {
		return []oauthClientScope{}, nil
	}
	var available []oauthClientScope
	if err := c.get(ctx, adminRealmsPath+url.PathEscape(realm)+"/client-scopes", &available); err != nil {
		return nil, err
	}
	if len(available) > 4096 {
		return nil, fmt.Errorf("realm OAuth client scope inventory exceeds limit")
	}
	wanted := make([]oauthClientScope, 0, len(names))
	for _, name := range names {
		var found *oauthClientScope
		for _, scope := range available {
			if scope.Name != name {
				continue
			}
			if found != nil || !validOAuthScopeID(scope.ID) || scope.Protocol != openIDConnectProtocol {
				return nil, fmt.Errorf("OAuth client scope %q is ambiguous or unsupported", name)
			}
			copy := scope
			found = &copy
		}
		if found == nil {
			return nil, fmt.Errorf("OAuth client scope %q must be provisioned in the realm", name)
		}
		wanted = append(wanted, *found)
	}
	return wanted, nil
}

func (c *Client) readOAuthScopeAttachments(ctx context.Context, base, kind string) ([]oauthClientScope, error) {
	var scopes []oauthClientScope
	if err := c.get(ctx, base+"/"+kind+"-client-scopes", &scopes); err != nil {
		return nil, err
	}
	if len(scopes) > 128 {
		return nil, fmt.Errorf("OAuth client scope attachments exceed limit")
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !validOAuthScopeID(scope.ID) || scope.Name == "" || seen[scope.ID] {
			return nil, ErrApplicationPrecondition
		}
		seen[scope.ID] = true
	}
	return scopes, nil
}

func validOAuthScopeID(id string) bool {
	return id != "" && id != "." && id != ".." && len(id) <= 255 && !strings.ContainsAny(id, "/\\\x00\r\n")
}

func sameOAuthScopes(left, right []oauthClientScope) bool {
	if len(left) != len(right) {
		return false
	}
	for _, scope := range left {
		if !slices.Contains(right, scope) {
			return false
		}
	}
	return true
}
