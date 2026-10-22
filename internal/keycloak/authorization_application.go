package keycloak

import (
	"context"
	"encoding/json"
	"strings"
)

// authorizationWriter binds every write, including journal checkpoints and
// feature toggles, to a fresh exact application owner. Guards compose with the
// controller's current-reference validation and survive credential retries.
func (c *Client) authorizationWriter(ctx context.Context, model AuthorizationModel, id string) (*Client, error) {
	if model.OwnerUID == "" {
		return c, nil // Direct native adapter callers do not acquire a Hanko journal.
	}
	guard := func(ctx context.Context) error { return c.requireAuthorizationApplication(ctx, model, id) }
	if err := guard(ctx); err != nil {
		return nil, err
	}
	return c.WithMutationGuard(guard), nil
}

func (c *Client) requireAuthorizationApplication(ctx context.Context, model AuthorizationModel, id string) error {
	if model.ApplicationUID == "" || len(model.ApplicationUID) > 128 || id == "" ||
		strings.TrimSpace(model.ApplicationRef) == strings.TrimSpace(c.CredentialClientID()) {
		return ErrAuthorizationOwnershipConflict
	}
	switch strings.TrimSpace(model.ApplicationRef) {
	case "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console":
		return ErrAuthorizationOwnershipConflict
	}
	var document map[string]any
	if err := c.get(ctx, authorizationClientPath(model.Realm, id), &document); err != nil {
		return err
	}
	var app Application
	if decodeSnapshot(document, &app) != nil || app.ID != id || app.ClientID != model.ApplicationRef || !ApplicationOwned(&app, model.ApplicationUID) {
		return ErrAuthorizationOwnershipConflict
	}
	if _, _, err := parseAuthorizationJournal(document, model.OwnerUID, id); err != nil {
		return err
	}
	return authorizationJournalMatchesApplication(document, model.ApplicationUID)
}

func authorizationJournalMatchesApplication(document map[string]any, uid string) error {
	if raw := journalValue(document); raw != "" {
		var journal authorizationJournal
		if json.Unmarshal([]byte(raw), &journal) != nil || (journal.Version != 1 && journal.ApplicationUID != uid) {
			return ErrAuthorizationOwnershipConflict
		}
	}
	return nil
}
