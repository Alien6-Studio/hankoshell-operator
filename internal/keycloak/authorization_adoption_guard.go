package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var ErrAuthorizationCleanupConflict = errors.New("authorization cleanup would affect foreign dependencies")

type authorizationAdoptionContextKey struct{}
type authorizationAdoptionAuthority struct{ realm, clientID, ownerUID, realmID, applicationUID, name string }

// A V2 journal adds a fresh graph boundary to every graph mutation. V1 callers
// retain their qualified reconciliation and journal semantics.
func (c *Client) authorizationAdoptionContext(ctx context.Context, model AuthorizationModel, clientID string) (context.Context, error) {
	if model.OwnerUID == "" {
		return ctx, nil
	}
	var document map[string]any
	if err := c.get(ctx, authorizationClientPath(model.Realm, clientID), &document); err != nil {
		return ctx, err
	}
	if raw := journalValue(document); raw == "" {
		return ctx, nil
	}
	var journal authorizationJournal
	if err := json.Unmarshal([]byte(journalValue(document)), &journal); err != nil {
		return ctx, ErrAuthorizationOwnershipConflict
	}
	if _, _, err := parseAuthorizationJournal(document, model.OwnerUID, clientID); err != nil {
		return ctx, err
	}
	if journal.Version != 2 {
		return ctx, nil
	}
	authority := authorizationAdoptionAuthority{model.Realm, clientID, model.OwnerUID, journal.RealmID, journal.ApplicationUID, model.Name}
	if _, err := c.currentAdoptedAuthorizationGraph(ctx, authority); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, authorizationAdoptionContextKey{}, authority), nil
}

func (c *Client) currentAdoptedAuthorizationGraph(ctx context.Context, authority authorizationAdoptionAuthority) (*AuthorizationAdoptionSnapshot, error) {
	var document map[string]any
	if err := c.get(ctx, authorizationClientPath(authority.realm, authority.clientID), &document); err != nil {
		return nil, err
	}
	objects, found, err := parseAuthorizationJournal(document, authority.ownerUID, authority.clientID)
	if err != nil || !found {
		return nil, ErrAuthorizationOwnershipConflict
	}
	var journal authorizationJournal
	if json.Unmarshal([]byte(journalValue(document)), &journal) != nil || journal.Version != 2 || journal.RealmID != authority.realmID || journal.ApplicationUID != authority.applicationUID {
		return nil, ErrAuthorizationOwnershipConflict
	}
	if err := c.verifyAuthorizationJournalRealm(ctx, authority.realm, document); err != nil {
		return nil, err
	}
	var backing Application
	if err := decodeSnapshot(document, &backing); err != nil {
		return nil, err
	}
	if enabled, _ := document["authorizationServicesEnabled"].(bool); !enabled {
		return nil, ErrAdoptionPrecondition
	}
	graph, err := c.InventoryAuthorization(ctx, authority.realm, authority.clientID)
	if err != nil {
		return nil, err
	}
	if err := c.readNativeResourcePermissionDependencies(ctx, authority.realm, authority.clientID, &graph); err != nil {
		return nil, err
	}
	if err := authorizationIncomingDependencies(graph, objects); err != nil {
		return nil, ErrAuthorizationCleanupConflict
	}
	state := &AuthorizationAdoptionSnapshot{Client: &ClientOwnershipSnapshot{Application: backing, document: document}, Graph: graph, Selected: objects, RealmID: authority.realmID, ApplicationUID: authority.applicationUID}
	return state, nil
}

func (c *Client) guardAdoptedAuthorizationMutation(ctx context.Context, method, path string) error {
	authority, adopted := ctx.Value(authorizationAdoptionContextKey{}).(authorizationAdoptionAuthority)
	if !adopted || method == http.MethodGet {
		return nil
	}
	state, err := c.currentAdoptedAuthorizationGraph(ctx, authority)
	if err != nil {
		return err
	}
	base := authorizationBase(authority.realm, authority.clientID)
	suffix, ok := strings.CutPrefix(path, base+"/")
	if !ok {
		return ErrAuthorizationOwnershipConflict
	}
	if method == http.MethodPost {
		return nil
	}
	parts := strings.Split(suffix, "/")
	if len(parts) < 2 {
		return ErrAuthorizationOwnershipConflict
	}
	id, err := url.PathUnescape(parts[len(parts)-1])
	if err != nil {
		return ErrAuthorizationOwnershipConflict
	}
	object, found := adoptedAuthorizationObject(authority, state, parts[0], id)
	if !found {
		return ErrAuthorizationOwnershipConflict
	}
	var document map[string]any
	if err := c.get(ctx, base+object.path+"/"+url.PathEscape(id), &document); err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	if !qualifiedAuthorizationObject(document, object, state.Client.Application) {
		return ErrAuthorizationCleanupConflict
	}
	return nil
}

func adoptedAuthorizationObject(authority authorizationAdoptionAuthority, state *AuthorizationAdoptionSnapshot, kind, id string) (authorizationAdoptionObject, bool) {
	var refs []AuthorizationManagedReference
	switch kind {
	case "scope":
		refs = state.Selected.Scopes
	case "resource":
		refs = state.Selected.Resources
	case "policy":
		refs = state.Selected.Policies
	case "permission":
		refs = state.Selected.Permissions
	default:
		return authorizationAdoptionObject{}, false
	}
	for _, ref := range refs {
		if ref.ID != id {
			continue
		}
		object := authorizationAdoptionObject{kind: kind, name: ref.Name, id: id, logical: ref.Name, path: "/" + kind}
		switch kind {
		case "policy":
			object.name = managedPolicyName(authority.name, ref.Name)
			for _, p := range state.Graph.Policies {
				if p.ID == id {
					object.path += "/" + p.Type
					return object, p.Name == object.name && !p.Incomplete
				}
			}
			return object, false
		case "permission":
			object.path += "/scope"
		}
		return object, true
	}
	return authorizationAdoptionObject{}, false
}

func (c *Client) finalizeAdoptedAuthorizationCleanup(ctx context.Context, model AuthorizationModel, id string, owned AuthorizationManagedObjects) (bool, error) {
	if _, adopted := ctx.Value(authorizationAdoptionContextKey{}).(authorizationAdoptionAuthority); !adopted {
		return false, nil
	}
	absent, err := c.authorizationOwnedAbsent(ctx, model, id, owned)
	if err != nil {
		return true, err
	}
	if !absent {
		return true, ErrAuthorizationReadBack
	}
	// Selected-object acquisition does not own the client's feature toggle.
	// Leaving it enabled cannot erase a foreign object arriving after read-back.
	return true, c.clearAuthorizationOwnership(ctx, model, id)
}
