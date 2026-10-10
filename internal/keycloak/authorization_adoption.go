package keycloak

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// AuthorizationAdoptionSnapshot binds a reviewed selection to a live client
// and graph. Raw selected representations remain private and ephemeral.
type AuthorizationAdoptionSnapshot struct {
	Client          *ClientOwnershipSnapshot
	Graph           InventoryAuthorizationGraph
	Selected        AuthorizationManagedObjects
	RealmID         string
	ApplicationUID  string
	DesiredPolicies []InventoryAuthorizationPolicy
	selected        []authorizationAdoptionObject
	documents       map[string]map[string]any
}

type authorizationAdoptionObject struct{ kind, name, id, logical, path string }

func (c *Client) ReadAuthorizationAdoption(ctx context.Context, model AuthorizationModel, applicationUID string) (*AuthorizationAdoptionSnapshot, error) {
	client, err := c.ReadClientOwnership(ctx, model.Realm, model.ApplicationRef)
	if err != nil {
		return nil, err
	}
	if client == nil || !ApplicationOwned(&client.Application, applicationUID) {
		return nil, ErrAdoptionPrecondition
	}
	if enabled, _ := client.document["authorizationServicesEnabled"].(bool); !enabled {
		return nil, ErrAdoptionPrecondition
	}
	realm, err := c.GetRealm(ctx, model.Realm)
	if err != nil {
		return nil, err
	}
	graph, err := c.InventoryAuthorization(ctx, model.Realm, client.Application.ID)
	if err != nil {
		return nil, err
	}
	if err := c.readNativeResourcePermissionDependencies(ctx, model.Realm, client.Application.ID, &graph); err != nil {
		return nil, err
	}
	s := &AuthorizationAdoptionSnapshot{Client: client, Graph: graph, RealmID: realm.ID, ApplicationUID: applicationUID, Selected: AuthorizationManagedObjects{ResourceServerID: client.Application.ID}, documents: map[string]map[string]any{}}
	if _, _, err := parseAuthorizationJournal(client.document, model.OwnerUID, client.Application.ID); err != nil {
		return nil, err
	}
	if err := c.selectAuthorizationAdoption(ctx, model, s); err != nil {
		return nil, err
	}
	if err := authorizationIncomingDependencies(s.Graph, s.Selected); err != nil {
		return nil, err
	}
	for _, object := range s.selected {
		var document map[string]any
		if err := c.get(ctx, authorizationBase(model.Realm, client.Application.ID)+object.path+"/"+url.PathEscape(object.id), &document); err != nil {
			return nil, err
		}
		if !qualifiedAuthorizationObject(document, object, client.Application) {
			return nil, ErrAdoptionPrecondition
		}
		s.documents[object.id] = document
	}
	return s, nil
}

func (c *Client) readNativeResourcePermissionDependencies(ctx context.Context, realm, clientID string, graph *InventoryAuthorizationGraph) error {
	var typed []authorizationPermissionRepresentation
	if err := readAuthorizationCollection(ctx, c, authorizationBase(realm, clientID)+"/permission/resource?fields=*", &typed); err != nil {
		return err
	}
	if len(typed) > 128 {
		return ErrAuthorizationReadLimit
	}
	byID := map[string]authorizationPermissionRepresentation{}
	for _, item := range typed {
		if item.ID == "" || byID[item.ID].ID != "" {
			return ErrAdoptionPrecondition
		}
		item.Type = "resource"
		byID[item.ID] = item
	}
	for i, item := range graph.Permissions {
		if item.Type != "resource" {
			continue
		}
		current, ok := byID[item.ID]
		if !ok || current.Name != item.Name {
			return ErrAdoptionPrecondition
		}
		for _, policy := range graph.Policies {
			if policy.ID == current.ID {
				current.Policies = slices.Clone(policy.AssociatedPolicies)
			}
		}
		graph.Permissions[i] = current
	}
	return nil
}

func (c *Client) selectAuthorizationAdoption(ctx context.Context, model AuthorizationModel, s *AuthorizationAdoptionSnapshot) error {
	selectAuthorizationLeaves(model, s)
	if err := c.selectAuthorizationPolicies(ctx, model, s); err != nil {
		return err
	}
	if err := selectAuthorizationPermissions(model, s); err != nil {
		return err
	}
	if !validAuthorizationObjects(s.Selected) {
		return ErrAdoptionPrecondition
	}
	return nil
}

func selectAuthorizationLeaves(model AuthorizationModel, s *AuthorizationAdoptionSnapshot) {
	for _, want := range model.Scopes {
		for _, got := range s.Graph.Scopes {
			if got.Name == want.Name {
				s.Selected.Scopes = append(s.Selected.Scopes, AuthorizationManagedReference{Name: want.Name, ID: got.ID})
				s.selected = append(s.selected, authorizationAdoptionObject{"scope", got.Name, got.ID, want.Name, "/scope"})
			}
		}
	}
	for _, want := range model.Resources {
		for _, got := range s.Graph.Resources {
			if got.Name == want.Name {
				s.Selected.Resources = append(s.Selected.Resources, AuthorizationManagedReference{Name: want.Name, ID: got.ID})
				s.selected = append(s.selected, authorizationAdoptionObject{"resource", got.Name, got.ID, want.Name, "/resource"})
			}
		}
	}
}

func selectAuthorizationPermissions(model AuthorizationModel, s *AuthorizationAdoptionSnapshot) error {
	for _, want := range model.Permissions {
		for _, got := range s.Graph.Permissions {
			if got.Name != want.Name {
				continue
			}
			if got.Type != "scope" {
				return ErrAdoptionPrecondition
			}
			s.Selected.Permissions = append(s.Selected.Permissions, AuthorizationManagedReference{Name: want.Name, ID: got.ID})
			s.selected = append(s.selected, authorizationAdoptionObject{"permission", got.Name, got.ID, want.Name, "/permission/scope"})
		}
	}
	return nil
}

func (c *Client) selectAuthorizationPolicies(ctx context.Context, model AuthorizationModel, s *AuthorizationAdoptionSnapshot) error {
	for _, permission := range model.Permissions {
		roles, clients, groups, err := c.resolveAuthorizationPrincipals(ctx, model.Realm, permission.Principals)
		if err != nil {
			return err
		}
		for _, want := range desiredAuthorizationPolicies(model.Name, permission.Name, roles, clients, groups) {
			payload := want.payload
			payload.Type = want.kind
			s.DesiredPolicies = append(s.DesiredPolicies, payload)
			for _, got := range s.Graph.Policies {
				if got.Name != want.payload.Name {
					continue
				}
				if got.Type != want.kind || got.Incomplete || normalizedLogic(got.Logic) != "POSITIVE" {
					return ErrAdoptionPrecondition
				}
				s.Selected.Policies = append(s.Selected.Policies, AuthorizationManagedReference{Name: want.logical, ID: got.ID})
				s.selected = append(s.selected, authorizationAdoptionObject{"policy", got.Name, got.ID, want.logical, "/policy/" + want.kind})
			}
		}
	}
	return nil
}

func authorizationIncomingDependencies(graph InventoryAuthorizationGraph, owned AuthorizationManagedObjects) error {
	selected, err := authorizationSelectedIDs(owned)
	if err != nil {
		return err
	}
	check := func(source string, targets []string) error {
		if selected[source] {
			return nil
		}
		for _, id := range targets {
			if selected[id] {
				return ErrAuthorizationOwnershipConflict
			}
		}
		return nil
	}
	return checkAuthorizationIncomingEdges(graph, check)
}

func authorizationSelectedIDs(owned AuthorizationManagedObjects) (map[string]bool, error) {
	selected := map[string]bool{}
	for _, refs := range [][]AuthorizationManagedReference{owned.Scopes, owned.Resources, owned.Policies, owned.Permissions} {
		for _, ref := range refs {
			if selected[ref.ID] {
				return nil, ErrAdoptionPrecondition
			}
			selected[ref.ID] = true
		}
	}
	return selected, nil
}

func checkAuthorizationIncomingEdges(graph InventoryAuthorizationGraph, check func(string, []string) error) error {
	for _, resource := range graph.Resources {
		ids := []string{}
		for _, scope := range resource.Scopes {
			ids = append(ids, scope.ID)
		}
		if err := check(resource.ID, ids); err != nil {
			return err
		}
	}
	for _, policy := range graph.Policies {
		if policy.Incomplete {
			return ErrAdoptionPrecondition
		}
		if err := check(policy.ID, policy.AssociatedPolicies); err != nil {
			return err
		}
	}
	for _, permission := range graph.Permissions {
		ids := append(slices.Clone(permission.Resources), permission.Scopes...)
		ids = append(ids, permission.Policies...)
		if err := check(permission.ID, ids); err != nil {
			return err
		}
	}
	return nil
}

func qualifiedAuthorizationObject(document map[string]any, object authorizationAdoptionObject, backing Application) bool {
	idKey := "id"
	allowed := map[string]bool{"id": true, "name": true, "displayName": true}
	switch object.kind {
	case "resource":
		idKey = "_id"
		for _, key := range []string{"_id", "uris", "type", "scopes", "owner", "ownerManagedAccess", "attributes", "resourceServerId"} {
			allowed[key] = true
		}
	case "policy":
		for _, key := range []string{"type", "logic", "decisionStrategy", "description", "roles", "clients", "groups", "groupsClaim", "config"} {
			allowed[key] = true
		}
	case "permission":
		for _, key := range []string{"type", "logic", "decisionStrategy", "description", "resources", "scopes", "policies", "resourceType"} {
			allowed[key] = true
		}
	}
	if document[idKey] != object.id || document["name"] != object.name {
		return false
	}
	for key, value := range document {
		if !allowed[key] {
			return false
		}
		if !qualifiedAuthorizationDefault(key, value, backing) {
			return false
		}
	}
	return true
}

func qualifiedAuthorizationDefault(key string, value any, backing Application) bool {
	switch key {
	case "description", "resourceType", "groupsClaim":
		return value == nil || value == ""
	case "attributes":
		m, ok := value.(map[string]any)
		return value == nil || ok && len(m) == 0
	case "ownerManagedAccess":
		return value == false
	case "resourceServerId":
		return value == backing.ID
	case "owner":
		return qualifiedAuthorizationResourceOwner(value, backing)
	case "config":
		m, ok := value.(map[string]any)
		return value == nil || ok && len(m) == 0
	case "logic":
		return value == "POSITIVE"
	case "decisionStrategy":
		return value == "AFFIRMATIVE" || value == "UNANIMOUS"
	}
	return true
}

func qualifiedAuthorizationResourceOwner(value any, backing Application) bool {
	m, ok := value.(map[string]any)
	if !ok {
		return value == nil
	}
	if m["id"] != backing.ID {
		return false
	}
	if len(m) == 1 {
		return true
	}
	return len(m) == 2 && (m["name"] == backing.ClientID || m["name"] == backing.Name && backing.Name != "")
}

func (s *AuthorizationAdoptionSnapshot) SameSemantics(other *AuthorizationAdoptionSnapshot) bool {
	return s != nil && other != nil && s.RealmID == other.RealmID && s.ApplicationUID == other.ApplicationUID && s.Client.SameSemantics(other.Client) && reflect.DeepEqual(canonicalAuthorizationObjects(s.Selected), canonicalAuthorizationObjects(other.Selected)) && sameAuthorizationGraph(s.Graph, other.Graph) && sameUnorderedDocuments(s.DesiredPolicies, other.DesiredPolicies) && reflect.DeepEqual(s.documents, other.documents)
}

func sameAuthorizationGraph(a, b InventoryAuthorizationGraph) bool {
	return sameUnorderedDocuments(a.Scopes, b.Scopes) && sameUnorderedDocuments(a.Resources, b.Resources) && sameUnorderedDocuments(a.Policies, b.Policies) && sameUnorderedDocuments(a.Permissions, b.Permissions)
}

// AuthorizationAdoptionReceipt reads only a validated provider journal.
func (c *Client) AuthorizationAdoptionReceipt(ctx context.Context, realm, clientID, uid string) (*adoption.Receipt, AuthorizationManagedObjects, error) {
	var document map[string]any
	if err := c.get(ctx, authorizationClientPath(realm, clientID), &document); err != nil {
		return nil, AuthorizationManagedObjects{}, err
	}
	objects, found, err := parseAuthorizationJournal(document, uid, clientID)
	if err != nil || !found {
		return nil, objects, err
	}
	if err := c.verifyAuthorizationJournalRealm(ctx, realm, document); err != nil {
		return nil, objects, err
	}
	var journal authorizationJournal
	if err := json.Unmarshal([]byte(journalValue(document)), &journal); err != nil {
		return nil, objects, ErrAdoptionPrecondition
	}
	return journal.AdoptionReceipt, objects, nil
}

// MarkAuthorizationAdoption writes a journal only. It never writes the client
// receipt, changes Authorization Services, or mutates authorization objects.
func (c *Client) MarkAuthorizationAdoption(ctx context.Context, model AuthorizationModel, expected *AuthorizationAdoptionSnapshot, receipt adoption.Receipt) error {
	if expected == nil || receipt.TargetKind != "HankoResourceServer" || receipt.TargetUID != model.OwnerUID {
		return ErrAdoptionPrecondition
	}
	if _, err := receipt.Canonical(); err != nil {
		return ErrAdoptionPrecondition
	}
	current, err := c.ReadAuthorizationAdoption(ctx, model, expected.ApplicationUID)
	if err != nil {
		return err
	}
	if !expected.SameSemantics(current) {
		return ErrAdoptionPrecondition
	}
	journal := authorizationJournal{Version: 2, OwnerUID: model.OwnerUID, Objects: canonicalAuthorizationObjects(current.Selected), RealmID: current.RealmID, ApplicationUID: current.ApplicationUID, AdoptionReceipt: &receipt}
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded) > maxAuthorizationJournalBytes {
		return ErrAdoptionPrecondition
	}
	if raw := journalValue(current.Client.document); raw != "" {
		if raw == string(encoded) {
			return nil
		}
		return ErrAuthorizationOwnershipConflict
	}
	attrs, _ := current.Client.document["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[authorizationOwnerAttribute] = string(encoded)
	current.Client.document["attributes"] = attrs
	delete(current.Client.document, "serviceAccountsEnabled")
	return c.putJSON(ctx, applicationPath(model.Realm, current.Client.Application.ID), current.Client.document)
}
