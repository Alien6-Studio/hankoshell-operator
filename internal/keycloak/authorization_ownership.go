package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

const authorizationOwnerAttribute = "hanko.sh/resource-server-ownership"
const maxAuthorizationJournalBytes = 512 * 1024

// This operational journal recovers ownership after a Kubernetes status write
// fails. It carries no executable plan or application proof. Keycloak admins
// are trusted for ownership markers, just as for the realm-role owner marker.
type authorizationJournal struct {
	Version         int                         `json:"version"`
	OwnerUID        string                      `json:"ownerUID"`
	Objects         AuthorizationManagedObjects `json:"objects"`
	RealmID         string                      `json:"realmID,omitempty"`
	ApplicationUID  string                      `json:"applicationUID,omitempty"`
	AdoptionReceipt *adoption.Receipt           `json:"adoptionReceipt,omitempty"`
}

func validAuthorizationJournal(j authorizationJournal, owner, clientID string) bool {
	if j.OwnerUID != owner || j.Objects.ResourceServerID != clientID || !validAuthorizationObjects(j.Objects) {
		return false
	}
	if j.Version == 1 {
		return j.AdoptionReceipt == nil && j.RealmID == "" && j.ApplicationUID == ""
	}
	return validAuthorizationAdoptionJournal(j, owner)
}

func validAuthorizationAdoptionJournal(j authorizationJournal, owner string) bool {
	if j.Version != 2 || j.AdoptionReceipt == nil || j.RealmID == "" || len(j.RealmID) > 128 || j.ApplicationUID == "" || len(j.ApplicationUID) > 128 {
		return false
	}
	if _, err := authorizationSelectedIDs(j.Objects); err != nil {
		return false
	}
	proof := j.AdoptionReceipt
	_, err := proof.Canonical()
	return err == nil && proof.TargetKind == "HankoResourceServer" && proof.TargetUID == owner
}

func validAuthorizationObjects(o AuthorizationManagedObjects) bool {
	if len(o.ResourceServerID) > 128 {
		return false
	}
	for _, group := range []struct {
		refs  []AuthorizationManagedReference
		limit int
	}{{o.Scopes, 64}, {o.Resources, 64}, {o.Policies, 256}, {o.Permissions, 128}} {
		if len(group.refs) > group.limit {
			return false
		}
		names, ids := map[string]bool{}, map[string]bool{}
		for _, ref := range group.refs {
			if ref.Name == "" || ref.ID == "" || len(ref.Name) > 512 || len(ref.ID) > 128 || names[ref.Name] || ids[ref.ID] {
				return false
			}
			names[ref.Name], ids[ref.ID] = true, true
		}
	}
	return true
}
func journalValue(representation map[string]any) string {
	attrs, _ := representation["attributes"].(map[string]any)
	value, _ := attrs[authorizationOwnerAttribute].(string)
	return value
}
func parseAuthorizationJournal(representation map[string]any, owner, clientID string) (AuthorizationManagedObjects, bool, error) {
	if raw, exists := representation["attributes"]; exists && raw != nil {
		attrs, ok := raw.(map[string]any)
		if !ok {
			return AuthorizationManagedObjects{}, false, ErrAuthorizationOwnershipConflict
		}
		if value, exists := attrs[authorizationOwnerAttribute]; exists && value != nil {
			if _, ok := value.(string); !ok {
				return AuthorizationManagedObjects{}, false, ErrAuthorizationOwnershipConflict
			}
		}
	}
	value := journalValue(representation)
	if value == "" {
		return AuthorizationManagedObjects{}, false, nil
	}
	var j authorizationJournal
	if len(value) > maxAuthorizationJournalBytes || json.Unmarshal([]byte(value), &j) != nil || !validAuthorizationJournal(j, owner, clientID) {
		return AuthorizationManagedObjects{}, false, ErrAuthorizationOwnershipConflict
	}
	if !closedAuthorizationAdoptionJournal(value, j) {
		return AuthorizationManagedObjects{}, false, ErrAuthorizationOwnershipConflict
	}
	if j.Version == 2 && !authorizationJournalApplicationOwned(representation, j) {
		return AuthorizationManagedObjects{}, false, ErrAuthorizationOwnershipConflict
	}
	return j.Objects, true, nil
}

func closedAuthorizationAdoptionJournal(value string, journal authorizationJournal) bool {
	if journal.Version != 2 {
		return true
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&journal) == nil && decoder.Decode(new(any)) == io.EOF
}

func authorizationJournalApplicationOwned(document map[string]any, j authorizationJournal) bool {
	var a Application
	encoded, err := json.Marshal(document)
	return err == nil && json.Unmarshal(encoded, &a) == nil && a.ID == j.Objects.ResourceServerID && ApplicationOwned(&a, j.ApplicationUID)
}

func (c *Client) verifyAuthorizationJournalRealm(ctx context.Context, realm string, document map[string]any) error {
	var j authorizationJournal
	if raw := journalValue(document); raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(journalValue(document)), &j); err != nil {
		return ErrAuthorizationOwnershipConflict
	}
	if j.Version != 2 {
		return nil
	}
	current, err := c.GetRealm(ctx, realm)
	if err != nil {
		return err
	}
	if current.ID != j.RealmID {
		return ErrAuthorizationOwnershipConflict
	}
	return nil
}
func (c *Client) readAuthorizationOwnership(ctx context.Context, model AuthorizationModel, clientID string) (AuthorizationManagedObjects, bool, error) {
	if model.OwnerUID == "" {
		return AuthorizationManagedObjects{}, false, nil
	}
	var representation map[string]any
	if err := c.get(ctx, authorizationClientPath(model.Realm, clientID), &representation); err != nil {
		return AuthorizationManagedObjects{}, false, err
	}
	objects, found, err := parseAuthorizationJournal(representation, model.OwnerUID, clientID)
	if err != nil || !found {
		return objects, found, err
	}
	return objects, true, c.verifyAuthorizationJournalRealm(ctx, model.Realm, representation)
}
func authorizationClientPath(realm, clientID string) string {
	return adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(clientID)
}
func canonicalAuthorizationObjects(o AuthorizationManagedObjects) AuthorizationManagedObjects {
	for _, refs := range []*[]AuthorizationManagedReference{&o.Scopes, &o.Resources, &o.Policies, &o.Permissions} {
		*refs = slices.Clone(*refs)
		slices.SortFunc(*refs, func(a, b AuthorizationManagedReference) int { return strings.Compare(a.Name, b.Name) })
	}
	return o
}
func (c *Client) saveAuthorizationOwnership(ctx context.Context, model AuthorizationModel, objects AuthorizationManagedObjects) error {
	if model.OwnerUID == "" {
		return nil
	} // Legacy native-client callers; domain adapter requires a UID.
	if len(model.OwnerUID) > 128 || !validAuthorizationObjects(objects) {
		return errors.New("authorization ownership exceeds evidence budget")
	}
	path := authorizationClientPath(model.Realm, objects.ResourceServerID)
	var representation map[string]any
	if err := c.get(ctx, path, &representation); err != nil {
		return err
	}
	if _, _, err := parseAuthorizationJournal(representation, model.OwnerUID, objects.ResourceServerID); err != nil {
		return err
	}
	journal := authorizationJournal{Version: 1, OwnerUID: model.OwnerUID}
	if raw := journalValue(representation); raw != "" && json.Unmarshal([]byte(raw), &journal) != nil {
		return ErrAuthorizationOwnershipConflict
	}
	if err := c.verifyAuthorizationJournalRealm(ctx, model.Realm, representation); err != nil {
		return err
	}
	journal.Objects = canonicalAuthorizationObjects(objects)
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded) > maxAuthorizationJournalBytes {
		return errors.New("authorization ownership exceeds evidence budget")
	}
	if journalValue(representation) == string(encoded) {
		return nil
	}
	attrs, _ := representation["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[authorizationOwnerAttribute] = string(encoded)
	representation["attributes"] = attrs
	delete(representation, "secret")
	delete(representation, "access")
	delete(representation, "serviceAccountsEnabled")
	return c.putJSON(ctx, path, representation)
}

type authorizationCheckpoint func(string, AuthorizationManagedReference) error

func (c *Client) authorizationProgress(ctx context.Context, model AuthorizationModel, objects *AuthorizationManagedObjects) authorizationCheckpoint {
	return func(kind string, ref AuthorizationManagedReference) error {
		var refs *[]AuthorizationManagedReference
		switch kind {
		case "scope":
			refs = &objects.Scopes
		case "resource":
			refs = &objects.Resources
		case "policy":
			refs = &objects.Policies
		case "permission":
			refs = &objects.Permissions
		default:
			return errors.New("invalid ownership category")
		}
		replaced := false
		for i := range *refs {
			if (*refs)[i].Name == ref.Name {
				(*refs)[i] = ref
				replaced = true
				break
			}
		}
		if !replaced {
			*refs = append(*refs, ref)
		}
		return c.saveAuthorizationOwnership(ctx, model, *objects)
	}
}

func (c *Client) clearAuthorizationOwnership(ctx context.Context, model AuthorizationModel, clientID string) error {
	if model.OwnerUID == "" {
		return nil
	}
	var representation map[string]any
	path := authorizationClientPath(model.Realm, clientID)
	if err := c.get(ctx, path, &representation); err != nil {
		return err
	}
	_, found, err := parseAuthorizationJournal(representation, model.OwnerUID, clientID)
	if err != nil || !found {
		return err
	}
	if err := c.verifyAuthorizationJournalRealm(ctx, model.Realm, representation); err != nil {
		return err
	}
	attrs, _ := representation["attributes"].(map[string]any)
	attrs[authorizationOwnerAttribute] = nil
	delete(representation, "secret")
	delete(representation, "access")
	delete(representation, "serviceAccountsEnabled")
	return c.putJSON(ctx, path, representation)
}

func authorizationOwnershipBudget(model AuthorizationModel, owned AuthorizationManagedObjects) error {
	for _, scope := range model.Scopes {
		owned.Scopes = budgetReference(owned.Scopes, scope.Name)
	}
	for _, resource := range model.Resources {
		owned.Resources = budgetReference(owned.Resources, resource.Name)
	}
	for _, permission := range model.Permissions {
		owned.Permissions = budgetReference(owned.Permissions, permission.Name)
		roles, clients, organizations := false, false, false
		for _, principal := range permission.Principals {
			switch principal.Kind {
			case "realm_role":
				roles = true
			case "organization":
				organizations = true
			default:
				clients = true
			}
		}
		if roles {
			owned.Policies = budgetReference(owned.Policies, permission.Name+"#realm_roles")
		}
		if organizations {
			owned.Policies = budgetReference(owned.Policies, permission.Name+"#organizations")
		}
		if clients {
			owned.Policies = budgetReference(owned.Policies, permission.Name+"#clients")
		}
	}
	if len(owned.Scopes) > 64 || len(owned.Resources) > 64 || len(owned.Policies) > 256 || len(owned.Permissions) > 128 {
		return errors.New("authorization ownership exceeds evidence budget; prune old objects before adding more")
	}
	return nil
}
func budgetReference(refs []AuthorizationManagedReference, name string) []AuthorizationManagedReference {
	if _, exists := refsByName(refs)[name]; !exists {
		return append(slices.Clone(refs), AuthorizationManagedReference{Name: name})
	}
	return refs
}

func (c *Client) authorizationOwnedAbsent(ctx context.Context, model AuthorizationModel, clientID string, owned AuthorizationManagedObjects) (bool, error) {
	base := authorizationBase(model.Realm, clientID)
	for _, collection := range []struct {
		path string
		refs []AuthorizationManagedReference
	}{{authorizationScopePath, owned.Scopes}, {authorizationResourcePath, owned.Resources}, {authorizationPolicyPath, owned.Policies}, {authorizationPermissionPath, owned.Permissions}} {
		if len(collection.refs) == 0 {
			continue
		}
		var objects []struct {
			ID         string `json:"id"`
			ResourceID string `json:"_id"`
		}
		if err := readAuthorizationCollection(ctx, c, base+collection.path, &objects); err != nil {
			if IsNotFound(err) {
				return c.authorizationDisabledOrAbsent(ctx, model.Realm, clientID)
			}
			return false, err
		}
		ids := keepAuthorizationIDs(collection.refs)
		for _, object := range objects {
			if ids[object.ID] || ids[object.ResourceID] {
				return false, nil
			}
		}
	}
	return true, nil
}

// Keycloak removes the graph and omits the disabled boolean from the client
// representation. A missing collection alone is insufficient: confirm that
// the backing client is absent or explicitly/default disabled, without writes.
func (c *Client) authorizationDisabledOrAbsent(ctx context.Context, realm, clientID string) (bool, error) {
	var representation map[string]any
	if err := c.get(ctx, authorizationClientPath(realm, clientID), &representation); err != nil {
		if IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	enabled, present := representation["authorizationServicesEnabled"]
	return !present || enabled == false, nil
}
