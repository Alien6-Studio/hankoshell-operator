package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

var ErrAdoptionPrecondition = errors.New("provider ownership acquisition precondition failed")

// These snapshots are ephemeral. Native fields are preserved for owner-only
// PUT/read-back, never hashed, logged, exported as status or retained as receipts.
type ClientOwnershipSnapshot struct {
	Application Application
	document    map[string]any
	mappers     []map[string]any
}
type RoleOwnershipSnapshot struct {
	Role     RealmRole
	document map[string]any
}

func decodeSnapshot(document map[string]any, target any) error {
	delete(document, "secret")
	delete(document, "access") // caller-specific administrative permissions
	b, err := json.Marshal(document)
	if err != nil {
		return ErrAdoptionPrecondition
	}
	if json.Unmarshal(b, target) != nil {
		return ErrAdoptionPrecondition
	}
	return nil
}

func (c *Client) ReadClientOwnership(ctx context.Context, realm, clientID string) (*ClientOwnershipSnapshot, error) {
	id, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, nil // absent provider client; never an acquisition candidate
	}
	var document map[string]any
	if err := c.get(ctx, applicationPath(realm, id), &document); err != nil {
		return nil, err
	}
	s := &ClientOwnershipSnapshot{document: document}
	if err := decodeSnapshot(document, &s.Application); err != nil {
		return nil, err
	}
	if s.Application.ID != id || s.Application.ClientID != clientID {
		return nil, ErrAdoptionPrecondition
	}
	if err := c.get(ctx, applicationPath(realm, id)+"/protocol-mappers/models", &s.mappers); err != nil {
		return nil, err
	}
	if len(s.mappers) > 512 {
		return nil, ErrAdoptionPrecondition
	}
	return s, nil
}

func (c *Client) ReadRoleOwnership(ctx context.Context, realm, name string) (*RoleOwnershipSnapshot, error) {
	var document map[string]any
	if err := c.get(ctx, adminRealmsPath+url.PathEscape(realm)+rolesSegment+url.PathEscape(name), &document); err != nil {
		return nil, err
	}
	s := &RoleOwnershipSnapshot{document: document}
	if err := decodeSnapshot(document, &s.Role); err != nil {
		return nil, err
	}
	if s.Role.ID == "" || s.Role.Name != name || s.Role.ClientRole {
		return nil, ErrAdoptionPrecondition
	}
	return s, nil
}

func withoutAcquisition(document map[string]any) map[string]any {
	b, _ := json.Marshal(document)
	var result map[string]any
	_ = json.Unmarshal(b, &result)
	if attrs, ok := result["attributes"].(map[string]any); ok {
		for key := range attrs {
			if adoption.ReservedAttribute(key) && key != "hanko.sh/resource-server-ownership" {
				delete(attrs, key)
			}
		}
		if len(attrs) == 0 {
			delete(result, "attributes")
		}
	}
	return result
}
func (s *ClientOwnershipSnapshot) SameSemantics(other *ClientOwnershipSnapshot) bool {
	return s != nil && other != nil && reflect.DeepEqual(withoutAcquisition(s.document), withoutAcquisition(other.document)) && sameMapperDocuments(s.mappers, other.mappers)
}

// QualifiedLeaf rejects native root settings outside #47's public projection.
// Known provider defaults are fixed preconditions, not opaque hashed payloads.
// Nonempty scope collections and custom authentication flows need #49 coverage.
func (s *ClientOwnershipSnapshot) QualifiedLeaf() bool {
	if s == nil {
		return false
	}
	projected := map[string]bool{"id": true, "clientId": true, "protocol": true, "enabled": true, "publicClient": true, "standardFlowEnabled": true, "serviceAccountsEnabled": true, "directAccessGrantsEnabled": true, "implicitFlowEnabled": true, "fullScopeAllowed": true, "redirectUris": true, "webOrigins": true, "attributes": true}
	defaults := map[string]any{"bearerOnly": false, "authorizationServicesEnabled": false, "rootUrl": "", "baseUrl": "", "adminUrl": "", "description": "", "surrogateAuthRequired": false, "alwaysDisplayInConsole": false, "consentRequired": false, "notBefore": float64(0), "nodeReRegistrationTimeout": float64(-1), "clientAuthenticatorType": "client-secret", "frontchannelLogout": true}
	for key, value := range s.document {
		if projected[key] {
			continue
		}
		if key == "name" && (value == "" || value == s.Application.ClientID) {
			continue
		}
		if want, ok := defaults[key]; ok && reflect.DeepEqual(value, want) {
			continue
		}
		if qualifiedEmptyNativeCollection(key, value) {
			continue
		}
		return false
	}
	return true
}
func sameMapperDocuments(a, b []map[string]any) bool {
	// Map by exact mapper UUID; response ordering has no semantic meaning.
	toMap := func(items []map[string]any) map[string]map[string]any {
		r := map[string]map[string]any{}
		for _, item := range items {
			id, _ := item["id"].(string)
			if id == "" || r[id] != nil {
				return nil
			}
			r[id] = item
		}
		return r
	}
	aa, bb := toMap(a), toMap(b)
	return aa != nil && bb != nil && reflect.DeepEqual(aa, bb)
}
func (s *RoleOwnershipSnapshot) SameSemantics(other *RoleOwnershipSnapshot) bool {
	return s != nil && other != nil && reflect.DeepEqual(withoutAcquisition(s.document), withoutAcquisition(other.document))
}

func clientUnmarked(a Application) bool {
	for key := range a.Attributes {
		if adoption.ReservedAttribute(key) {
			return false
		}
	}
	return true
}
func roleUnmarked(a RealmRole) bool {
	for key := range a.Attributes {
		if adoption.ReservedAttribute(key) {
			return false
		}
	}
	return true
}

func (c *Client) MarkApplicationAdoption(ctx context.Context, realm string, expected *ClientOwnershipSnapshot, uid, receipt string) error {
	return c.markClientAdoption(ctx, realm, expected, "HankoApplication", uid, receipt)
}
func (c *Client) MarkServiceAccountAdoption(ctx context.Context, realm string, expected *ClientOwnershipSnapshot, uid, receipt string) error {
	return c.markClientAdoption(ctx, realm, expected, "HankoServiceAccount", uid, receipt)
}
func (c *Client) markClientAdoption(ctx context.Context, realm string, expected *ClientOwnershipSnapshot, kind, uid, receipt string) error {
	proof, err := adoption.ParseReceipt(receipt)
	if err != nil || proof.TargetKind != kind || proof.TargetUID != uid || expected == nil {
		return ErrAdoptionPrecondition
	}
	current, err := c.ReadClientOwnership(ctx, realm, expected.Application.ClientID)
	if err != nil {
		return err
	}
	if current == nil || !clientUnmarked(current.Application) || !expected.SameSemantics(current) {
		return ErrAdoptionPrecondition
	}
	attrs, _ := current.document["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	if kind == "HankoApplication" {
		attrs[adoption.ApplicationOwnerKey] = uid
	} else {
		attrs[adoption.ClientOwnerKindKey] = kind
		attrs[adoption.ClientOwnerUIDKey] = uid
	}
	attrs[adoption.ReceiptKey] = receipt
	current.document["attributes"] = attrs
	// Keycloak reattaches its service_account scope when this flag is resent
	// as true, even on an already-enabled client. Omission preserves the flag
	// and avoids that business mutation in the ownership-only PUT.
	delete(current.document, "serviceAccountsEnabled")
	return c.putJSON(ctx, applicationPath(realm, current.Application.ID), current.document)
}
func (c *Client) MarkRoleAdoption(ctx context.Context, realm string, expected *RoleOwnershipSnapshot, uid, receipt string) error {
	proof, err := adoption.ParseReceipt(receipt)
	if err != nil || proof.TargetKind != "HankoRole" || proof.TargetUID != uid || expected == nil {
		return ErrAdoptionPrecondition
	}
	current, err := c.ReadRoleOwnership(ctx, realm, expected.Role.Name)
	if err != nil {
		return err
	}
	if current == nil || !roleUnmarked(current.Role) || !expected.SameSemantics(current) {
		return ErrAdoptionPrecondition
	}
	attrs, _ := current.document["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[adoption.RoleOwnerKey] = []string{uid}
	attrs[adoption.ReceiptKey] = []string{receipt}
	current.document["attributes"] = attrs
	return c.putJSON(ctx, adminRealmsPath+url.PathEscape(realm)+rolesSegment+url.PathEscape(current.Role.Name), current.document)
}

func ServiceAccountOwned(a *Application, uid string) bool {
	if a == nil || uid == "" {
		return false
	}
	for key := range a.Attributes {
		if adoption.ReservedAttribute(key) && key != adoption.ClientOwnerKindKey && key != adoption.ClientOwnerUIDKey && key != adoption.ReceiptKey {
			return false
		}
	}
	return a.Attributes[adoption.ClientOwnerKindKey] == "HankoServiceAccount" && a.Attributes[adoption.ClientOwnerUIDKey] == uid
}

// ApplicationOwned refuses mixed or cross-kind client envelopes.
func ApplicationOwned(a *Application, uid string) bool {
	if a == nil || uid == "" || a.Attributes[adoption.ApplicationOwnerKey] != uid {
		return false
	}
	for key := range a.Attributes {
		if adoption.ReservedAttribute(key) && key != adoption.ApplicationOwnerKey && key != adoption.ReceiptKey && key != authorizationOwnerAttribute {
			return false
		}
	}
	return true
}

func qualifiedEmptyNativeCollection(key string, value any) bool {
	switch key {
	case "authenticationFlowBindingOverrides", "registeredNodes":
		entries, ok := value.(map[string]any)
		return ok && len(entries) == 0
	case "defaultClientScopes", "optionalClientScopes":
		entries, ok := value.([]any)
		return ok && len(entries) == 0
	}
	return false
}

func (s *RoleOwnershipSnapshot) QualifiedLeaf() bool {
	if s == nil {
		return false
	}
	allowed := map[string]bool{"id": true, "name": true, "description": true, "containerId": true, "clientRole": true, "composite": true, "attributes": true}
	for key := range s.document {
		if !allowed[key] {
			return false
		}
	}
	return true
}
