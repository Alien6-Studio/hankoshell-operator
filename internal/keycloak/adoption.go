package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"

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
	normalizeMapperSnapshotDefaults(result)
	// These are native sets. Keycloak may reorder them on an owner-only PUT.
	// Sort copies without deduplicating: additions, removals and duplicates
	// still change the snapshot and must fail preservation read-back.
	for _, key := range []string{"defaultClientScopes", "optionalClientScopes"} {
		if values, ok := result[key].([]any); ok && qualifiedClientScopeCollection(key, values) {
			slices.SortFunc(values, func(a, b any) int {
				aa, _ := a.(string) // Already checked by the closed scope schema.
				bb, _ := b.(string)
				return strings.Compare(aa, bb)
			})
		}
	}
	if values, ok := result["protocolMappers"].([]any); ok {
		slices.SortStableFunc(values, func(a, b any) int {
			aa, aok := a.(map[string]any)
			bb, bok := b.(map[string]any)
			if !aok || !bok {
				return 0
			}
			ai, _ := aa["id"].(string)
			bi, _ := bb["id"].(string)
			return strings.Compare(ai, bi)
		})
	}
	return result
}
func (s *ClientOwnershipSnapshot) SameSemantics(other *ClientOwnershipSnapshot) bool {
	return s != nil && other != nil && reflect.DeepEqual(withoutAcquisition(s.document), withoutAcquisition(other.document)) && sameMapperDocuments(s.mappers, other.mappers)
}

// QualifiedLeaf rejects native root settings outside #47's public projection.
// Known provider defaults are fixed preconditions, not opaque hashed payloads.
// Scope references use the bounded closed schema; their native definitions are
// never acquired. Custom authentication flows remain unqualified.
func (s *ClientOwnershipSnapshot) QualifiedLeaf() bool {
	if s == nil {
		return false
	}
	if s.Application.ClientAuthenticatorType == "federated-jwt" && (!federatedWorkloadEnvelope(&s.Application) || !QualifiedClientAttribute("jwt.credential.issuer", s.Application.Attributes["jwt.credential.issuer"]) || !QualifiedClientAttribute("jwt.credential.sub", s.Application.Attributes["jwt.credential.sub"])) {
		return false
	}
	for key, value := range s.document {
		if !s.qualifiedLeafField(key, value) {
			return false
		}
	}
	return true
}
func (s *ClientOwnershipSnapshot) qualifiedLeafField(key string, value any) bool {
	projected := map[string]bool{"id": true, "clientId": true, "protocol": true, "enabled": true, "publicClient": true, "standardFlowEnabled": true, "serviceAccountsEnabled": true, "directAccessGrantsEnabled": true, "implicitFlowEnabled": true, "fullScopeAllowed": true, "redirectUris": true, "webOrigins": true, "attributes": true, "authorizationServicesEnabled": true, "clientAuthenticatorType": true}

	if !qualifiedAuthorizationFlag(key, value) {
		return false
	}
	if key == "clientAuthenticatorType" && value != "client-secret" && value != "federated-jwt" {
		return false
	}
	if projected[key] {
		return true
	}
	return s.qualifiedLeafDefault(key, value)
}
func (s *ClientOwnershipSnapshot) qualifiedLeafDefault(key string, value any) bool {
	defaults := map[string]any{"bearerOnly": false, "authorizationServicesEnabled": false, "rootUrl": "", "baseUrl": "", "adminUrl": "", "description": "", "surrogateAuthRequired": false, "alwaysDisplayInConsole": false, "consentRequired": false, "notBefore": float64(0), "nodeReRegistrationTimeout": float64(-1), "frontchannelLogout": true}
	if key == "name" && (value == "" || value == s.Application.ClientID) {
		return true
	}
	if key == "frontchannelLogout" && s.Application.Protocol == "openid-connect" && value == false {
		return true
	}
	if want, ok := defaults[key]; ok && reflect.DeepEqual(value, want) {
		return true
	}
	if key == "protocolMappers" && qualifiedMapperDocuments(value, s.mappers, &s.Application) {
		return true
	}
	if qualifiedEmptyNativeCollection(key, value) || (s.Application.Protocol == "openid-connect" && qualifiedClientScopeCollection(key, value)) {
		return true
	}
	return false
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
		if key == BoundedDelegationActorAttribute && boundedClientEnvelope(a, uid, adoption.ClientOwnerUIDKey) {
			continue
		}
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
		if (key == BoundedDelegationAttribute || key == BoundedDelegationActorAttribute) && boundedClientEnvelope(a, uid, adoption.ApplicationOwnerKey) {
			continue
		}
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

func qualifiedMapperDocuments(value any, expected []map[string]any, app *Application) bool {
	encoded, err := json.Marshal(value)
	var documents []map[string]any
	if err != nil || json.Unmarshal(encoded, &documents) != nil || !sameQualifiedMapperRoots(documents, expected) {
		return false
	}
	for _, document := range documents {
		if !qualifiedMapperRootKeys(document) {
			return false
		}
		if document["consentRequired"] != nil && document["consentRequired"] != false {
			return false
		}
		var mapper ProtocolMapper
		data, _ := json.Marshal(document)
		if json.Unmarshal(data, &mapper) != nil || !qualifiedLiveClientMapper(mapper, app) {
			return false
		}
	}
	return true
}

func sameQualifiedMapperRoots(a, b []map[string]any) bool {
	convert := func(documents []map[string]any) map[string]ProtocolMapper {
		result := map[string]ProtocolMapper{}
		for _, document := range documents {
			data, err := json.Marshal(document)
			var mapper ProtocolMapper
			if err != nil || json.Unmarshal(data, &mapper) != nil || mapper.ID == "" || result[mapper.ID].ID != "" {
				return nil
			}
			result[mapper.ID] = CanonicalProtocolMapper(mapper)
		}
		return result
	}
	aa, bb := convert(a), convert(b)

	return aa != nil && bb != nil && reflect.DeepEqual(aa, bb)
}

func qualifiedMapperRootKeys(document map[string]any) bool {
	allowed := map[string]bool{"id": true, "name": true, "protocol": true, "protocolMapper": true, "config": true, "consentRequired": true}
	for key := range document {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func normalizeMapperSnapshotDefaults(result map[string]any) {
	if mappers, ok := result["protocolMappers"].([]any); ok {
		for _, value := range mappers {
			document, ok := value.(map[string]any)
			if !ok {
				continue
			}
			config, _ := document["config"].(map[string]any)
			implementation, _ := document["protocolMapper"].(string)
			if implementation != "oidc-usermodel-attribute-mapper" && implementation != "oidc-usermodel-realm-role-mapper" {
				continue
			}
			if config["introspection.token.claim"] == nil {
				if access := config["access.token.claim"]; access == "true" || access == "false" {
					config["introspection.token.claim"] = access
				}
			}
		}
	}
}

func (s *ClientOwnershipSnapshot) AuthorizationEnabled() bool {
	return s != nil && s.document["authorizationServicesEnabled"] == true
}

func qualifiedAuthorizationFlag(key string, value any) bool {
	if key != "authorizationServicesEnabled" {
		return true
	}
	_, valid := value.(bool)
	return valid
}

var clientScopeReference = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func qualifiedClientScopeCollection(key string, value any) bool {
	if key != "defaultClientScopes" && key != "optionalClientScopes" {
		return false
	}
	values, ok := value.([]any)
	if !ok || len(values) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		name, ok := v.(string)
		if !ok || !clientScopeReference.MatchString(name) || strings.HasPrefix(name, "eyJ") || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
