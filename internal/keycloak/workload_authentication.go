package keycloak

import (
	"context"
	"maps"
	"net/url"
	"reflect"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
)

// AuthenticationStateHash hashes only closed, qualified noncredential fields.
// The underlying native document is ephemeral and never exported to status.
func (s *ClientOwnershipSnapshot) AuthenticationStateHash() (string, error) {
	if s == nil || !m2mAuthenticationEnvelope(&s.Application) || !s.PreservationQualified() {
		return "", ErrApplicationPrecondition
	}
	d := withoutAcquisition(s.document)
	attrs, _ := d["attributes"].(map[string]any)
	delete(attrs, "client.secret.creation.time")
	delete(attrs, "saml.artifact.binding.identifier")
	// Ownership is a separately required public identity, not omitted authority.
	return workloadauth.Hash("native-state", struct {
		Document            map[string]any
		OwnerKind, OwnerUID string
	}{d, s.Application.Attributes[adoption.ClientOwnerKindKey], s.Application.Attributes[adoption.ClientOwnerUIDKey]}), nil
}

func (s *ClientOwnershipSnapshot) AuthenticationTargetHash(method, alias, subject string, enable bool) (string, error) {
	if s == nil || !s.PreservationQualified() {
		return "", ErrApplicationPrecondition
	}
	d := maps.Clone(s.document)
	a := s.Application
	legacyOrigin := legacyM2MOrigin(&a)
	a.Attributes = maps.Clone(a.Attributes)
	d["clientAuthenticatorType"], a.ClientAuthenticatorType = method, method
	if enable {
		d["enabled"], a.Enabled = true, true
	}
	if method == "federated-jwt" {
		a.Attributes["jwt.credential.issuer"], a.Attributes["jwt.credential.sub"] = alias, subject
		if legacyOrigin {
			a.WebOrigins = []string{}
			d["webOrigins"] = []string{}
		}
	} else {
		delete(a.Attributes, "jwt.credential.issuer")
		delete(a.Attributes, "jwt.credential.sub")
	}
	attrs := map[string]any{}
	for k, v := range a.Attributes {
		attrs[k] = v
	}
	d["attributes"] = attrs
	return (&ClientOwnershipSnapshot{Application: a, document: d, mappers: s.mappers}).AuthenticationStateHash()
}

// CreateFederatedServiceAccount never retrieves a native client credential.
// A reserved UUID and durable Attempted checkpoint precede this boundary.
func (c *Client) CreateFederatedServiceAccount(ctx context.Context, realm, clientID, uuid, uid, alias, subject string, attributes map[string]string, verify func(context.Context) error) error {
	if !validFederatedCreate(uuid, uid, alias, subject, attributes) || verify == nil || verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	current, err := c.GetApplication(ctx, realm, clientID)
	if err != nil || current != nil {
		return ErrApplicationPrecondition
	}
	attrs := maps.Clone(attributes)
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs[adoption.ClientOwnerKindKey], attrs[adoption.ClientOwnerUIDKey] = "HankoServiceAccount", uid
	attrs["jwt.credential.issuer"], attrs["jwt.credential.sub"] = alias, subject
	payload := Application{ID: uuid, ClientID: clientID, Name: clientID, Protocol: "openid-connect", Enabled: true, ServiceAccountsEnabled: true, ClientAuthenticatorType: "federated-jwt", Attributes: attrs, RedirectURIs: []string{}, WebOrigins: []string{}}
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	_, _ = c.postJSONExpect(ctx, adminRealmsPath+url.PathEscape(realm)+"/clients", payload, 201)
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	return c.verifyCreatedFederatedServiceAccount(ctx, realm, clientID, uuid, uid, alias, subject, attrs)
}

func validFederatedCreate(uuid, uid, alias, subject string, attributes map[string]string) bool {
	if uuid == "" || uid == "" || !qualifiedFederatedAttribute("jwt.credential.issuer", alias) || !qualifiedFederatedAttribute("jwt.credential.sub", subject) {
		return false
	}
	for key := range attributes {
		if adoption.ReservedAttribute(key) || strings.HasPrefix(key, "jwt.credential.") || strings.HasPrefix(key, "hanko.sh/workload-") {
			return false
		}
	}
	return true
}
func (c *Client) verifyCreatedFederatedServiceAccount(ctx context.Context, realm, clientID, uuid, uid, alias, subject string, attrs map[string]string) error {
	after, err := c.GetApplication(ctx, realm, clientID)
	if err != nil || after == nil || after.ID != uuid || !after.Enabled || !FederatedWorkloadOwned(after, uid, alias, subject) {
		return ErrApplicationPrecondition
	}
	for key, value := range attrs {
		if after.Attributes[key] != value {
			return ErrApplicationPrecondition
		}
	}
	return nil
}

// ApplyServiceAccountAuthenticator issues a partial update after exact before
// state checks. All scopes, grants, mapper documents and unrelated attributes
// remain untouched. Resending serviceAccountsEnabled would add a native scope.
func (c *Client) ApplyServiceAccountAuthenticator(ctx context.Context, realm, clientID, uid, alias, subject, method string, expected *ClientOwnershipSnapshot, beforeHash, afterHash string, enable bool, verify func(context.Context) error) error {
	if expected == nil || verify == nil || verify(ctx) != nil || (method != "federated-jwt" && method != "client-secret") {
		return ErrApplicationPrecondition
	}
	current, err := c.readOwnedAuthenticationMutation(ctx, realm, clientID, uid, expected.Application.ID)
	if err != nil {
		return err
	}
	h, err := current.AuthenticationStateHash()
	if err != nil {
		return err
	}
	if h != beforeHash && h != afterHash {
		return ErrApplicationPrecondition
	}
	if h == beforeHash && h != afterHash {
		if err := c.putOwnedServiceAccountAuthenticator(ctx, realm, clientID, alias, subject, method, afterHash, current, enable, verify); err != nil {
			return err
		}
	}
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	return c.confirmServiceAccountAuthenticator(ctx, realm, clientID, uid, current.Application.ID, afterHash)
}
func (c *Client) confirmServiceAccountAuthenticator(ctx context.Context, realm, clientID, uid, id, afterHash string) error {
	after, err := c.ReadClientOwnership(ctx, realm, clientID)
	if err != nil || after == nil || !ServiceAccountOwned(&after.Application, uid) || after.Application.ID != id {
		return ErrApplicationPrecondition
	}
	h, err := after.AuthenticationStateHash()
	if err != nil || h != afterHash {
		return ErrApplicationPrecondition
	}
	return nil
}
func (c *Client) readOwnedAuthenticationMutation(ctx context.Context, realm, clientID, uid, id string) (*ClientOwnershipSnapshot, error) {
	current, err := c.ReadClientOwnership(ctx, realm, clientID)
	if err != nil || current == nil || !ServiceAccountOwned(&current.Application, uid) || current.Application.ID != id || !m2mAuthenticationEnvelope(&current.Application) {
		return nil, ErrApplicationPrecondition
	}
	return current, nil
}
func (c *Client) putOwnedServiceAccountAuthenticator(ctx context.Context, realm, clientID, alias, subject, method, afterHash string, current *ClientOwnershipSnapshot, enable bool, verify func(context.Context) error) error {
	predicted, err := current.AuthenticationTargetHash(method, alias, subject, enable)
	if err != nil || predicted != afterHash {
		return ErrApplicationPrecondition
	}
	// Keycloak merges the supplied attributes. Explicit null removes only our
	// mapping keys; omitting them would retain an inactive federated mapping.
	attrs := map[string]any{}
	if method == "federated-jwt" {
		attrs["jwt.credential.issuer"], attrs["jwt.credential.sub"] = alias, subject
	} else {
		attrs["jwt.credential.issuer"], attrs["jwt.credential.sub"] = nil, nil
	}
	payload := map[string]any{"id": current.Application.ID, "clientId": clientID, "clientAuthenticatorType": method, "attributes": attrs}
	if method == "federated-jwt" && legacyM2MOrigin(&current.Application) {
		payload["webOrigins"] = []string{}
	}
	if enable {
		payload["enabled"] = true
	}
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	_ = c.putJSON(ctx, applicationPath(realm, current.Application.ID), payload)
	return nil
}

func m2mAuthenticationEnvelope(a *Application) bool {
	return a != nil && a.ID != "" && a.Protocol == "openid-connect" && !a.PublicClient && a.ServiceAccountsEnabled && !a.StandardFlowEnabled && !a.DirectAccessGrantsEnabled && !a.ImplicitFlowEnabled && !a.FullScopeAllowed && len(a.RedirectURIs) == 0 && (len(a.WebOrigins) == 0 || legacyM2MOrigin(a)) && (a.ClientAuthenticatorType == "client-secret" || a.ClientAuthenticatorType == "federated-jwt")
}

// RecoverServiceAccountTransitionSecret is exclusive to explicitly approved
// fallback. It cannot rotate and refuses any before/after-state drift.
func (c *Client) RecoverServiceAccountTransitionSecret(ctx context.Context, realm, clientID, uid string, j workloadauth.Journal, verify func(context.Context) error) (string, error) {
	if j.DesiredMode != "Secret" || verify == nil || verify(ctx) != nil {
		return "", ErrApplicationPrecondition
	}
	s, err := c.ReadClientOwnership(ctx, realm, clientID)
	if err != nil || s == nil || s.Application.ID != j.ClientUUID || !ServiceAccountOwned(&s.Application, uid) {
		return "", ErrApplicationPrecondition
	}
	h, err := s.AuthenticationStateHash()
	if err != nil || (h != j.NativeStateHash && h != j.AppliedStateHash) {
		return "", ErrApplicationPrecondition
	}
	var credential struct {
		Value string `json:"value"`
	}
	if err := c.get(ctx, applicationPath(realm, j.ClientUUID)+clientSecretPath, &credential); err != nil {
		return "", err
	}
	if credential.Value == "" || verify(ctx) != nil {
		return "", ErrApplicationPrecondition
	}
	return credential.Value, nil
}

func (c *Client) CheckFederatedServiceAccountOwned(ctx context.Context, realm, clientID, uid, alias, subject string) error {
	a, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if !FederatedWorkloadOwned(a, uid, alias, subject) || !a.Enabled {
		return ErrApplicationPrecondition
	}
	if _, present := a.Attributes[adoption.ReceiptKey]; present {
		s, err := c.ReadClientOwnership(ctx, realm, clientID)
		if err != nil || s == nil || !s.PreservationQualified() {
			return ErrApplicationPrecondition
		}
	}
	return nil
}

// DeleteFederatedServiceAccountIfOwned preserves foreign/adopted dependencies.
func (c *Client) DeleteFederatedServiceAccountIfOwned(ctx context.Context, realm, clientID, uid, alias, subject string, expected *Application, verify func(context.Context) error) error {
	if expected == nil || verify == nil || verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	a, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if a == nil {
		return nil
	}
	if !FederatedWorkloadOwned(a, uid, alias, subject) || !reflect.DeepEqual(a, expected) {
		return ErrApplicationPrecondition
	}
	if !c.federatedServiceAccountDeletionQualified(ctx, realm, clientID, uid, a) {
		return ErrApplicationPrecondition
	}
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	_ = c.deleteMapper(ctx, applicationPath(realm, a.ID))
	a, err = c.GetApplication(ctx, realm, clientID)
	if err != nil || a != nil {
		return ErrApplicationPrecondition
	}
	return nil
}

func (c *Client) federatedServiceAccountDeletionQualified(ctx context.Context, realm, clientID, uid string, expected *Application) bool {
	snapshot, err := c.ReadClientOwnership(ctx, realm, clientID)
	if err != nil || snapshot == nil || !reflect.DeepEqual(&snapshot.Application, expected) || !snapshot.PreservationQualified() || snapshot.document["authorizationServicesEnabled"] == true {
		return false
	}
	if _, present := expected.Attributes[adoption.ReceiptKey]; present {
		return c.CheckAdoptedClientCleanup(ctx, realm, clientID, "HankoServiceAccount", uid) == nil
	}
	return true
}

func legacyM2MOrigin(a *Application) bool {
	return a != nil && a.ClientAuthenticatorType == "client-secret" && len(a.WebOrigins) == 1 && a.WebOrigins[0] == "+"
}
