package keycloak

import (
	"context"
	"maps"
	"net/url"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// getOwnedServiceAccount performs a fresh provider check for each sensitive
// operation. Neither a Kubernetes Secret nor a previously observed UUID proves
// ownership. Receipt-backed clients require the qualified preservation boundary.
func (c *Client) getOwnedServiceAccount(ctx context.Context, realm, clientID, uid string) (*Application, error) {
	a, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return nil, err
	}
	if !ServiceAccountOwned(a, uid) {
		return nil, ErrApplicationPrecondition
	}
	if _, present := a.Attributes[adoption.ReceiptKey]; present {
		snapshot, err := c.ReadClientOwnership(ctx, realm, clientID)
		if err != nil {
			return nil, err
		}
		if snapshot == nil || snapshot.Application.ID != a.ID || !validClientAdoptionReceipt(&snapshot.Application, "HankoServiceAccount", uid) || !snapshot.PreservationQualified() {
			return nil, ErrAdoptionPrecondition
		}
		a = &snapshot.Application
	}
	return a, nil
}
func (c *Client) CheckServiceAccountOwned(ctx context.Context, realm, clientID, uid string) error {
	_, err := c.getOwnedServiceAccount(ctx, realm, clientID, uid)
	return err
}
func (c *Client) DeleteServiceAccountIfOwned(ctx context.Context, realm, clientID, uid string) error {
	a, err := c.GetApplication(ctx, realm, clientID)
	if err != nil || a == nil {
		return err
	}
	if !ServiceAccountOwned(a, uid) {
		return ErrApplicationPrecondition
	}
	if _, present := a.Attributes[adoption.ReceiptKey]; present {
		if err := c.CheckAdoptedClientCleanup(ctx, realm, clientID, "HankoServiceAccount", uid); err != nil {
			return err
		}
	}
	return c.deleteMapper(ctx, applicationPath(realm, a.ID))
}
func (c *Client) GetServiceAccountSecretIfOwned(ctx context.Context, realm, clientID, uid string) (string, error) {
	a, err := c.getOwnedServiceAccount(ctx, realm, clientID, uid)
	if err != nil {
		return "", err
	}
	var secret struct {
		Value string `json:"value"`
	}
	err = c.get(ctx, applicationPath(realm, a.ID)+clientSecretPath, &secret)
	return secret.Value, err
}
func (c *Client) RotateServiceAccountSecretIfOwned(ctx context.Context, realm, clientID, uid string) (string, error) {
	a, err := c.getOwnedServiceAccount(ctx, realm, clientID, uid)
	if err != nil {
		return "", err
	}
	return c.rotateClientSecretByUUID(ctx, realm, clientID, a.ID)
}
func (c *Client) SyncServiceAccountAttributesIfOwned(ctx context.Context, realm, clientID, uid string, attrs map[string]string) error {
	return c.syncClientAttributes(ctx, realm, clientID, uid, attrs)
}
func serviceMapperOwned(config map[string]string, uid string) bool {
	for key := range config {
		if adoption.ReservedAttribute(key) && key != adoption.ClientOwnerKindKey && key != adoption.ClientOwnerUIDKey {
			return false
		}
	}
	return uid != "" && config[adoption.ClientOwnerKindKey] == "HankoServiceAccount" && config[adoption.ClientOwnerUIDKey] == uid
}
func (c *Client) EnsureServiceAccountMapperIfOwned(ctx context.Context, realm, clientID, uid string, desired ProtocolMapper) (ProtocolMapper, error) {
	a, err := c.getOwnedServiceAccount(ctx, realm, clientID, uid)
	if err != nil {
		return ProtocolMapper{}, err
	}
	if !serviceMapperOwned(desired.Config, uid) {
		return ProtocolMapper{}, ErrApplicationPrecondition
	}
	mappers, err := c.listClientProtocolMappersByUUID(ctx, realm, a.ID)
	if err != nil {
		return ProtocolMapper{}, err
	}
	current, found, err := findProtocolMapper(mappers, desired.Name)
	if err != nil || found && !serviceMapperOwned(current.Config, uid) {
		return ProtocolMapper{}, ErrApplicationPrecondition
	}
	path := clientProtocolMappersPath(realm, a.ID)
	if !found {
		return c.createClientProtocolMapper(ctx, realm, a.ID, path, desired)
	}
	desired.ID = current.ID
	if current.Protocol == desired.Protocol && current.ProtocolMapper == desired.ProtocolMapper && maps.Equal(CanonicalProtocolMapper(current).Config, CanonicalProtocolMapper(desired).Config) {
		return current, nil
	}
	if err := c.updateMapper(ctx, path+"/"+url.PathEscape(current.ID), desired); err != nil {
		return ProtocolMapper{}, err
	}
	return desired, nil
}
func (c *Client) DeleteServiceAccountMapperIfOwned(ctx context.Context, realm, clientID, uid, id string) error {
	a, err := c.getOwnedServiceAccount(ctx, realm, clientID, uid)
	if err != nil {
		return err
	}
	mappers, err := c.listClientProtocolMappersByUUID(ctx, realm, a.ID)
	if err != nil {
		return err
	}
	for _, mapper := range mappers {
		if mapper.ID == id {
			if !serviceMapperOwned(mapper.Config, uid) {
				return ErrApplicationPrecondition
			}
			return c.deleteMapper(ctx, clientProtocolMappersPath(realm, a.ID)+"/"+url.PathEscape(id))
		}
	}
	return nil
}

func setNewServiceAccountOwner(attributes map[string]any, spec CreateAppSpec) error {
	if spec.ServiceAccountOwnerUID == "" {
		return nil
	}
	if spec.Type != "m2m" {
		return ErrApplicationPrecondition
	}
	attributes[adoption.ClientOwnerKindKey], attributes[adoption.ClientOwnerUIDKey] = "HankoServiceAccount", spec.ServiceAccountOwnerUID
	return nil
}
func (c *Client) validateServiceAccountAttributes(ctx context.Context, realm string, payload map[string]any, uuid, clientID, uid string, attrs map[string]string) error {
	var current Application
	if decodeSnapshot(payload, &current) != nil || current.ID != uuid || current.ClientID != clientID || !ServiceAccountOwned(&current, uid) {
		return ErrApplicationPrecondition
	}
	if _, present := current.Attributes[adoption.ReceiptKey]; present {
		snapshot := &ClientOwnershipSnapshot{Application: current, document: payload}
		if err := c.get(ctx, applicationPath(realm, uuid)+"/protocol-mappers/models", &snapshot.mappers); err != nil {
			return err
		}
		if len(snapshot.mappers) > 512 || !validClientAdoptionReceipt(&current, "HankoServiceAccount", uid) || !snapshot.PreservationQualified() {
			return ErrAdoptionPrecondition
		}
	}
	for key := range attrs {
		if adoption.ReservedAttribute(key) {
			return ErrApplicationPrecondition
		}
	}
	return nil
}

func preserveAdoptedServiceAttributes(payload, current, next map[string]any) {
	if current[adoption.ReceiptKey] == nil {
		return
	}
	for key, value := range current {
		next[key] = value
	}
	delete(payload, "serviceAccountsEnabled")
	delete(payload, "access")
}
