package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// IdentityProviderMapper is the Keycloak representation of a mapper attached
// to an upstream identity provider.
type IdentityProviderMapper struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

// ProtocolMapper is the Keycloak representation of a mapper attached to an
// OIDC client.
type ProtocolMapper struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

// EnsureIdentityProviderMapper creates a mapper or corrects its drift by name.
// Mapper names must be stable and unique within an identity provider.
func (c *Client) EnsureIdentityProviderMapper(ctx context.Context, realm string, desired IdentityProviderMapper) (IdentityProviderMapper, error) {
	if desired.Name == "" || desired.IdentityProviderAlias == "" || desired.IdentityProviderMapper == "" {
		return IdentityProviderMapper{}, fmt.Errorf("identity-provider mapper name, alias and provider are required")
	}
	mappers, err := c.ListIdentityProviderMappers(ctx, realm, desired.IdentityProviderAlias)
	if err != nil {
		return IdentityProviderMapper{}, err
	}
	current, found, err := findIdentityProviderMapper(mappers, desired.Name)
	if err != nil {
		return IdentityProviderMapper{}, err
	}
	collectionPath := identityProviderMappersPath(realm, desired.IdentityProviderAlias)
	if !found {
		return c.createIdentityProviderMapper(ctx, realm, collectionPath, desired)
	}
	desired.ID = current.ID
	if current.IdentityProviderAlias == desired.IdentityProviderAlias &&
		current.IdentityProviderMapper == desired.IdentityProviderMapper && maps.Equal(current.Config, desired.Config) {
		return current, nil
	}
	if err := c.updateMapper(ctx, collectionPath+"/"+url.PathEscape(current.ID), desired); err != nil {
		return IdentityProviderMapper{}, fmt.Errorf("update identity-provider mapper %q: %w", desired.Name, err)
	}
	return desired, nil
}

func (c *Client) createIdentityProviderMapper(ctx context.Context, realm, collectionPath string, desired IdentityProviderMapper) (IdentityProviderMapper, error) {
	id, err := c.createMapper(ctx, collectionPath, desired)
	if err != nil {
		return IdentityProviderMapper{}, fmt.Errorf("create identity-provider mapper %q: %w", desired.Name, err)
	}
	if id != "" {
		desired.ID = id
		return desired, nil
	}
	mappers, err := c.ListIdentityProviderMappers(ctx, realm, desired.IdentityProviderAlias)
	if err != nil {
		return IdentityProviderMapper{}, err
	}
	created, ok, err := findIdentityProviderMapper(mappers, desired.Name)
	if err != nil {
		return IdentityProviderMapper{}, fmt.Errorf("resolve created identity-provider mapper %q: %w", desired.Name, err)
	}
	if !ok {
		return IdentityProviderMapper{}, fmt.Errorf("resolve created identity-provider mapper %q: mapper not found after creation", desired.Name)
	}
	return created, nil
}

// ListIdentityProviderMappers returns all mappers attached to one provider alias.
func (c *Client) ListIdentityProviderMappers(ctx context.Context, realm, alias string) ([]IdentityProviderMapper, error) {
	var mappers []IdentityProviderMapper
	if err := c.get(ctx, identityProviderMappersPath(realm, alias), &mappers); err != nil {
		return nil, fmt.Errorf("list identity-provider mappers for %q: %w", alias, err)
	}
	return mappers, nil
}

// DeleteIdentityProviderMapper deletes one mapper. A missing mapper is already
// converged and is therefore not an error.
func (c *Client) DeleteIdentityProviderMapper(ctx context.Context, realm, alias, id string) error {
	if id == "" {
		return nil
	}
	mapperPath := identityProviderMappersPath(realm, alias) + "/" + url.PathEscape(id)
	if err := c.deleteMapper(ctx, mapperPath); err != nil {
		return fmt.Errorf("delete identity-provider mapper %q: %w", id, err)
	}
	return nil
}

// EnsureClientProtocolMapper creates or updates an application-scoped OIDC
// protocol mapper by its stable name.
func (c *Client) EnsureClientProtocolMapper(ctx context.Context, realm, clientID string, desired ProtocolMapper) (ProtocolMapper, error) {
	if desired.Name == "" || desired.ProtocolMapper == "" {
		return ProtocolMapper{}, fmt.Errorf("protocol mapper name and provider are required")
	}
	if desired.Protocol == "" {
		desired.Protocol = openIDConnectProtocol
	}
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return ProtocolMapper{}, fmt.Errorf("resolve client UUID for protocol mapper: %w", err)
	}
	if uuid == "" {
		return ProtocolMapper{}, fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	mappers, err := c.listClientProtocolMappersByUUID(ctx, realm, uuid)
	if err != nil {
		return ProtocolMapper{}, err
	}
	current, found, err := findProtocolMapper(mappers, desired.Name)
	if err != nil {
		return ProtocolMapper{}, err
	}
	collectionPath := clientProtocolMappersPath(realm, uuid)
	if !found {
		return c.createClientProtocolMapper(ctx, realm, uuid, collectionPath, desired)
	}
	desired.ID = current.ID
	if current.Protocol == desired.Protocol && current.ProtocolMapper == desired.ProtocolMapper && maps.Equal(current.Config, desired.Config) {
		return current, nil
	}
	if err := c.updateMapper(ctx, collectionPath+"/"+url.PathEscape(current.ID), desired); err != nil {
		return ProtocolMapper{}, fmt.Errorf("update protocol mapper %q: %w", desired.Name, err)
	}
	return desired, nil
}

func (c *Client) createClientProtocolMapper(ctx context.Context, realm, uuid, collectionPath string, desired ProtocolMapper) (ProtocolMapper, error) {
	id, err := c.createMapper(ctx, collectionPath, desired)
	if err != nil {
		return ProtocolMapper{}, fmt.Errorf("create protocol mapper %q: %w", desired.Name, err)
	}
	if id != "" {
		desired.ID = id
		return desired, nil
	}
	mappers, err := c.listClientProtocolMappersByUUID(ctx, realm, uuid)
	if err != nil {
		return ProtocolMapper{}, err
	}
	created, ok, err := findProtocolMapper(mappers, desired.Name)
	if err != nil {
		return ProtocolMapper{}, fmt.Errorf("resolve created protocol mapper %q: %w", desired.Name, err)
	}
	if !ok {
		return ProtocolMapper{}, fmt.Errorf("resolve created protocol mapper %q: mapper not found after creation", desired.Name)
	}
	return created, nil
}

// ListClientProtocolMappers returns protocol mappers attached directly to a client.
func (c *Client) ListClientProtocolMappers(ctx context.Context, realm, clientID string) ([]ProtocolMapper, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return nil, fmt.Errorf("resolve client UUID for protocol mappers: %w", err)
	}
	if uuid == "" {
		return nil, fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	return c.listClientProtocolMappersByUUID(ctx, realm, uuid)
}

func (c *Client) listClientProtocolMappersByUUID(ctx context.Context, realm, uuid string) ([]ProtocolMapper, error) {
	var mappers []ProtocolMapper
	if err := c.get(ctx, clientProtocolMappersPath(realm, uuid), &mappers); err != nil {
		return nil, fmt.Errorf("list client protocol mappers: %w", err)
	}
	return mappers, nil
}

// DeleteClientProtocolMapper deletes one application mapper. Missing mappers
// are treated as already converged.
func (c *Client) DeleteClientProtocolMapper(ctx context.Context, realm, clientID, id string) error {
	if id == "" {
		return nil
	}
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve client UUID for mapper deletion: %w", err)
	}
	if uuid == "" {
		return nil
	}
	mapperPath := clientProtocolMappersPath(realm, uuid) + "/" + url.PathEscape(id)
	if err := c.deleteMapper(ctx, mapperPath); err != nil {
		return fmt.Errorf("delete protocol mapper %q: %w", id, err)
	}
	return nil
}

func identityProviderMappersPath(realm, alias string) string {
	return adminRealmsPath + url.PathEscape(realm) + "/identity-provider/instances/" + url.PathEscape(alias) + "/mappers"
}

func clientProtocolMappersPath(realm, uuid string) string {
	return adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(uuid) + "/protocol-mappers/models"
}

func findIdentityProviderMapper(mappers []IdentityProviderMapper, name string) (IdentityProviderMapper, bool, error) {
	var match IdentityProviderMapper
	found := false
	for _, mapper := range mappers {
		if mapper.Name != name {
			continue
		}
		if found {
			return IdentityProviderMapper{}, false, fmt.Errorf("multiple identity-provider mappers named %q", name)
		}
		match = mapper
		found = true
	}
	return match, found, nil
}

func findProtocolMapper(mappers []ProtocolMapper, name string) (ProtocolMapper, bool, error) {
	var match ProtocolMapper
	found := false
	for _, mapper := range mappers {
		if mapper.Name != name {
			continue
		}
		if found {
			return ProtocolMapper{}, false, fmt.Errorf("multiple protocol mappers named %q", name)
		}
		match = mapper
		found = true
	}
	return match, found, nil
}

func (c *Client) createMapper(ctx context.Context, mapperPath string, payload any) (string, error) {
	resp, body, err := c.mapperRequest(ctx, http.MethodPost, mapperPath, payload)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf(keycloakErrorFormat, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	location := strings.TrimRight(resp.Header.Get("Location"), "/")
	if location == "" {
		return "", nil
	}
	return path.Base(location), nil
}

func (c *Client) updateMapper(ctx context.Context, mapperPath string, payload any) error {
	resp, body, err := c.mapperRequest(ctx, http.MethodPut, mapperPath, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf(keycloakErrorFormat, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) deleteMapper(ctx context.Context, mapperPath string) error {
	resp, body, err := c.mapperRequest(ctx, http.MethodDelete, mapperPath, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf(keycloakErrorFormat, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) mapperRequest(ctx context.Context, method, mapperPath string, payload any) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	token, err := c.bearerToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+mapperPath, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+token)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return resp, responseBody, nil
}
