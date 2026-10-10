package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// Application is a non-secret projection of a complete provider client. Secret
// fields are deliberately absent, including when Keycloak returns them on GET.
type Application struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name"`
	Protocol                  string            `json:"protocol"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	FullScopeAllowed          bool              `json:"fullScopeAllowed"`
	RedirectURIs              []string          `json:"redirectUris"`
	WebOrigins                []string          `json:"webOrigins"`
	Attributes                map[string]string `json:"attributes"`
}

var ErrApplicationPrecondition = errors.New("application ownership or protocol changed")

// GetApplication uses exact lookup and a full GET; list representations may be
// brief or filtered by provider permissions. No client-secret endpoint is used.
func (c *Client) GetApplication(ctx context.Context, realm, clientID string) (*Application, error) {
	id, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil || id == "" {
		return nil, err
	}
	var result Application
	if err := c.get(ctx, applicationPath(realm, id), &result); err != nil {
		return nil, err
	}
	if result.ClientID != clientID || result.ID != id {
		return nil, ErrApplicationPrecondition
	}
	return &result, nil
}

func (c *Client) GetClientRealmRoleScopes(ctx context.Context, realm, clientID string) ([]RealmRole, error) {
	id, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil || id == "" {
		return nil, err
	}
	var result []RealmRole
	err = c.get(ctx, applicationPath(realm, id)+"/scope-mappings/realm", &result)
	return result, err
}

func applicationPath(realm, id string) string {
	return adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(id)
}

// EnsureClientRole preserves role identity and composites while repairing the
// explicitly managed description. Client-role lifecycle needs manage-clients.
func (c *Client) EnsureClientRole(ctx context.Context, realm, clientID, name, description string) error {
	if err := c.CreateClientRole(ctx, realm, clientID, name, description); err != nil {
		return err
	}
	roles, err := c.ListClientRoles(ctx, realm, clientID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		if role.Name == name && role.Description == description {
			return nil
		}
	}
	id, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if id == "" {
		return ErrApplicationPrecondition
	}
	path := applicationPath(realm, id) + "/roles/" + url.PathEscape(name)
	var role map[string]any
	if err := c.get(ctx, path, &role); err != nil {
		return err
	}
	if role["name"] != name {
		return ErrApplicationPrecondition
	}
	role["description"] = description
	return c.putJSON(ctx, path, role)
}

// CreateApplication does not retrieve confidential credentials. POST collisions
// fail instead of adopting another writer's client.
func (c *Client) CreateApplication(ctx context.Context, realm string, desired Application) error {
	_, err := c.postJSONExpect(ctx, adminRealmsPath+url.PathEscape(realm)+"/clients", desired, http.StatusCreated)
	return err
}

func (c *Client) DeleteApplicationIfOwned(ctx context.Context, realm, id, clientID, ownerKey, owner string) error {
	var current Application
	path := applicationPath(realm, id)
	if err := c.get(ctx, path, &current); err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	if current.ID != id || current.ClientID != clientID || !ApplicationOwned(&current, owner) {
		return ErrApplicationPrecondition
	}
	if _, present := current.Attributes[adoption.ReceiptKey]; present {
		if err := c.CheckAdoptedClientCleanup(ctx, realm, clientID, "HankoApplication", owner); err != nil {
			return err
		}
	}
	return c.deleteMapper(ctx, path)
}

// UpdateApplication preserves sibling-controller fields. Checks are repeated
// against a fresh complete read immediately before PUT. Keycloak does not offer
// conditional transactional client writes; administrators must avoid concurrent
// ownership edits. This method never performs an in-place protocol conversion.
func (c *Client) UpdateApplication(ctx context.Context, realm string, desired Application, ownerKey, owner string) error {
	var current map[string]any
	path := applicationPath(realm, desired.ID)
	if err := c.get(ctx, path, &current); err != nil {
		return err
	}
	attributes, _ := current["attributes"].(map[string]any)
	if current["clientId"] != desired.ClientID || current["protocol"] != desired.Protocol || attributes[ownerKey] != owner || attributes["hanko.sh/client-owner-kind"] != nil || attributes["hanko.sh/client-owner-uid"] != nil || attributes["hanko.sh/role-owner"] != nil {
		return ErrApplicationPrecondition
	}
	adopted := attributes[adoption.ReceiptKey] != nil
	if adopted {
		snapshot, err := c.currentAdoptedApplication(ctx, realm, desired, owner)
		if err != nil {
			return err
		}
		current = snapshot.document
		attributes, _ = current["attributes"].(map[string]any)
	}
	// Do not round-trip credentials returned by an administrative representation.
	delete(current, "secret")
	delete(current, "access")
	alreadyServiceAccount := current["serviceAccountsEnabled"] == true
	current["name"], current["enabled"], current["publicClient"] = desired.Name, desired.Enabled, desired.PublicClient
	current["standardFlowEnabled"], current["serviceAccountsEnabled"] = desired.StandardFlowEnabled, desired.ServiceAccountsEnabled
	current["directAccessGrantsEnabled"], current["implicitFlowEnabled"], current["fullScopeAllowed"] = false, false, false
	current["redirectUris"], current["webOrigins"] = desired.RedirectURIs, desired.WebOrigins
	if adopted && alreadyServiceAccount && desired.ServiceAccountsEnabled {
		delete(current, "serviceAccountsEnabled")
	}
	nextAttributes := applicationUpdateAttributes(attributes, desired.Attributes, adopted)
	// The authorization-domain journal belongs to HankoResourceServer.
	if receipt, ok := attributes["hanko.sh/adoption-receipt"].(string); ok {
		nextAttributes["hanko.sh/adoption-receipt"] = receipt
	}
	if journal, ok := attributes[authorizationOwnerAttribute].(string); ok {
		nextAttributes[authorizationOwnerAttribute] = journal
	}
	current["attributes"] = nextAttributes
	return c.putJSON(ctx, path, current)
}

// MarkApplicationOwner is deliberately separate from reconciliation. The
// application adapter has already validated an explicit UUID+observation
// migration approval; this second read refuses protocol/UUID races and preserves
// the exact current representation except the new UID ownership marker.
func (c *Client) MarkApplicationOwner(ctx context.Context, realm string, expected Application, ownerKey, owner string) error {
	var current map[string]any
	path := applicationPath(realm, expected.ID)
	if err := c.get(ctx, path, &current); err != nil {
		return err
	}
	attrs, _ := current["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	if current["clientId"] != expected.ClientID || current["protocol"] != expected.Protocol || (attrs[ownerKey] != nil && attrs[ownerKey] != "") || attrs["hanko.sh/client-owner-kind"] != nil || attrs["hanko.sh/client-owner-uid"] != nil || attrs["hanko.sh/adoption-receipt"] != nil || attrs["hanko.sh/role-owner"] != nil {
		return ErrApplicationPrecondition
	}
	delete(current, "secret")
	data, err := json.Marshal(current)
	if err != nil {
		return err
	}
	var snapshot Application
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if !reflect.DeepEqual(snapshot, expected) {
		return ErrApplicationPrecondition
	}
	attrs[ownerKey] = owner
	current["attributes"] = attrs
	return c.putJSON(ctx, path, current)
}

// ProtocolDocument retrieves a public protocol document with the same trusted
// transport and byte budget as Admin API reads. No bearer token is attached.
func (c *Client) ProtocolDocument(ctx context.Context, realm, protocol string) ([]byte, error) {
	var suffix string
	switch protocol {
	case "oidc":
		suffix = "/.well-known/openid-configuration"
	case "saml":
		suffix = "/protocol/saml/descriptor"
	default:
		return nil, fmt.Errorf("unsupported application protocol")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/realms/"+url.PathEscape(realm)+suffix, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("protocol metadata HTTP %d", response.StatusCode)
	}
	return io.ReadAll(response.Body) // do has already buffered and enforced the byte budget.
}

func (c *Client) currentAdoptedApplication(ctx context.Context, realm string, desired Application, owner string) (*ClientOwnershipSnapshot, error) {
	snapshot, err := c.ReadClientOwnership(ctx, realm, desired.ClientID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || snapshot.Application.ID != desired.ID || !validClientAdoptionReceipt(&snapshot.Application, "HankoApplication", owner) || !snapshot.PreservationQualified() {
		return nil, ErrAdoptionPrecondition
	}
	return snapshot, nil
}
func applicationUpdateAttributes(current map[string]any, desired map[string]string, adopted bool) map[string]string {
	result := map[string]string{}
	if adopted {
		for key, value := range current {
			if text, ok := value.(string); ok {
				result[key] = text
			}
		}
		delete(result, "post.logout.redirect.uris")
	}
	for key, value := range desired {
		result[key] = value
	}
	return result
}
