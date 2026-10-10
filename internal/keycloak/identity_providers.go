package keycloak

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
)

// IdentityProvider is the Keycloak representation of an upstream identity broker.
type IdentityProvider struct {
	InternalID                string            `json:"internalId,omitempty"`
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail"`
	StoreToken                bool              `json:"storeToken"`
	AddReadTokenRoleOnCreate  bool              `json:"addReadTokenRoleOnCreate"`
	LinkOnly                  bool              `json:"linkOnly"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias  string            `json:"postBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config,omitempty"`
}

// ListIdentityProviders returns every broker configured in a realm.
func (c *Client) ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProvider, error) {
	var providers []IdentityProvider
	if err := c.get(ctx, identityProvidersPath(realm), &providers); err != nil {
		return nil, fmt.Errorf("list identity providers for realm %q: %w", realm, err)
	}
	return providers, nil
}

// EnsureIdentityProvider creates a broker or corrects the fields declared by
// HankoRealm. Opaque provider config returned by Keycloak is preserved so a
// provider upgrade cannot make the operator erase newly introduced defaults.
func (c *Client) EnsureIdentityProvider(ctx context.Context, realm string, desired IdentityProvider) (IdentityProvider, error) {
	if strings.TrimSpace(desired.Alias) == "" || strings.TrimSpace(desired.ProviderID) == "" {
		return IdentityProvider{}, fmt.Errorf("identity-provider alias and provider ID are required")
	}
	providers, err := c.ListIdentityProviders(ctx, realm)
	if err != nil {
		return IdentityProvider{}, err
	}
	current, found, err := findIdentityProvider(providers, desired.Alias)
	if err != nil {
		return IdentityProvider{}, err
	}
	collectionPath := identityProvidersPath(realm)
	if !found {
		resp, body, requestErr := c.mapperRequest(ctx, http.MethodPost, collectionPath, desired)
		if requestErr != nil {
			return IdentityProvider{}, fmt.Errorf("create identity provider %q: %w", desired.Alias, requestErr)
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
			return IdentityProvider{}, fmt.Errorf("create identity provider %q: keycloak %d: %s", desired.Alias, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return desired, nil
	}

	next := mergeIdentityProvider(current, desired)
	if identityProviderMatches(current, next) {
		return current, nil
	}
	providerPath := collectionPath + "/" + url.PathEscape(desired.Alias)
	if err := c.putJSON(ctx, providerPath, next); err != nil {
		return IdentityProvider{}, fmt.Errorf("update identity provider %q: %w", desired.Alias, err)
	}
	return next, nil
}

// DeleteIdentityProvider removes one explicitly owned broker. Missing brokers
// are already converged and do not fail cleanup.
func (c *Client) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	if strings.TrimSpace(alias) == "" {
		return nil
	}
	providerPath := identityProvidersPath(realm) + "/" + url.PathEscape(alias)
	resp, body, err := c.mapperRequest(ctx, http.MethodDelete, providerPath, nil)
	if err != nil {
		return fmt.Errorf("delete identity provider %q: %w", alias, err)
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete identity provider %q: keycloak %d: %s", alias, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func identityProvidersPath(realm string) string {
	return "/admin/realms/" + url.PathEscape(realm) + "/identity-provider/instances"
}

func findIdentityProvider(providers []IdentityProvider, alias string) (IdentityProvider, bool, error) {
	var match IdentityProvider
	found := false
	for _, provider := range providers {
		if provider.Alias != alias {
			continue
		}
		if found {
			return IdentityProvider{}, false, fmt.Errorf("multiple identity providers with alias %q", alias)
		}
		match = provider
		found = true
	}
	return match, found, nil
}

func mergeIdentityProvider(current, desired IdentityProvider) IdentityProvider {
	next := current
	next.Alias = desired.Alias
	next.DisplayName = desired.DisplayName
	next.ProviderID = desired.ProviderID
	next.Enabled = desired.Enabled
	next.TrustEmail = desired.TrustEmail
	next.StoreToken = desired.StoreToken
	next.AddReadTokenRoleOnCreate = desired.AddReadTokenRoleOnCreate
	next.LinkOnly = desired.LinkOnly
	next.FirstBrokerLoginFlowAlias = desired.FirstBrokerLoginFlowAlias
	next.PostBrokerLoginFlowAlias = desired.PostBrokerLoginFlowAlias
	next.Config = maps.Clone(current.Config)
	if next.Config == nil {
		next.Config = make(map[string]string, len(desired.Config))
	}
	for key, value := range desired.Config {
		next.Config[key] = value
	}
	return next
}

func identityProviderMatches(left, right IdentityProvider) bool {
	return left.Alias == right.Alias &&
		left.DisplayName == right.DisplayName &&
		left.ProviderID == right.ProviderID &&
		left.Enabled == right.Enabled &&
		left.TrustEmail == right.TrustEmail &&
		left.StoreToken == right.StoreToken &&
		left.AddReadTokenRoleOnCreate == right.AddReadTokenRoleOnCreate &&
		left.LinkOnly == right.LinkOnly &&
		left.FirstBrokerLoginFlowAlias == right.FirstBrokerLoginFlowAlias &&
		left.PostBrokerLoginFlowAlias == right.PostBrokerLoginFlowAlias &&
		maps.Equal(left.Config, right.Config)
}
