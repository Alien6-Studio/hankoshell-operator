package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WithMutationGuard returns a separately guarded connection without changing
// another tenant's shared client or copying a mutex. Guards compose and cannot
// be removed by cloning. Configure before registering the returned client.
func (c *Client) WithMutationGuard(guard func(context.Context) error) *Client {
	if c == nil {
		return nil
	}
	clone := &Client{baseURL: c.baseURL, clientID: c.clientID, clientSecret: c.clientSecret,
		allowInsecureHTTP: c.allowInsecureHTTP, endpointError: c.endpointError,
		inventoryOnly: c.inventoryOnly, dependentRealm: c.dependentRealm, httpClient: c.httpClient,
		clientSession: c.clientSession}
	clone.mutationGuard = func(ctx context.Context) error {
		if c.mutationGuard != nil {
			if err := c.mutationGuard(ctx); err != nil {
				return err
			}
		}
		if guard != nil {
			return guard(ctx)
		}
		return nil
	}
	return clone
}

func (c *Client) authorizeMutation(req *http.Request) error {
	guarded, err := c.mutationGuardRequired(req)
	if err != nil || !guarded {
		return err
	}
	return c.mutationGuard(req.Context())
}

func (c *Client) mutationGuardRequired(req *http.Request) (bool, error) {
	if c.mutationGuard == nil || req.Method == http.MethodGet || req.Method == http.MethodHead {
		return false, nil
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return false, fmt.Errorf("invalid guarded provider endpoint: %w", err)
	}
	path := strings.TrimPrefix(req.URL.EscapedPath(), strings.TrimRight(base.EscapedPath(), "/"))
	return !isBootstrapTokenRequest(req.Method, path), nil
}
