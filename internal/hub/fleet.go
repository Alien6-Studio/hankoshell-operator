package hub

import (
	"context"
	"errors"
	"net/http"
)

// ErrFleetUnavailable permits bounded use of an already verified local plan.
// Authentication, redirects, invalid bodies and other refusals do not qualify.
var ErrFleetUnavailable = errors.New("signed fleet Hub unavailable")

// NewFleetClient uses the redirect refusal shared by every Hub route, including
// rotation, heartbeats and command confirmation. The caller's client is copied.
func NewFleetClient(endpoint, tenantID, token string, transport *http.Client) *Client {
	return NewWithHTTPClient(endpoint, tenantID, token, transport)
}

// FetchFleetPlan fetches opaque signed bytes through the existing authenticated
// Hub route. The Accept header explicitly requests the new envelope. It never
// follows redirects or includes a remote response body in an error.
func (c *Client) FetchFleetPlan(ctx context.Context) ([]byte, error) {
	req, err := c.authenticatedRequest(ctx, http.MethodGet, "/api/v1/bundles/latest", nil)
	if err != nil || req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.RawQuery != "" {
		return nil, errors.New("signed fleet endpoint must use an exact HTTPS authority")
	}
	req.Header.Set("Accept", "application/vnd.hanko.fleet-plan+json")
	transport := *c.httpClient
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transport.Do(req)
	if err != nil {
		return nil, ErrFleetUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout {
		return nil, ErrFleetUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("signed fleet plan response was refused")
	}
	body, err := readHubResponse(response, maxBundleEnvelopeBytes)
	if err != nil {
		return nil, errors.New("signed fleet plan response exceeds its bounded transport contract")
	}
	return body, nil
}
