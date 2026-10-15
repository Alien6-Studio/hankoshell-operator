package hub

import (
	"context"
	"errors"
	"net/http"
)

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
		return nil, errors.New("signed fleet plan transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("signed fleet plan response was refused")
	}
	body, err := readHubResponse(response, maxBundleEnvelopeBytes)
	if err != nil {
		return nil, errors.New("signed fleet plan response exceeds its bounded transport contract")
	}
	return body, nil
}
