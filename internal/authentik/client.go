// Package authentik is the opt-in experimental authentik adapter. It has no
// Kubernetes or reconciler dependencies and never provisions users or policies.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

const Version = "2026.8.4"
const MaxResponseBytes = 1024 * 1024

var ErrTransport = errors.New("experimental provider request failed")
var ErrResponse = errors.New("experimental provider returned an invalid or incomplete response")
var ErrRoute = errors.New("experimental provider route is not allowed")
var ErrNotFound = errors.New("experimental provider object is absent")
var ErrForbidden = errors.New("experimental provider credential lacks permission")
var ErrConflict = errors.New("experimental provider ownership conflict")
var ErrUnsupported = errors.New("experimental provider semantics are unsupported")

type StatusError struct{ Code int }

func (e *StatusError) Error() string { return "experimental provider request was rejected" }
func (e *StatusError) Is(target error) bool {
	return e.Code == http.StatusNotFound && target == ErrNotFound || (e.Code == http.StatusForbidden || e.Code == http.StatusUnauthorized) && target == ErrForbidden
}

type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

func NewClient(endpoint, token string, transport *http.Client) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Path != "" && u.Path != "/" || strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return nil, ErrRoute
	}
	if transport == nil {
		transport = &http.Client{Timeout: 20 * time.Second}
	}
	secured, err := httpsecurity.RequireHTTPS(transport, endpoint)
	if err != nil {
		return nil, ErrRoute
	}
	if secured.Timeout <= 0 || secured.Timeout > 20*time.Second {
		secured.Timeout = 20 * time.Second
	}
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), token: token, http: secured}, nil
}

var providerRoute = regexp.MustCompile(`^/api/v3/providers/oauth2/([1-9][0-9]{0,9}/)?$`)
var appRoute = regexp.MustCompile(`^/api/v3/core/applications/(hk-[a-f0-9]{40}/)?$`)

// No remotely supplied pagination link or discovery URL is ever followed.
func allowed(method, path string, query url.Values) bool {
	if !providerRoute.MatchString(path) && !appRoute.MatchString(path) {
		return false
	}
	collection := path == "/api/v3/providers/oauth2/" || path == "/api/v3/core/applications/"
	if collection {
		if method == http.MethodPost {
			return len(query) == 0
		}
		if method != http.MethodGet {
			return false
		}
		if !allowedQuery(query) {
			return false
		}
		return collectionQuery(path, query)
	}
	return len(query) == 0 && (method == http.MethodGet || method == http.MethodPatch || method == http.MethodDelete)
}
func (c *Client) request(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if !allowed(method, path, query) {
		return ErrRoute
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > MaxResponseBytes {
			return ErrResponse
		}
	}
	target := c.endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return ErrTransport
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ErrTransport
	}
	defer response.Body.Close()
	// Error bodies and server headers are deliberately never rendered or parsed.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &StatusError{Code: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes {
		return ErrResponse
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return ErrResponse
	}
	return nil
}

func allowedQuery(query url.Values) bool {
	for key, values := range query {
		if len(values) != 1 || key != "client_id" && key != "page_size" && key != "slug" {
			return false
		}
	}
	return true
}

func collectionQuery(path string, query url.Values) bool {
	if query.Get("page_size") != "2" {
		return false
	}
	switch path {
	case "/api/v3/providers/oauth2/":
		return query.Get("client_id") != "" && query.Get("slug") == ""
	case "/api/v3/core/applications/":
		return query.Get("slug") != "" && query.Get("client_id") == ""
	default:
		return false
	}
}
