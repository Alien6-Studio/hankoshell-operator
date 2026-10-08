package hankoapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

const maxResponseBytes = 1 << 20

// PositionSpec is the API projection of one HankoOrganization node.
type PositionSpec struct {
	Title    string   `json:"title"`
	ParentID string   `json:"parent_id"`
	GroupID  string   `json:"group_id"`
	RoleIDs  []string `json:"role_ids"`
}

type position struct {
	ID      string `json:"id"`
	GroupID string `json:"group_id"`
}

// PositionClient converges operator-owned nodes into the hankoShell API model used
// by hankoShell. The API, rather than its database, remains the boundary.
type PositionClient struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

// NewPositionClient validates the cluster-local API endpoint and credential.
func NewPositionClient(rawURL, adminToken string, httpClient *http.Client) (*PositionClient, error) {
	baseURL, err := normalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(adminToken) == "" {
		return nil, fmt.Errorf("HANKO_API_TOKEN is required for organization projection")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &PositionClient{baseURL: baseURL, adminToken: strings.TrimSpace(adminToken), httpClient: httpClient}, nil
}

// RequireHTTPS secures the enterprise projector before it is used.
func (c *PositionClient) RequireHTTPS() error {
	secured, err := httpsecurity.RequireHTTPS(c.httpClient, c.baseURL)
	if err != nil {
		return err
	}
	c.httpClient = secured
	return nil
}

// EnsurePosition adopts the unique position already bound to groupID or
// creates it, then replaces its writable state. This makes CRD reconciliation
// idempotent across operator restarts and adoption of pre-existing UI data.
func (c *PositionClient) EnsurePosition(ctx context.Context, realm string, spec PositionSpec) (string, error) {
	positions, err := c.list(ctx, realm)
	if err != nil {
		return "", err
	}
	var matched string
	for _, candidate := range positions {
		if candidate.GroupID != spec.GroupID {
			continue
		}
		if matched != "" {
			return "", fmt.Errorf("multiple Hanko positions are bound to group %q", spec.GroupID)
		}
		matched = candidate.ID
	}
	if matched == "" {
		var created position
		if err := c.request(ctx, http.MethodPost, collectionPath(realm), spec, &created, http.StatusCreated); err != nil {
			return "", err
		}
		if created.ID == "" {
			return "", fmt.Errorf("hanko position create response has no id")
		}
		return created.ID, nil
	}
	if err := c.request(ctx, http.MethodPatch, itemPath(realm, matched), spec, nil, http.StatusNoContent); err != nil {
		return "", err
	}
	return matched, nil
}

// DeletePosition removes a previously projected position. A missing position
// is already converged and therefore succeeds.
func (c *PositionClient) DeletePosition(ctx context.Context, realm, positionID string) error {
	if positionID == "" {
		return nil
	}
	return c.request(ctx, http.MethodDelete, itemPath(realm, positionID), nil, nil, http.StatusNoContent, http.StatusNotFound)
}

func (c *PositionClient) list(ctx context.Context, realm string) ([]position, error) {
	var response struct {
		Positions []position `json:"positions"`
	}
	if err := c.request(ctx, http.MethodGet, collectionPath(realm), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	return response.Positions, nil
}

func (c *PositionClient) request(ctx context.Context, method, path string, body, output any, expected ...int) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode Hanko position projection: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("create Hanko position projection request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.adminToken)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call Hanko position projection API: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if !hasStatus(expected, response.StatusCode) {
		return fmt.Errorf("hanko position projection returned status %d", response.StatusCode)
	}
	if output == nil || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(output); err != nil {
		return fmt.Errorf("decode Hanko position projection: %w", err)
	}
	return nil
}

func normalizeURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("HANKO_API_URL must be absolute")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("HANKO_API_URL must not contain credentials, query parameters or a fragment")
	}
	secure := parsed.Scheme == "https"
	clusterLocal := parsed.Scheme == "http" && (isLoopback(parsed.Hostname()) || strings.HasSuffix(parsed.Hostname(), ".svc") || strings.HasSuffix(parsed.Hostname(), ".svc.cluster.local"))
	if !secure && !clusterLocal {
		return "", fmt.Errorf("HANKO_API_URL must use HTTPS or a cluster-local HTTP service")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func collectionPath(realm string) string {
	return "/api/v1/realms/" + url.PathEscape(realm) + "/org/positions"
}

func itemPath(realm, positionID string) string {
	return collectionPath(realm) + "/" + url.PathEscape(positionID)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hasStatus(expected []int, actual int) bool {
	for _, status := range expected {
		if status == actual {
			return true
		}
	}
	return false
}
