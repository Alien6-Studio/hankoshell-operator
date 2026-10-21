package hankoapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

const serviceAccountRotatedAction = "operator.sa_rotated"

// AuditClient appends tightly scoped operator machine events through the
// hankoShell API's authenticated internal boundary.
type AuditClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewAuditClient validates the local hankoShell API endpoint and supervision token.
func NewAuditClient(rawURL, token string, httpClient *http.Client) (*AuditClient, error) {
	baseURL, err := normalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("HANKO_SUPERVISION_API_TOKEN is required for operator audit")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &AuditClient{baseURL: baseURL, token: token, httpClient: httpClient}, nil
}

// RequireHTTPS secures the enterprise audit client before it is used.
func (c *AuditClient) RequireHTTPS() error {
	secured, err := httpsecurity.RequireHTTPS(c.httpClient, c.baseURL)
	if err != nil {
		return err
	}
	c.httpClient = secured
	return nil
}

// RecordServiceAccountRotation appends one metadata-only rotation receipt. No
// active or pending credential is accepted by this API shape.
func (c *AuditClient) RecordServiceAccountRotation(
	ctx context.Context,
	namespace, instance, clientID, rotationID string,
	rotatedAt time.Time,
) error {
	payload, err := json.Marshal(map[string]any{
		"action": serviceAccountRotatedAction, "namespace": namespace,
		"instance": instance, "clientId": clientID, "rotationId": rotationID,
		"rotatedAt": rotatedAt.UTC(),
	})
	if err != nil {
		return fmt.Errorf("encode operator rotation audit: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/operator/audit", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create operator rotation audit request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call operator rotation audit API: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return fmt.Errorf("operator rotation audit returned status %d", response.StatusCode)
	}
	return nil
}
