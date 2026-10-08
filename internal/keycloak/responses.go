package keycloak

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	maxKeycloakAdminResponseBytes      int64 = 1 << 20
	maxKeycloakCredentialResponseBytes int64 = 64 << 10
	maxKeycloakErrorResponseBytes      int64 = 8 << 10
)

// ErrResponseTooLarge means a complete response exceeds its reviewed byte budget.
// Callers must not use partial data or treat the operation as successful.
var ErrResponseTooLarge = errors.New("keycloak response exceeds its byte budget")

// ErrResponseRead means the response stream could not be read completely.
// Neither a valid JSON prefix nor remote response contents authorize success.
var ErrResponseRead = errors.New("keycloak response body could not be read completely")

// boundedKeycloakResponse closes the original stream on every path and returns
// only fully read data. Budget decompressed bytes, independent of Content-Length;
// one extra byte detects overflow instead of accepting a truncated JSON prefix.
func boundedKeycloakResponse(response *http.Response, limit int64) (*http.Response, error) {
	if response == nil || response.Body == nil {
		return nil, ErrResponseRead
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		limit = min(limit, maxKeycloakErrorResponseBytes)
	}
	if response.ContentLength > limit {
		return nil, oversizedKeycloakResponse(response.StatusCode, limit)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, ErrResponseRead
	}
	if int64(len(body)) > limit {
		return nil, oversizedKeycloakResponse(response.StatusCode, limit)
	}
	buffered := *response
	buffered.Body = io.NopCloser(bytes.NewReader(body))
	buffered.ContentLength = int64(len(body))
	return &buffered, nil
}

func oversizedKeycloakResponse(status int, limit int64) error {
	return fmt.Errorf("%w (HTTP %d, limit %d bytes)", ErrResponseTooLarge, status, limit)
}
