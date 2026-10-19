//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureHTTPExchange struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Status       int    `json:"status"`
	Milliseconds int64  `json:"milliseconds"`
	Failure      string `json:"failure,omitempty"`
}

type fixtureHTTPTrace struct {
	next      http.RoundTripper
	mu        sync.Mutex
	exchanges []fixtureHTTPExchange
}

func (t *fixtureHTTPTrace) RoundTrip(request *http.Request) (*http.Response, error) {
	started := time.Now()
	response, err := t.next.RoundTrip(request)
	path := request.URL.EscapedPath()
	if len(path) > 512 {
		path = path[:512]
	}
	exchange := fixtureHTTPExchange{Method: request.Method, Path: path, Milliseconds: time.Since(started).Milliseconds()}
	if response != nil {
		exchange.Status = response.StatusCode
	}
	if err != nil {
		exchange.Failure = "transport-error"
		if errors.Is(err, context.DeadlineExceeded) {
			exchange.Failure = "deadline-exceeded"
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.exchanges) == 64 {
		copy(t.exchanges, t.exchanges[1:])
		t.exchanges = t.exchanges[:63]
	}
	t.exchanges = append(t.exchanges, exchange)
	return response, err
}

func (t *fixtureHTTPTrace) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *fixtureHTTPTrace) snapshot() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, _ := json.MarshalIndent(t.exchanges, "", "  ")
	return data
}

type fixtureTraceTransport func(*http.Request) (*http.Response, error)

func (f fixtureTraceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testFixtureHTTPDiagnostics(t *testing.T) {
	trace := &fixtureHTTPTrace{next: fixtureTraceTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("response-private-sentinel"))}, nil
	})}
	request, err := http.NewRequest(http.MethodPost, "https://fixture.invalid/admin/realms/managed/clients?secret=query-private-sentinel", strings.NewReader("body-private-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer header-private-sentinel")
	for range 70 {
		response, err := trace.RoundTrip(request)
		if err != nil || response.StatusCode != http.StatusCreated {
			t.Fatal("diagnostics changed HTTP outcome")
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	trace.next = fixtureTraceTransport(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })
	if _, err := trace.RoundTrip(request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("diagnostics hid the deadline error")
	}
	data := trace.snapshot()
	var exchanges []fixtureHTTPExchange
	if err := json.Unmarshal(data, &exchanges); err != nil {
		t.Fatal(err)
	}
	if len(exchanges) != 64 || exchanges[63].Failure != "deadline-exceeded" || exchanges[62].Status != http.StatusCreated {
		t.Fatal("diagnostics lost bounded status/deadline evidence")
	}
	if strings.Contains(string(data), "private-sentinel") || !strings.Contains(string(data), "/admin/realms/managed/clients") {
		t.Fatal("diagnostics leaked payloads or lost the route")
	}
}
