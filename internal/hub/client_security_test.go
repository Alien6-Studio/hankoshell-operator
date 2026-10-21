package hub

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type unexpectedRoundTripper struct{}

func (unexpectedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrUseLastResponse
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func responseClient(status int, body io.Reader, headers http.Header) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if body == nil {
			body = strings.NewReader("")
		}
		return &http.Response{
			StatusCode: status,
			Header:     headers,
			Body:       io.NopCloser(body),
		}, nil
	})}
}

func TestPrivateCATrustIsScopedToSynchronizationClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/bundles/latest":
			_ = json.NewEncoder(w).Encode(SignedBundle{Bundle: Bundle{Version: "v1", TenantID: "tenant-1"}})
		case "/api/v1/operators/enroll":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(EnrollResult{ClusterID: "cluster-1", TenantID: "tenant-1", Token: "permanent"})
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)

	caFile := filepath.Join(t.TempDir(), "hub-ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write test Hub CA: %v", err)
	}

	httpClient, err := NewHTTPClient(caFile)
	if err != nil {
		t.Fatalf("build private Hub client: %v", err)
	}
	syncClient := NewWithHTTPClient(server.URL, "tenant-1", "permanent", httpClient)
	if _, err := syncClient.FetchBundle(context.Background()); err != nil {
		t.Fatalf("private Hub synchronization should trust its configured CA: %v", err)
	}

	// The same private certificate must not become trusted by the public
	// enrollment client merely because synchronization trusts it.
	if _, err := Enroll(context.Background(), server.URL, "enr_test"); err == nil {
		t.Fatal("public enrollment unexpectedly trusted the private synchronization CA")
	}
}

func TestNewHTTPClientRejectsInvalidCA(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "invalid-ca.crt")
	if err := os.WriteFile(caFile, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPClient(caFile); err == nil {
		t.Fatal("expected invalid Hub CA to be rejected")
	}
}

func TestNewHTTPClientRejectsMissingCA(t *testing.T) {
	if _, err := NewHTTPClient(filepath.Join(t.TempDir(), "missing-ca.crt")); err == nil {
		t.Fatal("expected a missing Hub CA to be rejected")
	}
}

func TestNewHTTPClientRejectsUnexpectedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = unexpectedRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = original })

	if _, err := NewHTTPClient(""); err == nil {
		t.Fatal("expected an unexpected process-wide HTTP transport to be rejected")
	}
}

func TestHubClientLifecycleDeclaresJSONMediaTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/operators/enroll":
			if request.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "missing JSON media type", http.StatusUnsupportedMediaType)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(EnrollResult{
				ClusterID: "cluster-1", TenantID: "tenant-1", Token: "active",
				ExpiresAt: time.Now().Add(time.Minute),
			})
		case "/api/v1/operators/token/rotate":
			if request.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "missing JSON media type", http.StatusUnsupportedMediaType)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(EnrollResult{
				ClusterID: "cluster-1", TenantID: "tenant-1", Token: "pending",
				ExpiresAt: time.Now().Add(time.Minute),
			})
		case "/api/v1/operators/token/confirm":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/operators/status":
			if request.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "missing JSON media type", http.StatusUnsupportedMediaType)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/bundles/latest":
			if request.Header.Get("Accept") != "application/json" {
				http.Error(w, "missing JSON accept header", http.StatusNotAcceptable)
				return
			}
			_ = json.NewEncoder(w).Encode(SignedBundle{Bundle: Bundle{Version: "v1", TenantID: "tenant-1"}})
		case "/api/v1/mesh/policy":
			if request.Header.Get("Accept") != "application/json" {
				http.Error(w, "missing JSON accept header", http.StatusNotAcceptable)
				return
			}
			w.Header().Set("X-Hanko-Mesh-Policy-Mode", "audit-only")
			_, _ = w.Write([]byte(`{"algorithm":"Ed25519"}`))
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)

	if _, err := Enroll(context.Background(), server.URL, "enroll-once"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	client := New(server.URL, "tenant-1", "active")
	if _, err := client.PrepareRotation(context.Background(), "rotation-1"); err != nil {
		t.Fatalf("prepare rotation: %v", err)
	}
	if err := client.ConfirmRotation(context.Background()); err != nil {
		t.Fatalf("confirm rotation: %v", err)
	}
	if _, err := client.FetchBundle(context.Background()); err != nil {
		t.Fatalf("fetch bundle: %v", err)
	}
	if _, err := client.FetchMeshPolicy(context.Background()); err != nil {
		t.Fatalf("fetch mesh policy: %v", err)
	}
	if _, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Synced"}); err != nil {
		t.Fatalf("report status: %v", err)
	}
}

func TestFetchMeshPolicyPreservesSignedBytesAndRequiresAuditBinding(t *testing.T) {
	envelope := []byte(`{"algorithm":"Ed25519","keyId":"key","payload":"payload","signature":"signature"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/mesh/policy" || request.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Hanko-Mesh-Policy-Mode", "audit-only")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope)
	}))
	t.Cleanup(server.Close)
	client := New(server.URL, "tenant-a", "token")
	got, err := client.FetchMeshPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(envelope) {
		t.Fatalf("signed envelope bytes changed: got %q want %q", got, envelope)
	}

	unbound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(envelope)
	}))
	t.Cleanup(unbound.Close)
	if _, err := New(unbound.URL, "tenant-a", "token").FetchMeshPolicy(context.Background()); err == nil {
		t.Fatal("policy without audit-only response binding was accepted")
	}
}

func TestEnrollRejectsInvalidHubResponses(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
	}{
		"status":     {status: http.StatusUnauthorized, body: `denied`},
		"malformed":  {status: http.StatusCreated, body: `{`},
		"incomplete": {status: http.StatusCreated, body: `{"clusterID":"cluster-1"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			if _, err := Enroll(context.Background(), server.URL, "single-use"); err == nil {
				t.Fatal("invalid enrollment response was accepted")
			}
		})
	}
	if _, err := Enroll(context.Background(), "://invalid", "single-use"); err == nil {
		t.Fatal("invalid enrollment endpoint was accepted")
	}
}

func TestHubClientRejectsMalformedEndpoints(t *testing.T) {
	client := NewWithHTTPClient("://invalid", "tenant-1", "token", responseClient(http.StatusOK, nil, nil))
	checks := map[string]func() error{
		"prepare rotation": func() error {
			_, err := client.PrepareRotation(context.Background(), "rotation-1")
			return err
		},
		"confirm rotation": func() error { return client.ConfirmRotation(context.Background()) },
		"fetch bundle": func() error {
			_, err := client.FetchBundle(context.Background())
			return err
		},
		"fetch mesh policy": func() error {
			_, err := client.FetchMeshPolicy(context.Background())
			return err
		},
		"report status": func() error {
			_, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Synced"})
			return err
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("invalid endpoint was accepted")
			}
		})
	}
}

func TestHubClientSurfacesTransportFailures(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	client := NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", httpClient)
	checks := map[string]func() error{
		"prepare rotation": func() error {
			_, err := client.PrepareRotation(context.Background(), "rotation-1")
			return err
		},
		"confirm rotation": func() error { return client.ConfirmRotation(context.Background()) },
		"fetch bundle": func() error {
			_, err := client.FetchBundle(context.Background())
			return err
		},
		"fetch mesh policy": func() error {
			_, err := client.FetchMeshPolicy(context.Background())
			return err
		},
		"report status": func() error {
			_, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Degraded"})
			return err
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("transport failure was ignored")
			}
		})
	}
}

func TestRotationAndBundleRejectInvalidResponses(t *testing.T) {
	validExpiry := time.Now().Add(time.Minute).Format(time.RFC3339Nano)
	tests := map[string]struct {
		client *Client
		call   func(*Client) error
	}{
		"rotation status": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusConflict, strings.NewReader("conflict"), nil)),
			call:   func(client *Client) error { _, err := client.PrepareRotation(context.Background(), "r1"); return err },
		},
		"rotation malformed": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusCreated, strings.NewReader("{"), nil)),
			call:   func(client *Client) error { _, err := client.PrepareRotation(context.Background(), "r1"); return err },
		},
		"rotation incomplete": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusCreated, strings.NewReader(`{"clusterID":"cluster-1","expiresAt":"`+validExpiry+`"}`), nil)),
			call:   func(client *Client) error { _, err := client.PrepareRotation(context.Background(), "r1"); return err },
		},
		"confirmation status": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusUnauthorized, strings.NewReader("denied"), nil)),
			call:   func(client *Client) error { return client.ConfirmRotation(context.Background()) },
		},
		"bundle status": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusBadGateway, strings.NewReader("unavailable"), nil)),
			call:   func(client *Client) error { _, err := client.FetchBundle(context.Background()); return err },
		},
		"bundle malformed": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusOK, strings.NewReader("{"), nil)),
			call:   func(client *Client) error { _, err := client.FetchBundle(context.Background()); return err },
		},
		"status rejected": {
			client: NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", responseClient(http.StatusForbidden, strings.NewReader("denied"), nil)),
			call: func(client *Client) error {
				_, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Degraded"})
				return err
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.call(test.client); err == nil {
				t.Fatal("invalid Hub response was accepted")
			}
		})
	}
}

func TestFetchMeshPolicyRejectsInvalidResponses(t *testing.T) {
	auditHeaders := http.Header{"X-Hanko-Mesh-Policy-Mode": []string{"audit-only"}}
	tests := map[string]*http.Client{
		"read failure": responseClient(http.StatusOK, failingReader{}, auditHeaders),
		"oversized":    responseClient(http.StatusOK, strings.NewReader(strings.Repeat("x", maxMeshPolicyEnvelopeBytes+1)), auditHeaders),
		"status":       responseClient(http.StatusForbidden, strings.NewReader(`{"error":"denied"}`), auditHeaders),
		"binding":      responseClient(http.StatusOK, strings.NewReader(`{"policy":{}}`), nil),
		"empty":        responseClient(http.StatusOK, strings.NewReader(""), auditHeaders),
		"malformed":    responseClient(http.StatusOK, strings.NewReader("{"), auditHeaders),
	}
	for name, httpClient := range tests {
		t.Run(name, func(t *testing.T) {
			client := NewWithHTTPClient("https://hub.invalid", "tenant-1", "token", httpClient)
			if _, err := client.FetchMeshPolicy(context.Background()); err == nil {
				t.Fatal("invalid mesh policy response was accepted")
			}
		})
	}
}
