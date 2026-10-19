package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func legacyCalls() map[string]func(*Client) error {
	ctx := context.Background()
	return map[string]func(*Client) error{
		"bundle":           func(c *Client) error { _, err := c.FetchBundle(ctx); return err },
		"mesh":             func(c *Client) error { _, err := c.FetchMeshPolicy(ctx); return err },
		"rotation":         func(c *Client) error { _, err := c.PrepareRotation(ctx, "fixture"); return err },
		"confirm rotation": func(c *Client) error { return c.ConfirmRotation(ctx) },
		"heartbeat":        func(c *Client) error { _, err := c.ReportStatus(ctx, OperatorStatus{}); return err },
		"decommission":     func(c *Client) error { return c.ConfirmDecommission(ctx, nil) },
		"enrollment": func(c *Client) error {
			_, err := enrollWithClient(ctx, c.endpoint, "fixture", EnrollmentIdentity{}, c.httpClient)
			return err
		},
	}
}

func TestLegacyHubRoutesRefuseRedirectsWithoutChangingCaller(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			forwarded := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/forbidden" {
					forwarded++
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.Redirect(w, r, "/forbidden", status)
			}))
			defer server.Close()
			transport := server.Client()
			callback := 0
			transport.CheckRedirect = func(*http.Request, []*http.Request) error { callback++; return nil }
			c := NewWithHTTPClient(server.URL, "tenant", "fixture", transport)
			for name, call := range legacyCalls() {
				if err := call(c); err == nil {
					t.Errorf("%s accepted HTTP %d", name, status)
				}
			}
			if forwarded != 0 || callback != 0 {
				t.Fatal("Hub followed a response-selected destination")
			}
			response, err := transport.Get(server.URL + "/caller")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if forwarded != 1 || callback != 1 {
				t.Fatal("Hub mutated the caller's client")
			}
		})
	}
}

func TestHubErrorsNeverPublishRemoteBodies(t *testing.T) {
	for name, call := range legacyCalls() {
		t.Run(name, func(t *testing.T) {
			body := &measuredHubBody{Reader: strings.NewReader("synthetic-credential-sentinel")}
			c := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", measuredHubClient(http.StatusBadGateway, body))
			err := call(c)
			if err == nil || strings.Contains(err.Error(), "synthetic-credential-sentinel") || !body.closed {
				t.Fatalf("remote response escaped error boundary: %v", err)
			}
		})
	}
}

func TestLegacyBundleAggregateLimitAndUnambiguousJSON(t *testing.T) {
	for _, count := range []int{199, 200, 201} {
		bundle := Bundle{Version: "fixture", TenantID: "tenant"}
		for i := 0; i < count; i++ {
			if i%2 == 0 {
				bundle.Apps = append(bundle.Apps, json.RawMessage(`{}`))
			} else {
				bundle.Realms = append(bundle.Realms, json.RawMessage(`{}`))
			}
		}
		body, err := json.Marshal(SignedBundle{Bundle: bundle, Signature: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		c := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", responseClient(http.StatusOK, strings.NewReader(string(body)), nil))
		got, err := c.FetchBundle(context.Background())
		if (err == nil) != (count <= 200) {
			t.Fatalf("aggregate count %d: %v", count, err)
		}
		if err == nil && legacyBundleObjectCount(&got.Bundle) != count {
			t.Fatal("accepted bundle changed content")
		}
	}
	for _, body := range []string{
		`{"bundle":{"apps":[],"apps":[{}]},"signature":"fixture"}`,
		`{"bundle":{"apps":{}},"signature":"fixture"}`,
		`{"bundle":{"version":{"synthetic-credential-sentinel":1}},"signature":"fixture"}`,
		`{"bundle":{"apps":[` + strings.Repeat(`[`, 33) + `{}` + strings.Repeat(`]`, 33) + `]},"signature":"fixture"}`,
	} {
		c := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", responseClient(http.StatusOK, strings.NewReader(body), nil))
		if _, err := c.FetchBundle(context.Background()); err == nil || strings.Contains(err.Error(), "synthetic-credential-sentinel") {
			t.Fatalf("ambiguous or malformed bundle escaped rejection: %v", err)
		}
	}
}
