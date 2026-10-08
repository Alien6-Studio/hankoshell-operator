package keycloak

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

type responseRoundTripper func(*http.Request) (*http.Response, error)

func (f responseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type measuredKeycloakBody struct {
	io.Reader
	read   int64
	closes int
}

func (b *measuredKeycloakBody) Read(buffer []byte) (int, error) {
	n, err := b.Reader.Read(buffer)
	b.read += int64(n)
	return n, err
}

func (b *measuredKeycloakBody) Close() error {
	b.closes++
	return nil
}

type repeatingKeycloakReader struct{}

func (repeatingKeycloakReader) Read(buffer []byte) (int, error) {
	for i := range buffer {
		buffer[i] = 'x'
	}
	return len(buffer), nil
}

type failedKeycloakReader struct{}

func (failedKeycloakReader) Read([]byte) (int, error) {
	return 0, errors.New("broken stream credential=do-not-disclose")
}

func responseBudgetClient(status int, length int64, body *measuredKeycloakBody) *Client {
	c := New("https://keycloak.invalid", "operator", "synthetic-credential")
	c.token, c.tokenExpiry = "synthetic-token", time.Now().Add(time.Hour)
	c.httpClient = &http.Client{Transport: responseRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: body, ContentLength: length, Header: make(http.Header)}, nil
	})}
	return c
}

// Exercise every reviewed route/method. Newly classified operations inherit the
// gateway budget and cannot introduce a separate unbounded network read path.
func TestAllKeycloakOperationsBoundNetworkReadsAndCloseBodies(t *testing.T) {
	placeholder := regexp.MustCompile(`\{[^}]+\}`)
	operations := append(AdminOperations(), AdminOperation{
		Capability: "credentials", Methods: http.MethodPost, Path: "/realms/master/protocol/openid-connect/token",
	})
	for _, operation := range operations {
		for _, method := range strings.Split(operation.Methods, ",") {
			t.Run(method+" "+operation.Path, func(t *testing.T) {
				for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
					limit := maxKeycloakAdminResponseBytes
					if operation.Capability == "credentials" {
						limit = maxKeycloakCredentialResponseBytes
					}
					if status == http.StatusBadGateway {
						limit = maxKeycloakErrorResponseBytes
					}
					body := &measuredKeycloakBody{Reader: io.LimitReader(repeatingKeycloakReader{}, limit*2)}
					c := responseBudgetClient(status, -1, body)
					request, err := http.NewRequest(method, c.baseURL+placeholder.ReplaceAllString(operation.Path, "fixture"), nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := c.do(request)
					if response != nil || !errors.Is(err, ErrResponseTooLarge) {
						t.Fatalf("HTTP %d accepted an oversized response: %v", status, err)
					}
					if body.read > limit+1 || body.closes != 1 {
						t.Fatalf("HTTP %d read %d bytes, limit %d; closes=%d", status, body.read, limit+1, body.closes)
					}
				}
			})
		}
	}
}

func TestKeycloakBudgetsUseActualBytesAndPreserveExactBoundaries(t *testing.T) {
	for _, test := range []struct {
		path   string
		method string
		status int
		limit  int64
	}{
		{path: "/admin/realms", method: http.MethodGet, status: http.StatusOK, limit: maxKeycloakAdminResponseBytes},
		{path: "/realms/master/protocol/openid-connect/token", method: http.MethodPost, status: http.StatusOK, limit: maxKeycloakCredentialResponseBytes},
		{path: "/admin/realms/r/clients/c/client-secret", method: http.MethodPost, status: http.StatusOK, limit: maxKeycloakCredentialResponseBytes},
		{path: "/admin/realms", method: http.MethodGet, status: http.StatusForbidden, limit: maxKeycloakErrorResponseBytes},
		{path: "/admin/realms", method: http.MethodGet, status: http.StatusTemporaryRedirect, limit: maxKeycloakErrorResponseBytes},
	} {
		for _, length := range []int64{-1, 0, 1, test.limit, test.limit + 1} {
			for _, extra := range []int64{0, 1} {
				body := &measuredKeycloakBody{Reader: strings.NewReader(strings.Repeat(" ", int(test.limit+extra)))}
				c := responseBudgetClient(test.status, length, body)
				request, err := http.NewRequest(test.method, c.baseURL+test.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := c.do(request)
				if extra == 1 || length > test.limit {
					if response != nil || !errors.Is(err, ErrResponseTooLarge) {
						t.Fatalf("oversize accepted for %s, declared=%d actual=%d: %v", test.path, length, test.limit+extra, err)
					}
				} else {
					if err != nil || response == nil {
						t.Fatalf("exact budget rejected for %s: %v", test.path, err)
					}
					// The network body is closed already; readers see a bounded buffer.
					buffered, readErr := io.ReadAll(response.Body)
					response.Body.Close()
					if readErr != nil || int64(len(buffered)) != test.limit {
						t.Fatal("bounded response was truncated")
					}
				}
				if body.read > test.limit+1 || body.closes != 1 {
					t.Fatalf("body lifecycle/budget lost: read=%d closes=%d", body.read, body.closes)
				}
			}
		}
	}
}

func TestKeycloakReadFailureCannotAcceptJSONPrefixesOrIgnoredBodies(t *testing.T) {
	for _, test := range []struct {
		name, payload string
		call          func(*Client) error
	}{
		{name: "token", payload: `{"access_token":"do-not-disclose","expires_in":300}`, call: func(c *Client) error {
			c.invalidateToken()
			_, err := c.fetchToken(context.Background())
			if c.token != "" || !c.tokenExpiry.IsZero() {
				t.Fatal("partial token response reached the cache")
			}
			return err
		}},
		{name: "JSON representation", payload: `{"realm":"fixture"}`, call: func(c *Client) error {
			_, err := c.GetRealm(context.Background(), "fixture")
			return err
		}},
		{name: "Location success", payload: `{}`, call: func(c *Client) error {
			_, _, err := c.postJSONLocation(context.Background(), "/admin/realms/fixture/groups", map[string]string{"name": "fixture"})
			return err
		}},
		{name: "authorization success", payload: `{"id":"fixture"}`, call: func(c *Client) error {
			_, err := c.authorizationCreate(context.Background(), "/admin/realms/r/clients/c/authz/resource-server/scope", map[string]string{"name": "fixture"})
			return err
		}},
		{name: "mapper write", payload: `{}`, call: func(c *Client) error {
			_, _, err := c.mapperRequest(context.Background(), http.MethodPost, "/admin/realms/r/clients/c/protocol-mappers/models", map[string]string{"name": "fixture"})
			return err
		}},
		{name: "raw organization", payload: `{}`, call: func(c *Client) error {
			_, err := c.doRaw(context.Background(), http.MethodPost, "/admin/realms/r/organizations/o/identity-providers", "fixture")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &measuredKeycloakBody{Reader: io.MultiReader(strings.NewReader(test.payload), failedKeycloakReader{})}
			c := responseBudgetClient(http.StatusCreated, -1, body)
			if err := test.call(c); !errors.Is(err, ErrResponseRead) || strings.Contains(err.Error(), "do-not-disclose") {
				t.Fatalf("broken stream accepted or disclosed: %v", err)
			}
			if body.closes != 1 {
				t.Fatal("broken response was not closed")
			}
		})
	}
}

func TestKeycloakTokenRejectsOversizeAndMalformedSuffixBeforeCaching(t *testing.T) {
	for _, suffix := range []string{
		strings.Repeat(" ", int(maxKeycloakCredentialResponseBytes)),
		"{}", " trailing-invalid-json",
	} {
		body := &measuredKeycloakBody{Reader: strings.NewReader(`{"access_token":"do-not-disclose","expires_in":300}` + suffix)}
		c := responseBudgetClient(http.StatusOK, -1, body)
		c.invalidateToken()
		if token, err := c.fetchToken(context.Background()); token != "" || err == nil || c.token != "" || !c.tokenExpiry.IsZero() {
			t.Fatalf("unvalidated token reached caller/cache: token=%q err=%v", token, err)
		}
		if body.closes != 1 {
			t.Fatal("token stream was not closed")
		}
	}
}

func TestKeycloakSecretRotationRejectsOversizeBrokenAndMalformedResponses(t *testing.T) {
	for name, reader := range map[string]io.Reader{
		"oversize": io.MultiReader(strings.NewReader(`{"value":"do-not-disclose"}`), io.LimitReader(repeatingKeycloakReader{}, maxKeycloakCredentialResponseBytes)),
		"broken":   io.MultiReader(strings.NewReader(`{"value":"do-not-disclose"}`), failedKeycloakReader{}),
		"suffix":   strings.NewReader(`{"value":"do-not-disclose"}{}`),
	} {
		t.Run(name, func(t *testing.T) {
			body := &measuredKeycloakBody{Reader: reader}
			c := responseBudgetClient(http.StatusOK, -1, body)
			c.httpClient.Transport = responseRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/admin/realms/r/clients" {
					return &http.Response{StatusCode: http.StatusOK, ContentLength: -1,
						Body: io.NopCloser(strings.NewReader(`[{"id":"fixture-id","clientId":"fixture"}]`))}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: body}, nil
			})
			if secret, err := c.RotateClientSecret(context.Background(), "r", "fixture"); secret != "" || err == nil || strings.Contains(err.Error(), "do-not-disclose") {
				t.Fatalf("unvalidated secret reached caller: secret=%q err=%v", secret, err)
			}
			if body.read > maxKeycloakCredentialResponseBytes+1 || body.closes != 1 {
				t.Fatalf("secret response body lifecycle lost: read=%d closes=%d", body.read, body.closes)
			}
		})
	}
}

func TestKeycloakIgnoredWriteBodyCannotAuthorizeSuccessOrFollowup(t *testing.T) {
	for _, scenario := range []struct {
		name string
		call func(*Client) error
	}{
		{name: "master hardening", call: func(c *Client) error { return c.HardenMasterRealm(context.Background()) }},
		{name: "events", call: func(c *Client) error { return c.ConfigureRealmEvents(context.Background(), "r", RealmSpec{}) }},
		{name: "JSON put", call: func(c *Client) error {
			return c.putJSON(context.Background(), "/admin/realms/r", map[string]any{"enabled": true})
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			body := &measuredKeycloakBody{Reader: io.LimitReader(repeatingKeycloakReader{}, maxKeycloakAdminResponseBytes*2)}
			c := responseBudgetClient(http.StatusNoContent, -1, body)
			if err := scenario.call(c); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("ignored success body bypassed budget: %v", err)
			}
			if body.read > maxKeycloakAdminResponseBytes+1 || body.closes != 1 {
				t.Fatal("ignored response was not bounded/closed")
			}
		})
	}
}

func TestKeycloakGzipBudgetAppliesAfterDecompression(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := io.CopyN(writer, repeatingKeycloakReader{}, maxKeycloakCredentialResponseBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(compressed.Len()) >= maxKeycloakCredentialResponseBytes {
		t.Fatal("gzip fixture does not exercise expansion")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	t.Cleanup(server.Close)
	c := New(server.URL, "operator", "synthetic-credential")
	c.httpClient = server.Client()
	if token, err := c.fetchToken(context.Background()); token != "" || !errors.Is(err, ErrResponseTooLarge) || c.token != "" {
		t.Fatalf("compressed response bypassed credential budget: %v", err)
	}
}
