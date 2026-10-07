package keycloak

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEndpointContract(t *testing.T) {
	data, err := os.ReadFile("testdata/endpoints.json")
	if err != nil {
		t.Fatal(err)
	}
	var endpoints []struct {
		URL   string `json:"url"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal(data, &endpoints); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		for _, allow := range []bool{false, true} {
			want := endpoint.Valid && (allow || strings.HasPrefix(endpoint.URL, "https://"))
			if err := ValidateEndpoint(endpoint.URL, allow); (err == nil) != want {
				t.Errorf("endpoint %q allow=%v: %v", endpoint.URL, allow, err)
			}
			var options []ClientOption
			if allow {
				options = append(options, WithInsecureHTTP())
			}
			if client := New(endpoint.URL, "operator", "fixture", options...); (client.endpointError == nil) != want {
				t.Errorf("constructor normalized unsafe endpoint %q", endpoint.URL)
			}
		}
	}
}

func TestHTTPDefaultCannotSendAdministrativeCredentials(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_ = request.ParseForm()
			if request.Form.Get("client_secret") != "sensitive-fixture" {
				t.Error("token request omitted credentials")
			}
			_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":60}`))
			return
		}
		_, _ = w.Write([]byte(`{"systemInfo":{"version":"26.8.0"}}`))
	}))
	t.Cleanup(server.Close)
	if _, err := New(server.URL, "operator", "sensitive-fixture").ServerVersion(context.Background()); err == nil || requests.Load() != 0 {
		t.Fatal("default client dispatched administrative credentials over HTTP")
	}
	client := New(server.URL, "operator", "sensitive-fixture", WithInsecureHTTP())
	if version, err := client.ServerVersion(context.Background()); err != nil || version != "26.8.0" || requests.Load() != 2 {
		t.Fatalf("acknowledged HTTP fixture failed: version=%q err=%v requests=%d", version, err, requests.Load())
	}
	if err := client.RequireHTTPS(); err == nil {
		t.Fatal("HTTP option bypassed enterprise HTTPS requirement")
	}
}

func TestOperatorTransportOptInAndEnterprisePrecedence(t *testing.T) {
	t.Setenv("HANKO_KC_CLIENT_ID", "operator")
	t.Setenv("HANKO_KC_CLIENT_SECRET", "fixture")
	t.Setenv("HANKO_KEYCLOAK_URL", "http://iam.auth.svc:8080")
	t.Setenv("HANKO_KEYCLOAK_CA_FILE", "")
	for _, profile := range []string{"standard", "enterprise"} {
		t.Setenv("HANKO_SECURITY_PROFILE", profile)
		for _, flag := range []string{"", "false", "true", "TRUE", "1", "yes"} {
			t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", flag)
			want := profile == "standard" && flag == "true"
			if _, err := NewFromEnv(); (err == nil) != want {
				t.Errorf("profile=%s flag=%q: %v", profile, flag, err)
			}
		}
	}
	t.Setenv("HANKO_SECURITY_PROFILE", "standard")
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	if _, err := NewForOperator("http://iam.auth.svc", "operator", "fixture", []byte("CA")); err == nil {
		t.Fatal("private CA option accepted HTTP")
	}
}

func TestHTTPSUsesVerifiedSystemTrustWithoutCASecret(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "false")
	t.Setenv("HANKO_SECURITY_PROFILE", "standard")
	t.Setenv("HANKO_KEYCLOAK_CA_FILE", "")
	t.Setenv("HANKO_KEYCLOAK_URL", "https://iam.example.com")
	t.Setenv("HANKO_KC_CLIENT_ID", "operator")
	t.Setenv("HANKO_KC_CLIENT_SECRET", "fixture")
	client, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	transport := client.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.RootCAs != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("HTTPS without a CA Secret must use verified system trust and TLS >=1.2")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted HTTPS endpoint received credentials")
	}))
	t.Cleanup(server.Close)
	for _, options := range [][]ClientOption{nil, {WithInsecureHTTP()}} {
		if _, err := New(server.URL, "operator", "fixture", options...).ServerVersion(context.Background()); err == nil {
			t.Fatal("compatibility option disabled HTTPS certificate verification")
		}
	}
}

func TestUnsafeEndpointErrorsDoNotDiscloseURLCredentials(t *testing.T) {
	endpoint := "https://sensitive-user:sensitive-password@iam.example.com#sensitive-fragment"
	if _, err := New(endpoint, "operator", "fixture").ServerVersion(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive-") {
		t.Fatal("unsafe endpoint was accepted or disclosed URL credentials")
	}
	if _, err := NewWithTLS(endpoint, "operator", "fixture", nil); err == nil || strings.Contains(err.Error(), "sensitive-") {
		t.Fatal("private CA constructor accepted or disclosed an unsafe endpoint")
	}
}
