package hub

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const enterpriseEndpoint = "https://hub.mesh.example:9443"

func TestContinuumPolicyRejectsUnapprovedDestinations(t *testing.T) {
	for _, test := range []struct{ endpoint, address, enrollment string }{
		{"http://hub.mesh.example", "10.250.0.1", ""},
		{enterpriseEndpoint + "/hub", "10.250.0.1", ""},
		{enterpriseEndpoint + "?token=fixture", "10.250.0.1", ""},
		{"https://user:fixture@hub.mesh.example:9443", "10.250.0.1", ""},
		{"https://hub.mesh.example:65536", "10.250.0.1", ""},
		{enterpriseEndpoint, "192.0.2.1", ""},
		{enterpriseEndpoint, "127.0.0.1", ""},
		{enterpriseEndpoint, "169.254.169.254", ""},
		{enterpriseEndpoint, "100.100.100.200", ""},
		{enterpriseEndpoint, "fd00:ec2::254", ""},
		{enterpriseEndpoint, "10.250.0.0/24", ""},
		{enterpriseEndpoint, "::ffff:10.250.0.1", ""},
		{enterpriseEndpoint, "10.250.0.1", "http://enroll.example"},
		{enterpriseEndpoint, "10.250.0.1", "https://enroll.example/hub/../other"},
	} {
		if _, err := NewContinuumPolicy(test.endpoint, test.address, test.enrollment); err == nil {
			t.Errorf("accepted unapproved transport configuration: %#v", test)
		}
	}
	for _, address := range []string{"10.250.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "fd00::1"} {
		if _, err := NewContinuumPolicy(enterpriseEndpoint, address, ""); err != nil {
			t.Errorf("rejected private relay %s: %v", address, err)
		}
	}
}

func TestContinuumPolicyRejectsCRDTransportAndBootstrapChanges(t *testing.T) {
	const enrollment = "https://enroll.example/hub"
	policy, err := NewContinuumPolicy(enterpriseEndpoint, "10.250.0.1", enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(enterpriseEndpoint+"/", "continuum", enrollment, true); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ endpoint, transport, enrollment string }{
		{enterpriseEndpoint, "direct", enrollment},
		{enterpriseEndpoint, "", enrollment},
		{"https://public.example", "continuum", enrollment},
		{enterpriseEndpoint, "continuum", "https://other.example/hub"},
		{enterpriseEndpoint, "continuum", ""},
	} {
		if err := policy.Validate(test.endpoint, test.transport, test.enrollment, true); err == nil {
			t.Errorf("accepted CRD change: %#v", test)
		}
	}
	withoutBootstrap, err := NewContinuumPolicy(enterpriseEndpoint, "10.250.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutBootstrap.Enroll(context.Background(), "fixture", EnrollmentIdentity{}); err == nil {
		t.Fatal("enterprise enrollment must not fall back to the synchronization endpoint")
	}
}

func TestContinuumHTTPClientPreservesTLSAndRejectsRedirects(t *testing.T) {
	policy, err := NewContinuumPolicy(enterpriseEndpoint, "10.250.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.HTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	transport := c.Transport.(boundTransport).next.(*http.Transport)
	if transport.Proxy != nil || transport.DialContext == nil || transport.DialTLSContext != nil ||
		transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.ServerName != "hub.mesh.example" {
		t.Fatal("private relay must keep TLS authentication and disable proxy and DNS routing")
	}
	redirect, err := http.NewRequest(http.MethodGet, "https://public.example/api/v1/bundles/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(redirect, nil); err == nil {
		t.Fatal("enterprise synchronization must reject redirects")
	}
}

func TestEnterpriseBoundClientRejectsLeakageBeforeDispatch(t *testing.T) {
	endpoint, err := url.Parse(enterpriseEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	dispatched := 0
	c := bindClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		dispatched++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}, endpoint)
	for _, target := range []string{
		"http://hub.mesh.example:9443/api/v1/operators/status",
		"https://public.example/api/v1/operators/status",
		"https://hub.mesh.example:443/api/v1/operators/status",
	} {
		request, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer fixture")
		if response, err := c.Do(request); err == nil {
			_ = response.Body.Close()
			t.Errorf("dispatched unapproved destination: %s", target)
		}
	}
	if dispatched != 0 {
		t.Fatal("credentials reached an unapproved transport")
	}
	request, err := http.NewRequest(http.MethodGet, enterpriseEndpoint+"/api/v1/bundles/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if dispatched != 1 {
		t.Fatal("approved destination was not dispatched")
	}
}
