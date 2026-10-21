package httpsecurity

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

type forbiddenTransport struct{}

func (forbiddenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("unverifiable transport must never be used")
}

func TestHTTPSBindingRejectsUnsafeConfigurationAndPreservesCaller(t *testing.T) {
	for _, endpoint := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test?token=value", "https://example.test#fragment", "https://", "%"} {
		if _, err := RequireHTTPS(&http.Client{}, endpoint); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	if _, err := RequireHTTPS(&http.Client{Transport: forbiddenTransport{}}, "https://example.test"); err == nil {
		t.Fatal("unverifiable transport accepted")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "original.test"}}
	secured, err := RequireHTTPS(&http.Client{Transport: transport}, "https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "original.test" || transport.Proxy == nil {
		t.Fatal("binding mutated the caller transport")
	}
	bound := secured.Transport.(originTransport)
	if bound.next.(*http.Transport).TLSClientConfig.MinVersion != tls.VersionTLS13 || bound.next.(*http.Transport).Proxy != nil {
		t.Fatal("binding retained an ambient proxy or obsolete TLS")
	}
	_, err = bound.RoundTrip(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.test"}, Host: "other.test"})
	if err == nil {
		t.Fatal("conflicting HTTP Host escaped origin binding")
	}
	// A custom protocol map disables net/http's automatic TLS configuration.
	custom := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	secured, err = RequireHTTPS(&http.Client{Transport: custom}, "https://example.test")
	if err != nil || secured.Transport.(originTransport).next.(*http.Transport).TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("custom transport was not bound to TLS 1.3")
	}
}

func TestEnterpriseTLSClientRejectsRedirectsAndOtherOrigins(t *testing.T) {
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		leaked.Add(1)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("approved endpoint did not receive its credential")
		}
		http.Redirect(w, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	base := source.Client()
	secured, err := RequireHTTPS(base, source.URL)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, source.URL+"/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer fixture")
	response, err := secured.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || leaked.Load() != 0 {
		t.Fatal("enterprise credential followed a redirect")
	}
	request, err = http.NewRequest(http.MethodPost, destination.URL+"/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := secured.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("enterprise client dispatched an unapproved origin")
	}
	if leaked.Load() != 0 {
		t.Fatal("enterprise client leaked traffic")
	}
}

func TestEnterpriseClientRejectsUntrustedPeersAndTLS12(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted or obsolete TLS connection reached the handler")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12} //nolint:gosec // Deliberately obsolete peer: enterprise clients must reject it.
	server.StartTLS()
	t.Cleanup(server.Close)
	for _, base := range []*http.Client{server.Client(), {}} {
		secured, err := RequireHTTPS(base, server.URL)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := secured.Get(server.URL + "/token"); err == nil {
			_ = response.Body.Close()
			t.Fatal("enterprise client accepted TLS 1.2")
		}
	}
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted server reached the handler")
	}))
	t.Cleanup(untrusted.Close)
	secured, err := RequireHTTPS(&http.Client{}, untrusted.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := secured.Get(untrusted.URL + "/token"); err == nil {
		_ = response.Body.Close()
		t.Fatal("enterprise client accepted an untrusted server certificate")
	}
}
