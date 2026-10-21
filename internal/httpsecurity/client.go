// Package httpsecurity constrains enterprise HTTP clients before credentials
// can be sent. It has no provider or Kubernetes dependencies.
package httpsecurity

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RequireHTTPS clones a standard HTTP client, preserves its CA roots and
// private dialer, and binds requests to an authenticated TLS 1.3 origin.
func RequireHTTPS(c *http.Client, endpoint string) (*http.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("enterprise integration requires a plain HTTPS endpoint")
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("enterprise integration requires a verifiable TLS transport")
	}
	transport = transport.Clone()
	transport.Proxy = nil
	transport.DialTLSContext = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	transport.TLSClientConfig.InsecureSkipVerify = false
	transport.TLSClientConfig.ServerName = u.Hostname()
	secured := *c
	secured.Transport = originTransport{next: transport, host: u.Host}
	secured.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("enterprise HTTP redirects are disabled")
	}
	return &secured, nil
}

type originTransport struct {
	next http.RoundTripper
	host string
}

func (t originTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Host, t.host) || request.URL.User != nil ||
		(request.Host != "" && !strings.EqualFold(request.Host, t.host)) {
		return nil, fmt.Errorf("request is outside the approved enterprise HTTPS origin")
	}
	return t.next.RoundTrip(request)
}
