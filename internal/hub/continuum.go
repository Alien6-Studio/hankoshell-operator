package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContinuumPolicy binds enterprise synchronization to one reviewed private
// relay. It does not establish a tunnel or assert workload-mesh enforcement.
type ContinuumPolicy struct {
	endpoint           *url.URL
	address            netip.Addr
	enrollmentEndpoint *url.URL
}

// NewContinuumPolicy accepts an HTTPS relay origin and a private unicast IP.
// Enrollment is optional and uses a separately approved HTTPS endpoint.
func NewContinuumPolicy(endpoint, address, enrollmentEndpoint string) (*ContinuumPolicy, error) {
	u, err := approvedEndpoint(endpoint)
	if err != nil || (u != nil && u.Path != "") {
		return nil, fmt.Errorf("enterprise Hub endpoint must be an HTTPS origin without a path")
	}
	ip, err := netip.ParseAddr(address)
	shared := netip.MustParsePrefix("100.64.0.0/10")
	if err != nil || (!ip.IsPrivate() && !shared.Contains(ip)) || ip.Is4In6() {
		return nil, fmt.Errorf("enterprise Continuum relay must have a private unicast IP address")
	}
	for _, metadata := range []string{"100.100.100.200", "fd00:ec2::254"} {
		if ip == netip.MustParseAddr(metadata) {
			return nil, fmt.Errorf("enterprise Continuum relay must not target a cloud metadata endpoint")
		}
	}
	policy := &ContinuumPolicy{endpoint: u, address: ip}
	if enrollmentEndpoint != "" {
		policy.enrollmentEndpoint, err = approvedEndpoint(enrollmentEndpoint)
		if err != nil {
			return nil, fmt.Errorf("enterprise enrollment endpoint must be an explicit HTTPS URL")
		}
	}
	return policy, nil
}

// Validate rejects CRD changes that would switch transport or destination.
func (p *ContinuumPolicy) Validate(endpoint, transport, enrollmentEndpoint string, enrolling bool) error {
	u, err := approvedEndpoint(endpoint)
	if transport != "continuum" || err != nil || u.String() != p.endpoint.String() {
		return fmt.Errorf("enterprise synchronization requires the configured Continuum Hub endpoint and transport")
	}
	if enrollmentEndpoint != "" || enrolling {
		bootstrap, parseErr := approvedEndpoint(enrollmentEndpoint)
		if parseErr != nil || p.enrollmentEndpoint == nil || bootstrap.String() != p.enrollmentEndpoint.String() {
			return fmt.Errorf("enterprise enrollment requires the separately configured HTTPS endpoint")
		}
	}
	return nil
}

// HTTPClient verifies the Hub certificate and dials only the configured relay
// IP. Environment proxies, DNS changes and redirects cannot create a public
// synchronization path. The TLS name remains the reviewed Hub hostname.
func (p *ContinuumPolicy) HTTPClient(caFile string) (*http.Client, error) {
	c, err := NewHTTPClient(caFile)
	if err != nil {
		return nil, err
	}
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("enterprise Hub client requires a standard TLS transport")
	}
	transport.Proxy = nil
	transport.DialTLSContext = nil
	transport.TLSClientConfig.InsecureSkipVerify = false
	transport.TLSClientConfig.ServerName = p.endpoint.Hostname()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	port := p.endpoint.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	relay := net.JoinHostPort(p.address.String(), port)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, relay)
	}
	return bindClient(c, p.endpoint), nil
}

// Enroll uses system roots independently of the private synchronization CA.
// A failed exchange never retries against the private or another public URL.
func (p *ContinuumPolicy) Enroll(ctx context.Context, token string, identity EnrollmentIdentity) (*EnrollResult, error) {
	if p.enrollmentEndpoint == nil {
		return nil, fmt.Errorf("enterprise enrollment endpoint is not configured")
	}
	c, err := NewHTTPClient("")
	if err != nil {
		return nil, err
	}
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("enterprise enrollment client requires a standard TLS transport")
	}
	transport.Proxy = nil
	transport.TLSClientConfig.InsecureSkipVerify = false
	transport.TLSClientConfig.ServerName = ""
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	return enrollWithClient(ctx, p.enrollmentEndpoint.String(), token, identity, bindClient(c, p.enrollmentEndpoint))
}

func approvedEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return nil, fmt.Errorf("endpoint must be a plain HTTPS URL")
	}
	if port := u.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("endpoint has an invalid port")
		}
	}
	if err := validateEndpointPath(u.Path); err != nil {
		return nil, err
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func validateEndpointPath(path string) error {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("endpoint path must not contain traversal")
		}
	}
	return nil
}

type boundTransport struct {
	next     http.RoundTripper
	endpoint *url.URL
}

func (t boundTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != t.endpoint.Scheme || !strings.EqualFold(request.URL.Host, t.endpoint.Host) ||
		(request.Host != "" && !strings.EqualFold(request.Host, t.endpoint.Host)) || request.URL.User != nil ||
		!strings.HasPrefix(request.URL.Path, t.endpoint.Path+"/") {
		return nil, fmt.Errorf("request is outside the approved enterprise endpoint")
	}
	return t.next.RoundTrip(request)
}

func bindClient(c *http.Client, endpoint *url.URL) *http.Client {
	c.Transport = boundTransport{next: c.Transport, endpoint: endpoint}
	c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("enterprise HTTP redirects are disabled")
	}
	return c
}
