package keycloak

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ClientOption configures a Keycloak client before it is used.
type ClientOption func(*Client)

// WithInsecureHTTP explicitly permits plaintext HTTP in a trusted environment.
// It does not disable certificate verification for HTTPS connections.
func WithInsecureHTTP() ClientOption {
	return func(c *Client) { c.allowInsecureHTTP = true }
}

// Endpoint grammar is shared with the Helm validation helper. Only an origin
// and an optional unescaped context path are supported, never URL credentials,
// queries, fragments, ambiguous separators or path traversal.
const endpointHost = `[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?`
const endpointIPv6 = `([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|:(:[0-9A-Fa-f]{1,4}){1,7}|::`

var endpointPattern = regexp.MustCompile(`^https?://(` + endpointHost + `|\[(` + endpointIPv6 + `)\])(:[0-9]+)?(/[A-Za-z0-9._~-]+)*/?$`)

// ValidateEndpoint rejects unsafe administrative endpoints without including
// their contents in errors, since a rejected URL may contain credentials.
func ValidateEndpoint(endpoint string, allowInsecureHTTP bool) error {
	if !endpointPattern.MatchString(endpoint) {
		return fmt.Errorf("keycloak endpoint must be an HTTP(S) origin with an optional plain context path, without userinfo, query or fragment")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid Keycloak endpoint")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("keycloak endpoint port must be between 1 and 65535")
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("keycloak endpoint context path must not contain dot segments")
		}
	}
	if u.Scheme == "http" && !allowInsecureHTTP {
		return fmt.Errorf("keycloak administrative HTTP requires explicit HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP=true; use verified HTTPS")
	}
	return nil
}

// NewForOperator applies the administrator-owned compatibility setting to every
// operator connection, including instance credentials, rotation and tenants.
// Enterprise never permits HTTP. A CA bundle always requires HTTPS.
func NewForOperator(baseURL, clientID, clientSecret string, caPEM []byte) (*Client, error) {
	flag := os.Getenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP")
	if flag != "" && flag != "true" && flag != "false" {
		return nil, fmt.Errorf("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP must be true or false")
	}
	allow := flag == "true" && os.Getenv("HANKO_SECURITY_PROFILE") != "enterprise"
	if err := ValidateEndpoint(baseURL, allow); err != nil {
		return nil, err
	}
	if caPEM != nil {
		return NewWithTLS(baseURL, clientID, clientSecret, caPEM)
	}
	if allow {
		return New(baseURL, clientID, clientSecret, WithInsecureHTTP()), nil
	}
	return New(baseURL, clientID, clientSecret), nil
}
