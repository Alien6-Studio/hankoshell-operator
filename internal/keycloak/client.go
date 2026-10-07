// Package keycloak provides a Keycloak Admin REST client used by the operator
// reconcilers. Only client_credentials flow is supported — no password grant.
package keycloak

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

const (
	adminRealmsPath                = "/admin/realms/"
	masterClientsPath              = "/admin/realms/master/clients/"
	clientsPath                    = "/clients/"
	rolesPath                      = "/roles"
	rolesSegment                   = "/roles/"
	clientSecretPath               = "/client-secret"
	authorizationScopePath         = "/scope"
	authorizationResourcePath      = "/resource"
	authorizationPolicyPath        = "/policy"
	authorizationPermissionPath    = "/permission"
	authorizationHeader            = "Authorization"
	contentTypeHeader              = "Content-Type"
	forwardedProtoHeader           = "X-Forwarded-Proto"
	bearerPrefix                   = "Bearer "
	jsonMediaType                  = "application/json"
	httpsScheme                    = "https"
	openIDConnectProtocol          = "openid-connect"
	keycloakPathErrorFormat        = "keycloak %s %d: %s"
	keycloakErrorFormat            = "keycloak %d: %s"
	clientNotFoundFormat           = "client %q not found in realm %q"
	postLogoutRedirectURIAttribute = "post.logout.redirect.uris"
	hankoAppAttribute              = "hanko.app"
	hankoServiceAttribute          = "hanko.service"
)

// Client is a Keycloak Admin REST client with automatic token refresh.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string

	httpClient  *http.Client
	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// New creates a Client with explicit credentials. Equivalent to NewFromEnv but
// sourced programmatically (e.g. from a Kubernetes Secret).
func New(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// RequireHTTPS constrains a newly constructed enterprise client before use.
// Call it before registering the client in a pool or starting reconciliation.
func (c *Client) RequireHTTPS() error {
	secured, err := httpsecurity.RequireHTTPS(c.httpClient, c.baseURL)
	if err != nil {
		return err
	}
	c.httpClient = secured
	return nil
}

// NewWithTLS creates a Client that verifies the Keycloak Admin API TLS certificate
// against the provided PEM-encoded CA bundle. Use when Keycloak is exposed on HTTPS
// (KC_HTTPS_*) and a custom or self-signed CA is in use.
func NewWithTLS(baseURL, clientID, clientSecret string, caPEM []byte) (*Client, error) {
	endpoint, err := url.Parse(baseURL)
	if err != nil || endpoint.Scheme != httpsScheme || endpoint.Host == "" {
		return nil, fmt.Errorf("keycloak: a custom CA requires an HTTPS URL")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("keycloak: no valid PEM certificates found in CA bundle")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 10 * time.Second, Transport: transport},
	}, nil
}

// NewFromEnv creates a Client from the standard hankoShell Keycloak env vars.
// Requires client_credentials: HANKO_KC_CLIENT_ID and HANKO_KC_CLIENT_SECRET.
func NewFromEnv() (*Client, error) {
	base := os.Getenv("HANKO_KEYCLOAK_URL")
	if base == "" {
		return nil, fmt.Errorf("HANKO_KEYCLOAK_URL is required")
	}
	clientID := os.Getenv("HANKO_KC_CLIENT_ID")
	clientSecret := os.Getenv("HANKO_KC_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("HANKO_KC_CLIENT_ID and HANKO_KC_CLIENT_SECRET are required")
	}
	if caFile := os.Getenv("HANKO_KEYCLOAK_CA_FILE"); caFile != "" {
		caPEM, err := readCAFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read Keycloak CA bundle: %w", err)
		}
		return NewWithTLS(base, clientID, clientSecret, caPEM)
	}
	return New(base, clientID, clientSecret), nil
}

// readCAFile confines projected Secret symlinks to the configured directory.
func readCAFile(caFile string) ([]byte, error) {
	if !filepath.IsAbs(caFile) || filepath.Clean(caFile) != caFile {
		return nil, fmt.Errorf("keycloak CA file must be a clean absolute path")
	}
	root, err := os.OpenRoot(filepath.Dir(caFile))
	if err != nil {
		return nil, fmt.Errorf("open Keycloak CA directory: %w", err)
	}
	defer root.Close()
	data, err := root.ReadFile(filepath.Base(caFile))
	if err != nil {
		return nil, fmt.Errorf("read Keycloak CA file: %w", err)
	}
	return data, nil
}

// Realm is the minimal Keycloak realm representation used by reconcilers.
type Realm struct {
	// ID is the Keycloak internal UUID for the realm.
	// Do NOT use this as the URL path segment — Keycloak Admin API paths use
	// the realm name, not the UUID.
	ID string `json:"id"`
	// RealmName is the URL-addressable realm identifier used in Admin API paths
	// (e.g. "alien6"). Maps to the JSON "realm" field returned by Keycloak.
	RealmName   string            `json:"realm"`
	DisplayName string            `json:"displayName"`
	Enabled     bool              `json:"enabled"`
	LoginTheme  string            `json:"loginTheme"`
	Attributes  map[string]string `json:"attributes"`
	SMTPServer  map[string]string `json:"smtpServer"`
}

// URLName returns the identifier to use in Keycloak Admin API URL paths.
// Keycloak returns the UUID in "id" but expects the realm name in URLs.
// Falls back to ID when RealmName is empty (e.g. master realm which has id="master").
func (r Realm) URLName() string {
	if r.RealmName != "" {
		return r.RealmName
	}
	return r.ID
}

// App is the minimal Keycloak client representation used by reconcilers.
type App struct {
	ClientID               string   `json:"clientId"`
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	Protocol               string   `json:"protocol"`
	PublicClient           bool     `json:"publicClient"`
	ServiceAccountsEnabled bool     `json:"serviceAccountsEnabled"`
	StandardFlowEnabled    bool     `json:"standardFlowEnabled"`
	RedirectURIs           []string `json:"redirectUris"`
}

// BaseURL returns the configured Keycloak base URL (used to derive OIDC endpoints).
func (c *Client) BaseURL() string { return c.baseURL }

// CredentialClientID returns the client whose credentials authorize this Admin
// API connection. Reconcilers use it to prevent a managed service account from
// rotating or deleting the very client that authorizes the operator.
func (c *Client) CredentialClientID() string { return c.clientID }

// IsNotFound reports whether err came from a Keycloak 404 response.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), " 404: ")
}

// IsForbidden reports whether err came from a Keycloak 403 response.
func IsForbidden(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), " 403: ")
}

// ListRealms returns all realms available in this Keycloak instance.
func (c *Client) ListRealms(ctx context.Context) ([]Realm, error) {
	var realms []Realm
	if err := c.get(ctx, "/admin/realms", &realms); err != nil {
		return nil, fmt.Errorf("list realms: %w", err)
	}
	return realms, nil
}

// GetRealm fetches the realm representation from Keycloak.
func (c *Client) GetRealm(ctx context.Context, realm string) (*Realm, error) {
	var r Realm
	if err := c.get(ctx, adminRealmsPath+realm, &r); err != nil {
		return nil, fmt.Errorf("get realm %q: %w", realm, err)
	}
	return &r, nil
}

// RealmSpec holds the fields needed to create or update a Keycloak realm.
type RealmSpec struct {
	ID          string
	DisplayName string
	FrontendURL string
	LoginTheme  string
	Enabled     bool

	// Security profile fields (applied via UpdateRealm)
	BruteForceProtected   bool
	FailureFactor         int    // max login failures before lockout
	WaitIncrementSeconds  int    // lockout duration in seconds
	SSOSessionMaxLifespan int    // max SSO session lifetime in seconds
	SSOSessionIdleTimeout int    // max inactive SSO session duration in seconds
	PasswordPolicy        string // e.g. "length(12)"
	OTPRequired           bool   // adds OTP as required action for all users (legacy, prefer MFAPolicy)
	MFAPolicy             string // "none", "optional", "required"

	// SSLRequired enforces TLS on the realm: "none", "external" (default), "all".
	SSLRequired string
	// RevokeRefreshToken invalidates refresh tokens after use.
	RevokeRefreshToken bool
	// RefreshTokenMaxReuse is the number of reuses allowed when RevokeRefreshToken is true.
	RefreshTokenMaxReuse int
	// OTPAlgorithm is the TOTP hash algorithm: HmacSHA1, HmacSHA256, HmacSHA512.
	OTPAlgorithm string
	OTPDigits    int
	OTPPeriod    int

	VerifyEmail               *bool
	RememberMe                *bool
	RegistrationAllowed       *bool
	EventsEnabled             *bool
	AdminEventsEnabled        *bool
	AuditRetentionDays        *int
	AuditExportEnabled        *bool
	AdminConsoleExposure      string
	IDPBrokerRequireSignature *bool
	IDPBrokerTrustEmail       *bool
}

var realmManagementRoles = []string{
	"create-client",
	"impersonation",
	"manage-authorization",
	"manage-clients",
	"manage-events",
	"manage-identity-providers",
	"manage-realm",
	"manage-users",
	"query-clients",
	"query-groups",
	"query-realms",
	"query-users",
	"view-authorization",
	"view-clients",
	"view-events",
	"view-identity-providers",
	"view-realm",
	"view-users",
}

type realmManagementClient struct {
	ID                     string            `json:"id"`
	ClientID               string            `json:"clientId"`
	Enabled                bool              `json:"enabled"`
	BearerOnly             bool              `json:"bearerOnly"`
	PublicClient           bool              `json:"publicClient"`
	ServiceAccountsEnabled bool              `json:"serviceAccountsEnabled"`
	FullScopeAllowed       bool              `json:"fullScopeAllowed"`
	Protocol               string            `json:"protocol"`
	Attributes             map[string]string `json:"attributes"`
}

// CreateRealm creates a new realm in Keycloak with all RealmRepresentation security fields.
// Required-action defaults are reconciled by UpdateRealm after management access is ready.
func (c *Client) CreateRealm(ctx context.Context, spec RealmSpec) error {
	payload := createRealmPayload(spec)
	b, _ := json.Marshal(payload)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/admin/realms", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("create realm %q: keycloak %d: %s", spec.ID, resp.StatusCode, body)
}

func createRealmPayload(spec RealmSpec) map[string]any {
	payload := map[string]any{
		"realm":                spec.ID,
		"displayName":          spec.DisplayName,
		"loginTheme":           spec.LoginTheme,
		"enabled":              spec.Enabled,
		"sslRequired":          stringDefault(spec.SSLRequired, "external"),
		"revokeRefreshToken":   spec.RevokeRefreshToken,
		"refreshTokenMaxReuse": spec.RefreshTokenMaxReuse,
	}
	if spec.FrontendURL != "" {
		payload["attributes"] = map[string]string{"frontendUrl": spec.FrontendURL}
	}
	applyRealmBruteForce(payload, spec)
	if spec.PasswordPolicy != "" {
		payload["passwordPolicy"] = spec.PasswordPolicy
	}
	applyOptionalRealmBooleans(payload, spec)
	applyRealmMFA(payload, spec)
	return payload
}

// UpdateRealm applies spec settings to an existing realm via PUT.
// Only non-zero values are included in the payload to avoid overwriting
// Keycloak defaults for fields not managed by the operator.
func (c *Client) UpdateRealm(ctx context.Context, realmID string, spec RealmSpec) error {
	payload, err := c.updateRealmPayload(ctx, realmID, spec)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(payload)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+adminRealmsPath+realmID, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update realm %q: keycloak %d: %s", realmID, resp.StatusCode, body)
	}
	if spec.MFAPolicy != "" {
		return c.setRequiredActionDefault(ctx, realmID, "CONFIGURE_TOTP", spec.MFAPolicy == "required")
	}
	return nil
}

// LogoutAllRealmSessions invalidates every active SSO session in a realm. The
// operator uses it after an IAM profile raises the required assurance level so
// sessions created under the weaker policy cannot remain active.
func (c *Client) LogoutAllRealmSessions(ctx context.Context, realm string) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	path := adminRealmsPath + url.PathEscape(realm) + "/logout-all"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("logout all sessions in realm %q: keycloak %d: %s", realm, resp.StatusCode, body)
}

func (c *Client) updateRealmPayload(ctx context.Context, realmID string, spec RealmSpec) (map[string]any, error) {
	payload := map[string]any{
		"displayName":          spec.DisplayName,
		"loginTheme":           spec.LoginTheme,
		"enabled":              true,
		"sslRequired":          stringDefault(spec.SSLRequired, "external"),
		"revokeRefreshToken":   spec.RevokeRefreshToken,
		"refreshTokenMaxReuse": spec.RefreshTokenMaxReuse,
		// Brute-force detection window and quick-login throttle — always enforced on update.
		"maxDeltaTimeSeconds":          43200,
		"minimumQuickLoginWaitSeconds": 60,
		// Offline session idle timeout (30 days) — set on update to survive realm recreation.
		"offlineSessionIdleTimeout": 2592000,
	}
	attributes, err := c.realmFrontendAttributes(ctx, realmID, spec.FrontendURL)
	if err != nil {
		return nil, err
	}
	if attributes != nil {
		payload["attributes"] = attributes
	}
	applyRealmBruteForce(payload, spec)
	applyRealmSessionTimeouts(payload, spec)
	if spec.PasswordPolicy != "" {
		payload["passwordPolicy"] = spec.PasswordPolicy
	}
	applyOptionalRealmBooleans(payload, spec)
	applyRealmMFA(payload, spec)
	return payload, nil
}

func (c *Client) realmFrontendAttributes(ctx context.Context, realmID, frontendURL string) (map[string]string, error) {
	if frontendURL == "" {
		return nil, nil
	}
	current, err := c.GetRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("read realm before security update: %w", err)
	}
	attributes := make(map[string]string, len(current.Attributes)+1)
	for key, value := range current.Attributes {
		attributes[key] = value
	}
	attributes["frontendUrl"] = frontendURL
	return attributes, nil
}

func applyRealmBruteForce(payload map[string]any, spec RealmSpec) {
	if !spec.BruteForceProtected {
		return
	}
	payload["bruteForceProtected"] = true
	if spec.FailureFactor > 0 {
		payload["failureFactor"] = spec.FailureFactor
	}
	if spec.WaitIncrementSeconds > 0 {
		payload["waitIncrementSeconds"] = spec.WaitIncrementSeconds
		payload["maxFailureWaitSeconds"] = spec.WaitIncrementSeconds
	}
}

func applyRealmSessionTimeouts(payload map[string]any, spec RealmSpec) {
	if spec.SSOSessionMaxLifespan > 0 {
		payload["ssoSessionMaxLifespan"] = spec.SSOSessionMaxLifespan
	}
	if spec.SSOSessionIdleTimeout > 0 {
		payload["ssoSessionIdleTimeout"] = spec.SSOSessionIdleTimeout
	}
}

func applyRealmMFA(payload map[string]any, spec RealmSpec) {
	otpAlgorithm := stringDefault(spec.OTPAlgorithm, "HmacSHA1")
	switch spec.MFAPolicy {
	case "required", "optional":
		payload["otpPolicyType"] = "totp"
		payload["otpPolicyAlgorithm"] = otpAlgorithm
		payload["otpPolicyDigits"] = intDefault(spec.OTPDigits, 6)
		payload["otpPolicyPeriod"] = intDefault(spec.OTPPeriod, 30)
	}
}

func applyOptionalRealmBooleans(payload map[string]any, spec RealmSpec) {
	if spec.VerifyEmail != nil {
		payload["verifyEmail"] = *spec.VerifyEmail
	}
	if spec.RememberMe != nil {
		payload["rememberMe"] = *spec.RememberMe
	}
	if spec.RegistrationAllowed != nil {
		payload["registrationAllowed"] = *spec.RegistrationAllowed
	}
	if spec.EventsEnabled != nil {
		payload["eventsEnabled"] = *spec.EventsEnabled
	}
	if spec.AdminEventsEnabled != nil {
		payload["adminEventsEnabled"] = *spec.AdminEventsEnabled
	}
}

type requiredActionProvider struct {
	Alias         string            `json:"alias"`
	Name          string            `json:"name"`
	ProviderID    string            `json:"providerId"`
	Enabled       bool              `json:"enabled"`
	DefaultAction bool              `json:"defaultAction"`
	Priority      int               `json:"priority"`
	Config        map[string]string `json:"config,omitempty"`
}

// setRequiredActionDefault uses Keycloak's dedicated required-actions API.
// RealmRepresentation does not accept a defaultRequiredActions field on
// Keycloak 26.x, so MFA enrolment must be configured on the provider itself.
func (c *Client) setRequiredActionDefault(ctx context.Context, realmID, alias string, enabled bool) error {
	path := adminRealmsPath + url.PathEscape(realmID) +
		"/authentication/required-actions/" + url.PathEscape(alias)
	var action requiredActionProvider
	if err := c.get(ctx, path, &action); err != nil {
		return fmt.Errorf("get required action %q for realm %q: %w", alias, realmID, err)
	}
	if action.DefaultAction == enabled && (!enabled || action.Enabled) {
		return nil
	}
	action.DefaultAction = enabled
	if enabled {
		action.Enabled = true
	}
	body, err := json.Marshal(action)
	if err != nil {
		return fmt.Errorf("marshal required action %q for realm %q: %w", alias, realmID, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update required action %q for realm %q: keycloak %d: %s", alias, realmID, resp.StatusCode, responseBody)
	}
	return nil
}

func intDefault(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func stringDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// DeleteRealm deletes a realm from Keycloak. Returns nil if the realm does not exist.
func (c *Client) DeleteRealm(ctx context.Context, realmID string) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realmID, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete realm %q: keycloak %d: %s", realmID, resp.StatusCode, body)
}

// EnsureRealmManagementAccess creates the master-realm proxy used to administer
// realmID and grants its standard administration roles directly to this client's
// service account. Existing proxy settings and unrelated role mappings are never
// overwritten. The cached access token is refreshed after adding mappings so the
// new realm permissions are immediately usable.
func (c *Client) EnsureRealmManagementAccess(ctx context.Context, realmID string) error {
	if err := validateManagedRealmID(realmID); err != nil {
		return err
	}
	proxyUUID, proxyClientID, err := c.resolveRealmManagementProxy(ctx, realmID)
	if err != nil {
		return err
	}
	if err := c.validateRealmManagementClient(ctx, proxyUUID, proxyClientID); err != nil {
		return err
	}
	rolesByName, err := c.ensureRealmManagementRoles(ctx, proxyUUID, proxyClientID)
	if err != nil {
		return err
	}
	serviceAccountID, err := c.operatorServiceAccountID(ctx)
	if err != nil {
		return err
	}
	mappingsPath := "/admin/realms/master/users/" + url.PathEscape(serviceAccountID) +
		"/role-mappings/clients/" + url.PathEscape(proxyUUID)
	missingMappings, err := c.missingRealmManagementMappings(ctx, mappingsPath, proxyClientID, rolesByName)
	if err != nil {
		return err
	}
	if len(missingMappings) == 0 {
		return nil
	}
	if err := c.writeRealmRoleMappings(ctx, http.MethodPost, mappingsPath, missingMappings); err != nil {
		return fmt.Errorf("grant operator access to realm management proxy %q: %w", proxyClientID, err)
	}

	c.invalidateToken()
	if _, err := c.bearerToken(ctx); err != nil {
		return fmt.Errorf("refresh operator token after granting realm %q access: %w", realmID, err)
	}
	return nil
}

func (c *Client) resolveRealmManagementProxy(ctx context.Context, realmID string) (string, string, error) {
	proxyClientID := realmID + "-realm"
	proxyUUID, err := c.resolveClientUUID(ctx, "master", proxyClientID)
	if err != nil {
		return "", proxyClientID, fmt.Errorf("resolve realm management proxy %q: %w", proxyClientID, err)
	}
	if proxyUUID != "" {
		return proxyUUID, proxyClientID, nil
	}
	if err := c.createRealmManagementClient(ctx, proxyClientID); err != nil {
		return "", proxyClientID, err
	}
	proxyUUID, err = c.resolveClientUUID(ctx, "master", proxyClientID)
	if err != nil {
		return "", proxyClientID, fmt.Errorf("resolve created realm management proxy %q: %w", proxyClientID, err)
	}
	if proxyUUID == "" {
		return "", proxyClientID, fmt.Errorf("created realm management proxy %q was not found", proxyClientID)
	}
	return proxyUUID, proxyClientID, nil
}

func (c *Client) ensureRealmManagementRoles(ctx context.Context, proxyUUID, proxyClientID string) (map[string]RealmRole, error) {
	path := masterClientsPath + url.PathEscape(proxyUUID) + rolesPath
	var roles []RealmRole
	if err := c.get(ctx, path, &roles); err != nil {
		return nil, fmt.Errorf("list roles for realm management proxy %q: %w", proxyClientID, err)
	}
	created, err := c.createMissingRealmManagementRoles(ctx, path, proxyClientID, roles)
	if err != nil {
		return nil, err
	}
	if created {
		if err := c.get(ctx, path, &roles); err != nil {
			return nil, fmt.Errorf("reload roles for realm management proxy %q: %w", proxyClientID, err)
		}
	}
	return requiredRealmManagementRoles(roles)
}

func (c *Client) createMissingRealmManagementRoles(ctx context.Context, path, proxyClientID string, roles []RealmRole) (bool, error) {
	existing := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		existing[role.Name] = struct{}{}
	}
	created := false
	for _, roleName := range realmManagementRoles {
		if _, ok := existing[roleName]; ok {
			continue
		}
		if err := c.createClientRole(ctx, path, roleName); err != nil {
			return false, fmt.Errorf("create role %q for realm management proxy %q: %w", roleName, proxyClientID, err)
		}
		created = true
	}
	return created, nil
}

func requiredRealmManagementRoles(roles []RealmRole) (map[string]RealmRole, error) {
	required := make(map[string]struct{}, len(realmManagementRoles))
	for _, roleName := range realmManagementRoles {
		required[roleName] = struct{}{}
	}
	byName := make(map[string]RealmRole, len(roles))
	for _, role := range roles {
		if _, ok := required[role.Name]; !ok {
			continue
		}
		if role.ID == "" {
			return nil, fmt.Errorf("realm management role %q has no Keycloak ID", role.Name)
		}
		byName[role.Name] = role
	}
	for _, roleName := range realmManagementRoles {
		if _, ok := byName[roleName]; !ok {
			return nil, fmt.Errorf("realm management role %q was not found after creation", roleName)
		}
	}
	return byName, nil
}

func (c *Client) operatorServiceAccountID(ctx context.Context) (string, error) {
	operatorUUID, err := c.resolveClientUUID(ctx, "master", c.clientID)
	if err != nil {
		return "", fmt.Errorf("resolve operator client %q: %w", c.clientID, err)
	}
	if operatorUUID == "" {
		return "", fmt.Errorf("operator client %q not found in master realm", c.clientID)
	}
	var serviceAccount struct {
		ID string `json:"id"`
	}
	path := masterClientsPath + url.PathEscape(operatorUUID) + "/service-account-user"
	if err := c.get(ctx, path, &serviceAccount); err != nil {
		return "", fmt.Errorf("get service account for operator client %q: %w", c.clientID, err)
	}
	if serviceAccount.ID == "" {
		return "", fmt.Errorf("operator client %q service account has no Keycloak ID", c.clientID)
	}
	return serviceAccount.ID, nil
}

func (c *Client) missingRealmManagementMappings(ctx context.Context, path, proxyClientID string, rolesByName map[string]RealmRole) ([]RealmRole, error) {
	var current []RealmRole
	if err := c.get(ctx, path, &current); err != nil {
		return nil, fmt.Errorf("list operator mappings for realm management proxy %q: %w", proxyClientID, err)
	}
	mapped := make(map[string]struct{}, len(current))
	for _, role := range current {
		mapped[role.Name] = struct{}{}
	}
	missing := make([]RealmRole, 0, len(realmManagementRoles))
	for _, roleName := range realmManagementRoles {
		if _, ok := mapped[roleName]; !ok {
			missing = append(missing, rolesByName[roleName])
		}
	}
	return missing, nil
}

// EnsureRealmDeletionAccess bootstraps realm administration only when the
// target realm still exists. A missing realm needs no Keycloak permission and
// must not create an orphan master-realm proxy during finalizer recovery.
func (c *Client) EnsureRealmDeletionAccess(ctx context.Context, realmID string) error {
	if err := validateManagedRealmID(realmID); err != nil {
		return err
	}
	_, err := c.GetRealm(ctx, realmID)
	if err == nil || IsForbidden(err) {
		return c.EnsureRealmManagementAccess(ctx, realmID)
	}
	if IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("check realm %q before deletion: %w", realmID, err)
}

// DeleteRealmManagementAccess removes only the validated master-realm proxy for
// realmID. It refuses to delete a client whose security-sensitive settings do
// not match a Keycloak realm-management proxy.
func (c *Client) DeleteRealmManagementAccess(ctx context.Context, realmID string) error {
	if err := validateManagedRealmID(realmID); err != nil {
		return err
	}
	proxyClientID := realmID + "-realm"
	proxyUUID, err := c.resolveClientUUID(ctx, "master", proxyClientID)
	if err != nil {
		return fmt.Errorf("resolve realm management proxy %q for deletion: %w", proxyClientID, err)
	}
	if proxyUUID == "" {
		return nil
	}
	if err := c.validateRealmManagementClient(ctx, proxyUUID, proxyClientID); err != nil {
		return err
	}

	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+masterClientsPath+url.PathEscape(proxyUUID), nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete realm management proxy %q: keycloak %d: %s", proxyClientID, resp.StatusCode, body)
	}
	c.invalidateToken()
	return nil
}

func validateManagedRealmID(realmID string) error {
	if realmID == "" {
		return fmt.Errorf("managed realm ID must not be empty")
	}
	if realmID == "master" {
		return fmt.Errorf("master realm management access is protected")
	}
	if url.PathEscape(realmID) != realmID {
		return fmt.Errorf("managed realm ID %q is not safe for a Keycloak path", realmID)
	}
	return nil
}

func (c *Client) createRealmManagementClient(ctx context.Context, clientID string) error {
	payload := realmManagementClient{
		ClientID:               clientID,
		Enabled:                true,
		BearerOnly:             true,
		PublicClient:           false,
		ServiceAccountsEnabled: false,
		FullScopeAllowed:       false,
		Protocol:               openIDConnectProtocol,
		Attributes:             map[string]string{"realm_client": "true"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal realm management proxy %q: %w", clientID, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/admin/realms/master/clients", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	responseBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("create realm management proxy %q: keycloak %d: %s", clientID, resp.StatusCode, responseBody)
}

func (c *Client) validateRealmManagementClient(ctx context.Context, uuid, clientID string) error {
	var proxy realmManagementClient
	path := masterClientsPath + url.PathEscape(uuid)
	if err := c.get(ctx, path, &proxy); err != nil {
		return fmt.Errorf("get realm management proxy %q: %w", clientID, err)
	}
	if proxy.ID != uuid || proxy.ClientID != clientID || !proxy.Enabled || !proxy.BearerOnly ||
		proxy.PublicClient || proxy.ServiceAccountsEnabled || proxy.FullScopeAllowed ||
		(proxy.Protocol != "" && proxy.Protocol != openIDConnectProtocol) ||
		proxy.Attributes["realm_client"] != "true" {
		return fmt.Errorf("client %q is not a safe realm management proxy", clientID)
	}
	return nil
}

func (c *Client) createClientRole(ctx context.Context, rolesPath, roleName string) error {
	body, err := json.Marshal(RealmRole{Name: roleName})
	if err != nil {
		return fmt.Errorf("marshal client role %q: %w", roleName, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+rolesPath, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	responseBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf(keycloakPathErrorFormat, rolesPath, resp.StatusCode, responseBody)
}

// RealmRole is the subset of Keycloak's RoleRepresentation required to manage
// realm roles and their composite relationships.
type RealmRole struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Composite   bool                `json:"composite,omitempty"`
	ClientRole  bool                `json:"clientRole,omitempty"`
	ContainerID string              `json:"containerId,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// GetRealmRole returns one realm-scoped role by name.
func (c *Client) GetRealmRole(ctx context.Context, realm, roleName string) (*RealmRole, error) {
	var role RealmRole
	path := adminRealmsPath + realm + rolesSegment + url.PathEscape(roleName)
	if err := c.get(ctx, path, &role); err != nil {
		return nil, fmt.Errorf("get realm role %q in %q: %w", roleName, realm, err)
	}
	return &role, nil
}

// GetRealmRoleClosure returns the referenced realm role and every role it
// inherits through Keycloak composites. The traversal follows both realm and
// client-role children and fails closed on any unreadable edge. Reconcilers use
// this before attaching roles to groups or mappers so an ordinary-looking role
// cannot hide a control-plane authority role.
func (c *Client) GetRealmRoleClosure(ctx context.Context, realm, roleName string) ([]RealmRole, error) {
	root, err := c.GetRealmRole(ctx, realm, roleName)
	if err != nil {
		return nil, err
	}
	return c.getRoleClosure(ctx, realm, *root)
}

// GetClientRoleClosure returns a client role and its complete composite role
// closure. Client roles may themselves contain realm roles, so treating them
// as intrinsically tenant-local would leave an indirect authority-grant path.
func (c *Client) GetClientRoleClosure(ctx context.Context, realm, clientID, roleName string) ([]RealmRole, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return nil, err
	}
	if uuid == "" {
		return nil, fmt.Errorf("client %q not found in realm %q", clientID, realm)
	}
	var root RealmRole
	rolePath := adminRealmsPath + realm + clientsPath + uuid + rolesPath + "/" + url.PathEscape(roleName)
	if err := c.get(ctx, rolePath, &root); err != nil {
		return nil, fmt.Errorf("get client role %q of %q in %q: %w", roleName, clientID, realm, err)
	}
	root.ClientRole = true
	if root.ContainerID == "" {
		root.ContainerID = uuid
	}
	return c.getRoleClosure(ctx, realm, root)
}

func (c *Client) getRoleClosure(ctx context.Context, realm string, root RealmRole) ([]RealmRole, error) {
	closure := make([]RealmRole, 0, 1)
	seen := make(map[string]struct{})
	stack := []RealmRole{root}
	for len(stack) > 0 {
		role := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		key := fmt.Sprintf("%t\x00%s\x00%s", role.ClientRole, role.ContainerID, role.Name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		closure = append(closure, role)
		if !role.Composite {
			continue
		}
		path, err := roleResourcePath(realm, role)
		if err != nil {
			return nil, err
		}
		var children []RealmRole
		if err := c.get(ctx, path+"/composites", &children); err != nil {
			return nil, fmt.Errorf("list composites for role %q in %q: %w", role.Name, realm, err)
		}
		stack = append(stack, children...)
	}
	return closure, nil
}

func roleResourcePath(realm string, role RealmRole) (string, error) {
	if role.ClientRole {
		if strings.TrimSpace(role.ContainerID) == "" {
			return "", fmt.Errorf("client role %q has no container ID", role.Name)
		}
		return adminRealmsPath + realm + clientsPath + url.PathEscape(role.ContainerID) + rolesPath + "/" + url.PathEscape(role.Name), nil
	}
	return adminRealmsPath + realm + rolesSegment + url.PathEscape(role.Name), nil
}

// EnsureRealmRole creates the role when absent and updates its description
// when a non-empty description differs. An omitted description leaves an
// adopted role's existing description untouched. Other Keycloak-managed
// representation fields are preserved.
func (c *Client) EnsureRealmRole(ctx context.Context, realm, roleName, description string) error {
	role, err := c.GetRealmRole(ctx, realm, roleName)
	if err != nil {
		if !IsNotFound(err) {
			return err
		}
		payload := RealmRole{Name: roleName, Description: description}
		return c.writeRealmRole(ctx, http.MethodPost, adminRealmsPath+realm+rolesPath, payload,
			http.StatusCreated, http.StatusConflict)
	}
	if description == "" || role.Description == description {
		return nil
	}
	role.Description = description
	return c.writeRealmRole(ctx, http.MethodPut,
		adminRealmsPath+realm+rolesSegment+url.PathEscape(roleName), *role, http.StatusNoContent)
}

// EnsureRealmRoleComposites additively attaches child realm roles to a parent.
// Existing composites not declared by hankoShell are intentionally preserved.
func (c *Client) EnsureRealmRoleComposites(ctx context.Context, realm, parentName string, childNames []string) error {
	if len(childNames) == 0 {
		return nil
	}
	if _, err := c.GetRealmRole(ctx, realm, parentName); err != nil {
		return fmt.Errorf("get composite parent: %w", err)
	}

	path := adminRealmsPath + realm + rolesSegment + url.PathEscape(parentName) + "/composites/realm"
	var current []RealmRole
	if err := c.get(ctx, path, &current); err != nil {
		return fmt.Errorf("list composites for realm role %q: %w", parentName, err)
	}
	missing, err := c.missingRealmRoleComposites(ctx, realm, parentName, childNames, current)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}

	body, err := json.Marshal(missing)
	if err != nil {
		return fmt.Errorf("marshal realm role composites: %w", err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+adminRealmsPath+realm+rolesSegment+url.PathEscape(parentName)+"/composites",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	responseBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("add composites to realm role %q: keycloak %d: %s", parentName, resp.StatusCode, responseBody)
}

func (c *Client) missingRealmRoleComposites(ctx context.Context, realm, parentName string, childNames []string, current []RealmRole) ([]RealmRole, error) {
	existing := make(map[string]struct{}, len(current))
	for _, role := range current {
		existing[role.Name] = struct{}{}
	}
	missing := make([]RealmRole, 0, len(childNames))
	for _, childName := range childNames {
		if childName == parentName {
			return nil, fmt.Errorf("realm role %q cannot include itself", parentName)
		}
		if _, ok := existing[childName]; ok {
			continue
		}
		child, err := c.GetRealmRole(ctx, realm, childName)
		if err != nil {
			return nil, fmt.Errorf("get composite child %q: %w", childName, err)
		}
		missing = append(missing, *child)
	}
	return missing, nil
}

func (c *Client) writeRealmRole(ctx context.Context, method, path string, role RealmRole, accepted ...int) error {
	body, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("marshal realm role %q: %w", role.Name, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for _, status := range accepted {
		if resp.StatusCode == status {
			return nil
		}
	}
	responseBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("write realm role %q: keycloak %d: %s", role.Name, resp.StatusCode, responseBody)
}

// SyncRealmRole creates the role when absent, or fully updates its
// description, composite flag, and attributes to match role when present.
// Unlike EnsureRealmRole, this overwrites rather than preserves drifted
// fields, since HankoRole is the sole declared owner of these roles.
func (c *Client) SyncRealmRole(ctx context.Context, realm string, role RealmRole) error {
	existing, err := c.GetRealmRole(ctx, realm, role.Name)
	if err != nil {
		if !IsNotFound(err) {
			return err
		}
		return c.writeRealmRole(ctx, http.MethodPost, adminRealmsPath+realm+rolesPath, role,
			http.StatusCreated, http.StatusConflict)
	}
	role.ID = existing.ID
	role.ContainerID = existing.ContainerID
	role.ClientRole = existing.ClientRole
	return c.writeRealmRole(ctx, http.MethodPut,
		adminRealmsPath+realm+rolesSegment+url.PathEscape(role.Name), role, http.StatusNoContent)
}

// DeleteRealmRole deletes a realm role from realm. Returns nil if the role
// does not exist.
func (c *Client) DeleteRealmRole(ctx context.Context, realm, roleName string) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realm+rolesSegment+url.PathEscape(roleName), nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete realm role %q in %q: keycloak %d: %s", roleName, realm, resp.StatusCode, body)
}

// ReconcileClientRealmRoleScopes sets the exact realm-role scope mappings for
// one client. This keeps fullScopeAllowed disabled while allowing explicitly
// declared realm roles to appear in that client's tokens.
func (c *Client) ReconcileClientRealmRoleScopes(ctx context.Context, realm, clientID string, roleNames []string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}

	path := adminRealmsPath + realm + clientsPath + uuid + "/scope-mappings/realm"
	var current []RealmRole
	if err := c.get(ctx, path, &current); err != nil {
		return fmt.Errorf("list realm-role scopes for client %q: %w", clientID, err)
	}

	currentByName := make(map[string]RealmRole, len(current))
	for _, role := range current {
		currentByName[role.Name] = role
	}
	toAdd, desired, err := c.resolveRealmRoleScopes(ctx, realm, roleNames, currentByName)
	if err != nil {
		return err
	}
	toRemove := staleRealmRoleScopes(current, desired)
	if err := c.writeRealmRoleScopesIfNeeded(ctx, http.MethodPost, path, clientID, "add", toAdd); err != nil {
		return err
	}
	return c.writeRealmRoleScopesIfNeeded(ctx, http.MethodDelete, path, clientID, "remove", toRemove)
}

func (c *Client) resolveRealmRoleScopes(ctx context.Context, realm string, roleNames []string, current map[string]RealmRole) ([]RealmRole, map[string]struct{}, error) {
	desired := make(map[string]struct{}, len(roleNames))
	toAdd := make([]RealmRole, 0, len(roleNames))
	for _, roleName := range roleNames {
		if roleName == "" {
			return nil, nil, fmt.Errorf("realm-role scope name must not be empty")
		}
		desired[roleName] = struct{}{}
		if _, ok := current[roleName]; ok {
			continue
		}
		role, err := c.GetRealmRole(ctx, realm, roleName)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve realm-role scope %q: %w", roleName, err)
		}
		toAdd = append(toAdd, *role)
	}
	return toAdd, desired, nil
}

func staleRealmRoleScopes(current []RealmRole, desired map[string]struct{}) []RealmRole {
	stale := make([]RealmRole, 0, len(current))
	for _, role := range current {
		if _, ok := desired[role.Name]; !ok {
			stale = append(stale, role)
		}
	}
	return stale
}

func (c *Client) writeRealmRoleScopesIfNeeded(ctx context.Context, method, path, clientID, action string, roles []RealmRole) error {
	if len(roles) == 0 {
		return nil
	}
	if err := c.writeRealmRoleMappings(ctx, method, path, roles); err != nil {
		return fmt.Errorf("%s realm-role scopes from client %q: %w", action, clientID, err)
	}
	return nil
}

func (c *Client) writeRealmRoleMappings(ctx context.Context, method, path string, roles []RealmRole) error {
	body, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("marshal realm-role scope mappings: %w", err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	responseBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf(keycloakPathErrorFormat, path, resp.StatusCode, responseBody)
}

// ClientExists reports whether a client with the given clientId exists in the realm.
// It uses Keycloak's clientId filter to avoid fetching the full client list,
// then does an exact-match check (the filter is a prefix search in Keycloak).
func (c *Client) ClientExists(ctx context.Context, realm, clientID string) (bool, error) {
	var clients []App
	path := fmt.Sprintf("/admin/realms/%s/clients?clientId=%s", realm, url.QueryEscape(clientID))
	if err := c.get(ctx, path, &clients); err != nil {
		return false, fmt.Errorf("lookup client %q in realm %q: %w", clientID, realm, err)
	}
	for _, cl := range clients {
		if cl.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}

// ListApps returns the OIDC clients registered in the realm.
func (c *Client) ListApps(ctx context.Context, realm string) ([]App, error) {
	var apps []App
	if err := c.get(ctx, adminRealmsPath+realm+"/clients", &apps); err != nil {
		return nil, fmt.Errorf("list apps in realm %q: %w", realm, err)
	}
	return apps, nil
}

// resolveClientUUID returns the Keycloak-internal UUID for a given clientId.
// Returns ("", nil) when the client does not exist.
func (c *Client) resolveClientUUID(ctx context.Context, realm, clientID string) (string, error) {
	var clients []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	path := fmt.Sprintf("/admin/realms/%s/clients?clientId=%s", realm, url.QueryEscape(clientID))
	if err := c.get(ctx, path, &clients); err != nil {
		return "", fmt.Errorf("resolve UUID for client %q in realm %q: %w", clientID, realm, err)
	}
	for _, cl := range clients {
		if cl.ClientID == clientID {
			return cl.ID, nil
		}
	}
	return "", nil
}

// ClientRole is a minimal Keycloak client role representation.
type ClientRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListClientRoles returns all roles defined for a client in Keycloak.
func (c *Client) ListClientRoles(ctx context.Context, realm, clientID string) ([]ClientRole, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return nil, fmt.Errorf("resolve UUID for role list: %w", err)
	}
	if uuid == "" {
		return nil, nil
	}
	var roles []ClientRole
	if err := c.get(ctx, adminRealmsPath+realm+clientsPath+uuid+rolesPath, &roles); err != nil {
		return nil, fmt.Errorf("list roles for client %q: %w", clientID, err)
	}
	return roles, nil
}

// CreateClientRole creates a client-scoped role in Keycloak. Idempotent — if the
// role already exists (HTTP 409) the call succeeds silently.
func (c *Client) CreateClientRole(ctx context.Context, realm, clientID, roleName, description string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}

	payload := map[string]any{"name": roleName, "description": description}
	b, _ := json.Marshal(payload)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+adminRealmsPath+realm+clientsPath+uuid+rolesPath,
		strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("create role %q for client %q: keycloak %d: %s", roleName, clientID, resp.StatusCode, body)
}

// DeleteClientRole removes a client-scoped role from Keycloak.
// Returns nil if the role does not exist.
func (c *Client) DeleteClientRole(ctx context.Context, realm, clientID, roleName string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve UUID for role delete: %w", err)
	}
	if uuid == "" {
		return nil
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realm+clientsPath+uuid+rolesSegment+url.PathEscape(roleName), nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete role %q for client %q: keycloak %d: %s", roleName, clientID, resp.StatusCode, body)
}

// DeleteApp deletes an OIDC client from Keycloak. Returns nil if the client was not found.
func (c *Client) DeleteApp(ctx context.Context, realm, clientID string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve client UUID for %q: %w", clientID, err)
	}
	if uuid == "" {
		return nil // already gone
	}

	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realm+clientsPath+uuid, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete client %q: keycloak %d: %s", clientID, resp.StatusCode, body)
}

// reservedAppAttributeKeys are Keycloak client attribute keys the operator sets
// itself from other CreateAppSpec fields. CreateApp/UpdateApp silently drop these
// keys from spec.Attributes so a client-authored attribute map cannot override
// operator-managed settings.
var reservedAppAttributeKeys = map[string]struct{}{
	"login_theme":                  {},
	postLogoutRedirectURIAttribute: {},
	hankoAppAttribute:              {},
	hankoServiceAttribute:          {},
}

func mergeAppAttributes(dst map[string]any, attrs map[string]string) {
	for k, v := range attrs {
		if _, reserved := reservedAppAttributeKeys[k]; reserved {
			continue
		}
		dst[k] = v
	}
}

// CreateApp creates an OIDC client in Keycloak. Returns the client secret for confidential clients.
func (c *Client) CreateApp(ctx context.Context, realm string, spec CreateAppSpec) (string, error) {
	attributes := map[string]any{"login_theme": spec.Theme}
	if spec.Type == "m2m" {
		attributes[hankoServiceAttribute] = "true"
	} else {
		attributes[hankoAppAttribute] = "true"
	}
	payload := map[string]any{
		"clientId":                  spec.ClientID,
		"name":                      spec.Name,
		"enabled":                   true,
		"protocol":                  openIDConnectProtocol,
		"publicClient":              spec.Type == "spa",
		"standardFlowEnabled":       spec.Type != "m2m",
		"serviceAccountsEnabled":    spec.Type == "m2m",
		"directAccessGrantsEnabled": false,
		"fullScopeAllowed":          false, // prevent scope escalation to other realm clients
		"redirectUris":              spec.RedirectURIs,
		// "+" tells Keycloak to allow the origins of the registered redirect
		// URIs. Sending the redirect URIs themselves would break SPA CORS:
		// Keycloak compares the Origin header literally, and a path-bearing
		// entry never matches.
		"webOrigins": []string{"+"},
		"attributes": attributes,
	}
	if len(spec.PostLogoutRedirectURIs) > 0 {
		attributes[postLogoutRedirectURIAttribute] = joinURIs(spec.PostLogoutRedirectURIs)
	}
	mergeAppAttributes(attributes, spec.Attributes)

	b, _ := json.Marshal(payload)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+adminRealmsPath+realm+"/clients",
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create client %q: keycloak %d: %s", spec.ClientID, resp.StatusCode, body)
	}

	// Confidential clients: resolve internal UUID then fetch the generated secret.
	if spec.Type != "spa" {
		uuid, err := c.resolveClientUUID(ctx, realm, spec.ClientID)
		if err != nil || uuid == "" {
			return "", fmt.Errorf("resolve UUID after create for %q: %w", spec.ClientID, err)
		}
		var secret struct {
			Value string `json:"value"`
		}
		if err := c.get(ctx, adminRealmsPath+realm+clientsPath+uuid+clientSecretPath, &secret); err != nil {
			return "", fmt.Errorf("fetch client secret: %w", err)
		}
		return secret.Value, nil
	}
	return "", nil
}

// CreateAppSpec holds the fields needed to create an OIDC client.
type CreateAppSpec struct {
	ClientID               string
	Name                   string
	Type                   string // "web", "spa"
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Theme                  string
	// Attributes sets arbitrary Keycloak client attributes. Keys in
	// reservedAppAttributeKeys are dropped — those are operator-managed via
	// other fields on this spec.
	Attributes map[string]string
}

// UpdateApp applies spec changes (redirectURIs, theme, type) to an existing OIDC client via PUT.
func (c *Client) UpdateApp(ctx context.Context, realm string, spec CreateAppSpec) error {
	uuid, err := c.resolveClientUUID(ctx, realm, spec.ClientID)
	if err != nil {
		return fmt.Errorf("resolve UUID for update of %q: %w", spec.ClientID, err)
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, spec.ClientID, realm)
	}
	// Preserve provider features owned by sibling controllers, notably
	// authorizationServicesEnabled from HankoResourceServer. A partial client
	// representation sent with PUT would otherwise reset those fields and make
	// the application and authorization reconcilers fight perpetual drift.
	payload := make(map[string]any)
	if err := c.get(ctx, adminRealmsPath+realm+clientsPath+uuid, &payload); err != nil {
		return fmt.Errorf("read client %q before update: %w", spec.ClientID, err)
	}

	attributes := map[string]any{"login_theme": spec.Theme}
	if spec.Type == "m2m" {
		attributes[hankoServiceAttribute] = "true"
	} else {
		attributes[hankoAppAttribute] = "true"
	}
	payload["clientId"] = spec.ClientID
	payload["name"] = spec.Name
	payload["enabled"] = true
	payload["protocol"] = openIDConnectProtocol
	payload["publicClient"] = spec.Type == "spa"
	payload["standardFlowEnabled"] = spec.Type != "m2m"
	payload["serviceAccountsEnabled"] = spec.Type == "m2m"
	payload["directAccessGrantsEnabled"] = false
	payload["fullScopeAllowed"] = false // prevent scope escalation to other realm clients
	payload["redirectUris"] = spec.RedirectURIs
	// See CreateApp: "+" = allow the origins of the redirect URIs.
	payload["webOrigins"] = []string{"+"}
	payload["attributes"] = attributes
	if len(spec.PostLogoutRedirectURIs) > 0 {
		attributes[postLogoutRedirectURIAttribute] = joinURIs(spec.PostLogoutRedirectURIs)
	}
	mergeAppAttributes(attributes, spec.Attributes)

	b, _ := json.Marshal(payload)
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+adminRealmsPath+realm+clientsPath+uuid,
		strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("update client %q: keycloak %d: %s", spec.ClientID, resp.StatusCode, body)
}

// SyncClientAttributes replaces the caller-managed attributes on an existing
// client while preserving its complete Keycloak representation. This is the
// safe update path for imported service accounts whose privilege-bearing
// fields (notably fullScopeAllowed and scope mappings) are not owned by the
// HankoServiceAccount CRD.
func (c *Client) SyncClientAttributes(ctx context.Context, realm, clientID string, attrs map[string]string) error {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve UUID for attribute update of %q: %w", clientID, err)
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}

	var payload map[string]any
	path := adminRealmsPath + realm + clientsPath + uuid
	if err := c.get(ctx, path, &payload); err != nil {
		return fmt.Errorf("get client %q before attribute update: %w", clientID, err)
	}

	nextAttributes := make(map[string]any, len(attrs)+len(reservedAppAttributeKeys))
	if current, ok := payload["attributes"].(map[string]any); ok {
		for key := range reservedAppAttributeKeys {
			if value, exists := current[key]; exists {
				nextAttributes[key] = value
			}
		}
	}
	mergeAppAttributes(nextAttributes, attrs)
	payload["attributes"] = nextAttributes

	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal client %q attribute update: %w", clientID, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("update client %q attributes: keycloak %d: %s", clientID, resp.StatusCode, body)
}

// UpdateAppAttributes is retained as a compatibility alias for callers built
// before the desired-state operation was named SyncClientAttributes.
func (c *Client) UpdateAppAttributes(ctx context.Context, realm, clientID string, attrs map[string]string) error {
	return c.SyncClientAttributes(ctx, realm, clientID, attrs)
}

// GetClientSecret returns the current client secret without rotating it.
func (c *Client) GetClientSecret(ctx context.Context, realm, clientID string) (string, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return "", fmt.Errorf("resolve UUID for %q: %w", clientID, err)
	}
	if uuid == "" {
		return "", fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	var secret struct {
		Value string `json:"value"`
	}
	if err := c.get(ctx, adminRealmsPath+realm+clientsPath+uuid+clientSecretPath, &secret); err != nil {
		return "", fmt.Errorf("get client secret for %q: %w", clientID, err)
	}
	return secret.Value, nil
}

// SetClientSecret replaces a confidential client's secret with caller-provided
// high-entropy material. Rotation reconcilers persist that material as a
// pending Kubernetes credential before calling this method, making recovery
// possible if either process crashes between Keycloak and Kubernetes writes.
func (c *Client) SetClientSecret(ctx context.Context, realm, clientID, desiredSecret string) error {
	if len(desiredSecret) < 32 {
		return fmt.Errorf("replacement secret for client %q must contain at least 32 characters", clientID)
	}
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return fmt.Errorf("resolve UUID for secret replacement of %q: %w", clientID, err)
	}
	if uuid == "" {
		return fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	path := adminRealmsPath + realm + clientsPath + uuid
	var representation map[string]any
	if err := c.get(ctx, path, &representation); err != nil {
		return fmt.Errorf("get client %q before secret replacement: %w", clientID, err)
	}
	representation["secret"] = desiredSecret
	body, err := json.Marshal(representation)
	if err != nil {
		return fmt.Errorf("marshal client %q secret replacement: %w", clientID, err)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("replace secret for client %q: keycloak returned status %d", clientID, resp.StatusCode)
	}
	return nil
}

// RotateClientSecret regenerates the Keycloak client secret and returns the new value.
func (c *Client) RotateClientSecret(ctx context.Context, realm, clientID string) (string, error) {
	uuid, err := c.resolveClientUUID(ctx, realm, clientID)
	if err != nil {
		return "", fmt.Errorf("resolve UUID for rotation of %q: %w", clientID, err)
	}
	if uuid == "" {
		return "", fmt.Errorf(clientNotFoundFormat, clientID, realm)
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+adminRealmsPath+realm+clientsPath+uuid+clientSecretPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("rotate secret for client %q: keycloak %d: %s", clientID, resp.StatusCode, body)
	}
	var secret struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return "", fmt.Errorf("decode rotated secret: %w", err)
	}
	return secret.Value, nil
}

func joinURIs(uris []string) string {
	return strings.Join(uris, "##")
}

// HardenMasterRealm applies a fixed security baseline to the Keycloak master realm.
// The master realm controls all admin API access and must never be left at defaults.
// This is idempotent and called on every HankoKeycloakInstance reconcile cycle.
func (c *Client) HardenMasterRealm(ctx context.Context) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"bruteForceProtected":          true,
		"failureFactor":                3,
		"maxFailureWaitSeconds":        900,
		"waitIncrementSeconds":         60,
		"minimumQuickLoginWaitSeconds": 60,
		"maxDeltaTimeSeconds":          43200,
		"registrationAllowed":          false,
		"editUsernameAllowed":          false,
		"sslRequired":                  "external",
		"revokeRefreshToken":           true,
		"refreshTokenMaxReuse":         0,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+"/admin/realms/master", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("harden master realm: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("harden master realm: keycloak %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ConfigureRealmEvents enables Keycloak's native event log for the given realm,
// capturing security-relevant events (login failures, password changes, etc.).
// This is idempotent and called on every HankoRealm reconcile cycle after UpdateRealm.
func (c *Client) ConfigureRealmEvents(ctx context.Context, realm string, spec RealmSpec) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	eventsEnabled := true
	if spec.EventsEnabled != nil {
		eventsEnabled = *spec.EventsEnabled
	}
	adminEventsEnabled := true
	if spec.AdminEventsEnabled != nil {
		adminEventsEnabled = *spec.AdminEventsEnabled
	}
	retentionSeconds := 7 * 24 * 60 * 60
	if spec.AuditRetentionDays != nil {
		retentionSeconds = *spec.AuditRetentionDays * 24 * 60 * 60
	}
	exportEnabled := true
	if spec.AuditExportEnabled != nil {
		exportEnabled = *spec.AuditExportEnabled
	}
	listeners := []string{}
	if exportEnabled {
		listeners = append(listeners, "jboss-logging")
	}
	payload := map[string]any{
		"eventsEnabled":      eventsEnabled,
		"adminEventsEnabled": adminEventsEnabled,
		// Admin events have no built-in expiration in Keycloak (eventsExpiration
		// below only prunes login/user events), so full request/response bodies
		// per event would accumulate unbounded. Keep the audit trail (who/what/when)
		// without the heavy payload.
		"adminEventsDetailsEnabled": false,
		"eventsExpiration":          retentionSeconds,
		"eventsListeners":           listeners,
		"enabledEventTypes": []string{
			"LOGIN", "LOGIN_ERROR",
			"LOGOUT", "LOGOUT_ERROR",
			"REGISTER", "REGISTER_ERROR",
			"CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
			"CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
			"REFRESH_TOKEN", "REFRESH_TOKEN_ERROR",
			"INTROSPECT_TOKEN", "INTROSPECT_TOKEN_ERROR",
			"UPDATE_EMAIL", "UPDATE_EMAIL_ERROR",
			"UPDATE_PROFILE", "UPDATE_PROFILE_ERROR",
			"UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR",
			"RESET_PASSWORD", "RESET_PASSWORD_ERROR",
			"VERIFY_EMAIL", "VERIFY_EMAIL_ERROR",
			"SEND_VERIFY_EMAIL", "SEND_VERIFY_EMAIL_ERROR",
			"SEND_RESET_PASSWORD", "SEND_RESET_PASSWORD_ERROR",
			"IDENTITY_PROVIDER_LOGIN", "IDENTITY_PROVIDER_LOGIN_ERROR",
		},
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+adminRealmsPath+realm+"/events/config",
		strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("configure realm events %q: %w", realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("configure realm events %q: keycloak %d: %s", realm, resp.StatusCode, body)
	}
	return nil
}

// ConfigureAdminConsoleExposure reconciles the realm-scoped Keycloak web
// console client. Network restriction itself is supplied by the platform
// ingress; disabled additionally makes the browser console unusable even when
// the ingress is reachable. The operator's Admin API service account is not
// affected.
func (c *Client) ConfigureAdminConsoleExposure(ctx context.Context, realm, exposure string) error {
	if exposure == "" {
		return nil
	}
	uuid, err := c.resolveClientUUID(ctx, realm, "security-admin-console")
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("security-admin-console client not found in realm %q", realm)
	}
	path := adminRealmsPath + url.PathEscape(realm) + clientsPath + url.PathEscape(uuid)
	var current map[string]any
	if err := c.get(ctx, path, &current); err != nil {
		return fmt.Errorf("read admin console client for realm %q: %w", realm, err)
	}
	desiredEnabled := exposure != "disabled"
	if enabled, ok := current["enabled"].(bool); ok && enabled == desiredEnabled {
		return nil
	}
	current["enabled"] = desiredEnabled
	if err := c.putJSON(ctx, path, current); err != nil {
		return fmt.Errorf("configure admin console exposure for realm %q: %w", realm, err)
	}
	return nil
}

// ConfigureIdentityProviderTrust applies realm-wide trust minima to every
// configured broker while preserving provider-specific configuration.
func (c *Client) ConfigureIdentityProviderTrust(ctx context.Context, realm string, requireSignature, trustEmail *bool) error {
	if requireSignature == nil && trustEmail == nil {
		return nil
	}
	collectionPath := adminRealmsPath + url.PathEscape(realm) + "/identity-provider/instances"
	var providers []map[string]any
	if err := c.get(ctx, collectionPath, &providers); err != nil {
		return fmt.Errorf("list identity providers for realm %q: %w", realm, err)
	}
	for _, provider := range providers {
		alias, changed, err := applyIdentityProviderTrust(provider, requireSignature, trustEmail)
		if err != nil {
			return fmt.Errorf("realm %q: %w", realm, err)
		}
		if !changed {
			continue
		}
		path := collectionPath + "/" + url.PathEscape(alias)
		if err := c.putJSON(ctx, path, provider); err != nil {
			return fmt.Errorf("configure identity provider %q trust in realm %q: %w", alias, realm, err)
		}
	}
	return nil
}

func applyIdentityProviderTrust(provider map[string]any, requireSignature, trustEmail *bool) (string, bool, error) {
	alias, _ := provider["alias"].(string)
	if alias == "" {
		return "", false, fmt.Errorf("identity provider without alias")
	}
	emailChanged := applyIdentityProviderTrustEmail(provider, trustEmail)
	signatureChanged := applyIdentityProviderSignature(provider, requireSignature)
	return alias, emailChanged || signatureChanged, nil
}

func applyIdentityProviderTrustEmail(provider map[string]any, trustEmail *bool) bool {
	if trustEmail == nil {
		return false
	}
	if current, ok := provider["trustEmail"].(bool); ok && current == *trustEmail {
		return false
	}
	provider["trustEmail"] = *trustEmail
	return true
}

func applyIdentityProviderSignature(provider map[string]any, requireSignature *bool) bool {
	if requireSignature == nil {
		return false
	}
	config, _ := provider["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
		provider["config"] = config
	}
	desired := strconv.FormatBool(*requireSignature)
	if current, _ := config["validateSignature"].(string); current == desired {
		return false
	}
	config["validateSignature"] = desired
	return true
}

func (c *Client) putJSON(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(contentTypeHeader, jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(keycloakPathErrorFormat, path, resp.StatusCode, responseBody)
	}
	return nil
}

// ServerVersion returns the Keycloak server version string.
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	var info struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}
	if err := c.get(ctx, "/admin/serverinfo", &info); err != nil {
		return "", err
	}
	return info.SystemInfo.Version, nil
}

// Internal helpers.

func (c *Client) get(ctx context.Context, path string, out any) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set("Accept", jsonMediaType)
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf(keycloakPathErrorFormat, path, resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

// bearerToken returns a valid bearer token, refreshing when expired.
// The mutex is held only for cache reads and writes, not during the HTTP call,
// to avoid blocking all reconcile goroutines on a single token refresh.
func (c *Client) bearerToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()
	return c.fetchToken(ctx)
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.tokenExpiry = time.Time{}
	c.mu.Unlock()
}

func (c *Client) fetchToken(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/realms/master/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set(contentTypeHeader, "application/x-www-form-urlencoded")
	req.Header.Set(forwardedProtoHeader, httpsScheme)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak token endpoint %d: %s", resp.StatusCode, body)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("keycloak returned empty access token")
	}
	ttl := tok.ExpiresIn
	if ttl <= 0 {
		ttl = 60
	}
	c.mu.Lock()
	c.token = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(ttl-10) * time.Second)
	result := c.token
	c.mu.Unlock()
	return result, nil
}
