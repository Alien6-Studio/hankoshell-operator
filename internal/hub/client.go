// Package hub provides an HTTP client for the hankoShell Hub API used by tenant reconcilers.
package hub

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/supervision"
)

const (
	requestTimeout             = 10 * time.Second
	maxBundleEnvelopeBytes     = 1 << 20
	maxHubControlResponseBytes = 64 << 10
	maxHubErrorResponseBytes   = 8 << 10
	maxMeshPolicyEnvelopeBytes = 1 << 20
	contentTypeHeader          = "Content-Type"
	jsonMediaType              = "application/json"
)

// Bundle contains the CRD specs authenticated and distributed by hankoShell Hub.
type Bundle struct {
	Version         string            `json:"version"`
	TenantID        string            `json:"tenantID"`
	IAMProfiles     []json.RawMessage `json:"iamProfiles,omitempty"`
	Realms          []json.RawMessage `json:"realms,omitempty"`
	Apps            []json.RawMessage `json:"apps,omitempty"`
	Themes          []json.RawMessage `json:"themes,omitempty"`
	ServiceAccounts []json.RawMessage `json:"serviceAccounts,omitempty"`
}

// SignedBundle is the payload returned by the Hub bundle endpoint.
type SignedBundle struct {
	Bundle    Bundle `json:"bundle"`
	Signature string `json:"signature"` // HMAC-SHA256(JSON(Bundle), hmacKey), hex-encoded
}

// OperatorStatus is the payload sent by the operator to report reconciliation state.
type OperatorStatus struct {
	TenantID      string         `json:"tenantID"`
	BundleVersion string         `json:"bundleVersion"`
	Phase         string         `json:"phase"`
	ResourceCount map[string]int `json:"resourceCount"`
	// AgentVersion is this binary's build identifier; the Hub preserves the
	// previously reported value when an older operator omits it.
	AgentVersion string `json:"agentVersion,omitempty"`
	// Transport is the authenticated Hub synchronization path selected by the
	// operator. Hub accepts only direct or continuum and preserves the previous
	// value when an older operator omits it.
	Transport string `json:"transport,omitempty"`
	// Health is "healthy" after a successful reconciliation and "degraded"
	// when a reconciliation error was reported; Detail carries the error
	// reason so the fleet view can display it without cluster access.
	Health string `json:"health,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Supervision is the bounded supervision summary collected alongside the
	// heartbeat; nil when the collector is not configured.
	Supervision *supervision.Summary `json:"supervision,omitempty"`
	// MeshRegistrations is nil only for legacy heartbeats. Current operators send
	// a replacement snapshot on success and an empty snapshot on error so stale
	// workload authority is revoked fail closed.
	MeshRegistrations *[]MeshRegistration `json:"meshRegistrations,omitempty"`
}

// MeshRegistration is the immutable Ready projection of HankoMeshService sent
// to Hub. It deliberately contains no pod IP, bearer token, or private key.
type MeshRegistration struct {
	Name               string       `json:"name"`
	Namespace          string       `json:"namespace"`
	Realm              string       `json:"realm,omitempty"`
	IdentityRef        string       `json:"identityRef"`
	ResourceServerRef  string       `json:"resourceServerRef"`
	WorkloadID         string       `json:"workloadId"`
	Audience           string       `json:"audience"`
	ServiceName        string       `json:"serviceName"`
	ServiceUID         string       `json:"serviceUid"`
	ServiceAccountName string       `json:"serviceAccountName"`
	ServiceAccountUID  string       `json:"serviceAccountUid"`
	SelectorSHA256     string       `json:"selectorSha256"`
	EnforcementMode    string       `json:"enforcementMode,omitempty"`
	ReceiverNodeUIDs   []string     `json:"receiverNodeUIDs"`
	Ports              []MeshPort   `json:"ports"`
	Egress             []MeshEgress `json:"egress,omitempty"`
}

// MeshEgress is one immutable reviewed Kubernetes Service destination.
type MeshEgress struct {
	Namespace   string     `json:"namespace"`
	ServiceName string     `json:"serviceName"`
	ServiceUID  string     `json:"serviceUid"`
	Ports       []MeshPort `json:"ports"`
}

// MeshPort is one exact TCP or UDP Service port.
type MeshPort struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// EnrollResult carries the bounded credentials returned by Hub in exchange
// for a single-use enrollment token.
type EnrollResult struct {
	ClusterID string    `json:"clusterID"`
	TenantID  string    `json:"tenantID"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// EnrollmentIdentity identifies a Kubernetes cluster during initial enrollment.
// Empty fields are omitted for callers using the legacy enrollment contract.
type EnrollmentIdentity struct {
	ClusterName string `json:"clusterName,omitempty"`
	ClusterUID  string `json:"clusterUID,omitempty"`
}

// Enroll exchanges a single-use enrollment token for bounded operator
// credentials. It is a package-level function because no operator token
// exists yet at the time it is called.
func Enroll(ctx context.Context, endpoint, enrollToken string) (*EnrollResult, error) {
	return EnrollWithIdentity(ctx, endpoint, enrollToken, EnrollmentIdentity{})
}

// EnrollWithIdentity exchanges a bootstrap token with the cluster's discovered
// identity. The Hub must support these fields before upgrading the operator;
// a rejected request is never retried without its identity metadata.
func EnrollWithIdentity(ctx context.Context, endpoint, enrollToken string, identity EnrollmentIdentity) (*EnrollResult, error) {
	// Enrollment trust stays independent from the private synchronization CA.
	return enrollWithClient(ctx, endpoint, enrollToken, identity, defaultHTTPClient())
}

func enrollWithClient(ctx context.Context, endpoint, enrollToken string, identity EnrollmentIdentity, httpClient *http.Client) (*EnrollResult, error) {
	body, err := json.Marshal(struct {
		EnrollToken string `json:"enrollToken"`
		EnrollmentIdentity
	}{EnrollToken: enrollToken, EnrollmentIdentity: identity})
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment request: %w", err)
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/operators/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build enrollment request: %w", err)
	}
	req.Header.Set(contentTypeHeader, jsonMediaType)

	// Enrollment deliberately uses the system trust store. A private CA used
	// for the Continuum-only synchronization endpoint must never broaden the
	// trust boundary of the public, single-use bootstrap exchange.
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll with hub: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readHubResponse(resp, maxHubControlResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("hub enrollment returned %d: %s", resp.StatusCode, respBody)
	}
	var out EnrollResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}
	if out.Token == "" || out.TenantID == "" || out.ClusterID == "" || out.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("hub enrollment response is missing credentials")
	}
	return &out, nil
}

// PrepareRotation idempotently creates a pending operator credential. Hub
// keeps the active credential valid until ConfirmRotation succeeds.
func (c *Client) PrepareRotation(ctx context.Context, rotationID string) (*EnrollResult, error) {
	body, err := json.Marshal(map[string]string{"rotationID": rotationID})
	if err != nil {
		return nil, fmt.Errorf("marshal credential rotation request: %w", err)
	}
	req, err := c.authenticatedRequest(ctx, http.MethodPost, "/api/v1/operators/token/rotate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build credential rotation request: %w", err)
	}
	req.Header.Set(contentTypeHeader, jsonMediaType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prepare operator credential rotation: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := readHubResponse(resp, maxHubControlResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read credential rotation response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("hub credential rotation returned %d: %s", resp.StatusCode, responseBody)
	}
	var out EnrollResult
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, fmt.Errorf("decode credential rotation response: %w", err)
	}
	if out.Token == "" || out.TenantID == "" || out.ClusterID == "" || out.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("hub credential rotation response is missing credentials")
	}
	return &out, nil
}

// ConfirmRotation promotes this client's pending credential and invalidates
// the previous bearer. Repeated confirmation is safe.
func (c *Client) ConfirmRotation(ctx context.Context) error {
	req, err := c.authenticatedRequest(ctx, http.MethodPost, "/api/v1/operators/token/confirm", nil)
	if err != nil {
		return fmt.Errorf("build credential rotation confirmation: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("confirm operator credential rotation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, readErr := readHubResponse(resp, maxHubControlResponseBytes)
		if readErr != nil {
			return fmt.Errorf("read credential rotation confirmation: %w", readErr)
		}
		return fmt.Errorf("hub credential rotation confirmation returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (c *Client) authenticatedRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Tenant-ID", c.tenantID)
	return req, nil
}

// Client is an authenticated HTTP client for the hankoShell Hub API.
type Client struct {
	endpoint   string
	tenantID   string
	token      string
	hmacKey    []byte
	httpClient *http.Client
}

// New creates a Hub client. The HMAC key is derived from the token via SHA-256
// so that both sides can verify bundle integrity without an out-of-band secret.
// Any holder of that bearer token can produce the same HMAC; it does not prove
// independent publisher authenticity or protect against token compromise.
func New(endpoint, tenantID, token string) *Client {
	return NewWithHTTPClient(endpoint, tenantID, token, nil)
}

// NewWithHTTPClient creates a Hub client with a dedicated transport. It is
// used by the operator to trust an internal Hub CA for synchronization without
// changing the process-wide trust store used by public enrollment or any
// other outbound integration.
func NewWithHTTPClient(endpoint, tenantID, token string, httpClient *http.Client) *Client {
	sum := sha256.Sum256([]byte(token))
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		tenantID:   tenantID,
		token:      token,
		hmacKey:    sum[:],
		httpClient: httpClient,
	}
}

// NewHTTPClient returns a dedicated Hub synchronization client. When caFile
// is set, the PEM certificates are appended to (not substituted for) the
// system roots and are scoped to this client only.
func NewHTTPClient(caFile string) (*http.Client, error) {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unsupported default HTTP transport type %T", http.DefaultTransport)
	}
	transport := defaultTransport.Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	caFile = strings.TrimSpace(caFile)
	if caFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read Hub CA file: %w", err)
		}
		if ok := roots.AppendCertsFromPEM(pemBytes); !ok {
			return nil, fmt.Errorf("hub CA file %q contains no valid PEM certificate", caFile)
		}
		tlsConfig.RootCAs = roots
	}

	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: requestTimeout, Transport: transport}, nil
}

func defaultHTTPClient() *http.Client {
	client, err := NewHTTPClient("")
	if err != nil {
		// NewHTTPClient cannot fail without a CA file. Keep this fallback local
		// and secure if that invariant changes in the future.
		return &http.Client{Timeout: requestTimeout}
	}
	return client
}

// FetchBundle retrieves the latest signed bundle for this tenant from Hub.
func (c *Client) FetchBundle(ctx context.Context) (*SignedBundle, error) {
	req, err := c.authenticatedRequest(ctx, http.MethodGet, "/api/v1/bundles/latest", nil)
	if err != nil {
		return nil, fmt.Errorf("build fetch-bundle request: %w", err)
	}
	req.Header.Set("Accept", jsonMediaType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle from hub: %w", err)
	}
	defer resp.Body.Close()

	body, err := readHubResponse(resp, maxBundleEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("read bundle response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub returned %d: %s", resp.StatusCode, body)
	}

	var sb SignedBundle
	if err := json.Unmarshal(body, &sb); err != nil {
		return nil, fmt.Errorf("decode signed bundle: %w", err)
	}
	return &sb, nil
}

// FetchMeshPolicy retrieves an opaque signed policy envelope. The operator is
// only a bounded carrier: Continuum verifies the Ed25519 signature and trust
// context, so these exact response bytes must never be re-serialized here.
func (c *Client) FetchMeshPolicy(ctx context.Context) ([]byte, error) {
	req, err := c.authenticatedRequest(ctx, http.MethodGet, "/api/v1/mesh/policy", nil)
	if err != nil {
		return nil, fmt.Errorf("build fetch-mesh-policy request: %w", err)
	}
	req.Header.Set("Accept", jsonMediaType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch mesh policy from hub: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := readHubResponse(resp, maxMeshPolicyEnvelopeBytes)
	if readErr != nil {
		return nil, fmt.Errorf("read mesh policy response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub mesh policy returned %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Hanko-Mesh-Policy-Mode") != "audit-only" {
		return nil, fmt.Errorf("hub mesh policy response is missing the audit-only mode binding")
	}
	if len(body) == 0 || !json.Valid(body) {
		return nil, fmt.Errorf("hub mesh policy response is not valid JSON")
	}
	return append([]byte(nil), body...), nil
}

// VerifyBundle verifies a token-derived HMAC, not an independent signing key.
func (c *Client) VerifyBundle(sb *SignedBundle) bool {
	payload, err := json.Marshal(sb.Bundle)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sb.Signature))
}

// StatusAck is the Hub acknowledgement of a heartbeat. It is the only channel
// through which Hub can ask this operator to act: no inbound connection to the
// cluster exists.
type StatusAck struct {
	OK bool `json:"ok"`
	// Decommission is non-nil while a fleet decommission is pending for this
	// cluster. The credential stays valid until ConfirmDecommission succeeds.
	Decommission *DecommissionCommand `json:"decommission,omitempty"`
	// AgentUpdate is non-nil while Hub asks this operator to converge on the
	// published reference agent release. A pending decommission always
	// outranks it, so the two are never delivered together.
	AgentUpdate *AgentUpdateCommand `json:"agentUpdate,omitempty"`
}

// AgentUpdateCommand asks the operator to restart itself on the reference
// agent release. The operator preserves its current image repository and requires
// a locally approved digest/version/source revision and publisher signature.
// The command itself is not an image trust anchor.
type AgentUpdateCommand struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// DecommissionCommand asks the operator to uninstall its own release and
// confirm the cleanup inventory before the deadline.
type DecommissionCommand struct {
	RequestedAt time.Time `json:"requestedAt"`
	Deadline    time.Time `json:"deadline"`
}

var (
	ErrDecommissionExpired        = errors.New("hub decommission command has expired")
	ErrInvalidDecommissionCommand = errors.New("hub decommission command has invalid timestamps")
)

// Validate requires a current, bounded authorization window before any cleanup.
func (c *DecommissionCommand) Validate(now time.Time) error {
	if c == nil || c.RequestedAt.IsZero() || c.Deadline.IsZero() ||
		c.RequestedAt.After(now) || !c.Deadline.After(c.RequestedAt) {
		return ErrInvalidDecommissionCommand
	}
	if !now.Before(c.Deadline) {
		return ErrDecommissionExpired
	}
	return nil
}

// ErrDecommissionUnauthorized reports that Hub no longer accepts this
// operator's credential. After a confirmed decommission this is the expected
// outcome of a retry, so callers treat it as confirmation-equivalent.
var ErrDecommissionUnauthorized = errors.New("hub rejected the operator credential")

// ReportStatus sends the current reconciliation state to Hub and returns the
// acknowledgement, which may carry a pending decommission command.
func (c *Client) ReportStatus(ctx context.Context, status OperatorStatus) (*StatusAck, error) {
	b, err := json.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("marshal operator status: %w", err)
	}
	req, err := c.authenticatedRequest(ctx, http.MethodPost, "/api/v1/operators/status", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("build report-status request: %w", err)
	}
	req.Header.Set(contentTypeHeader, jsonMediaType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("report status to hub: %w", err)
	}
	defer resp.Body.Close()

	body, err := readHubResponse(resp, maxHubControlResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read status acknowledgement: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hub status report returned %d: %s", resp.StatusCode, body)
	}
	ack := &StatusAck{OK: true}
	// A legacy or proxy-altered body never fails the heartbeat itself; without
	// a decoded acknowledgement no command is delivered and Hub re-sends it on
	// the next heartbeat.
	if err := json.Unmarshal(body, ack); err != nil {
		return &StatusAck{OK: true}, nil
	}
	return ack, nil
}

// ConfirmDecommission reports the cleanup inventory that completes a pending
// decommission. Hub records the chained receipt and revokes this credential
// atomically, so it must be called before the operator deletes its own RBAC.
func (c *Client) ConfirmDecommission(ctx context.Context, removedResources map[string]int) error {
	b, err := json.Marshal(map[string]map[string]int{"removedResources": removedResources})
	if err != nil {
		return fmt.Errorf("marshal decommission confirmation: %w", err)
	}
	req, err := c.authenticatedRequest(ctx, http.MethodPost, "/api/v1/operators/decommission/confirm", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build decommission confirmation: %w", err)
	}
	req.Header.Set(contentTypeHeader, jsonMediaType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("confirm decommission with hub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrDecommissionUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := readHubResponse(resp, maxHubControlResponseBytes)
		if readErr != nil {
			return fmt.Errorf("read decommission confirmation: %w", readErr)
		}
		return fmt.Errorf("hub decommission confirmation returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

// readHubResponse bounds decompressed bytes even when Content-Length is absent
// or inaccurate. The extra byte detects oversize payloads instead of accepting
// a truncated JSON prefix. Error responses have a smaller diagnostic budget.
func readHubResponse(response *http.Response, limit int64) ([]byte, error) {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		limit = min(limit, maxHubErrorResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read hub response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("hub response (HTTP %d) exceeds %d bytes", response.StatusCode, limit)
	}
	return body, nil
}
