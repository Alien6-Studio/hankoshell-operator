// Package supervision collects a bounded supervision summary that the
// operator attaches to its Hub heartbeat: the health of the Keycloak
// instances it observes and, when a local hankoShell API is configured, the alert
// digest and audit chain head served by that API. The summary deliberately
// carries no actor identities and no event details — only what the fleet view
// needs to show that a cluster requires attention.
package supervision

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

// Summary is the supervision snapshot sent to the Hub. The JSON shape is
// duplicated in the Hub store (SupervisionSummary) and must stay compatible.
type Summary struct {
	ObservedAt time.Time   `json:"observedAt"`
	Source     string      `json:"source"` // "operator" or "api"
	Components []Component `json:"components,omitempty"`
	Alerts     *Alerts     `json:"alerts,omitempty"`
	Audit      *Audit      `json:"audit,omitempty"`
}

// Component is the health of one component observed on the cluster.
type Component struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "healthy" or "degraded"
	Detail string `json:"detail,omitempty"`
}

// Alerts is a digest of the open alerts reported by the local hankoShell API.
type Alerts struct {
	// OpenBySeverity preserves an observed empty API digest as {}; nil is unknown.
	OpenBySeverity map[string]int `json:"openBySeverity"`
	// ActiveBySeverity relays the API's activity-window counts; nil means the
	// local API predates the field — F-26 (#378).
	ActiveBySeverity map[string]int `json:"activeBySeverity,omitempty"`
	Recent           []AlertItem    `json:"recent,omitempty"`
}

// AlertItem is one recent alert, stripped of actor and detail.
type AlertItem struct {
	ID       string    `json:"id"`
	FiredAt  time.Time `json:"firedAt"`
	Severity string    `json:"severity"`
	Action   string    `json:"action"`
	RealmID  string    `json:"realmId,omitempty"`
	// Active is a pointer so an API predating the field stays unknown
	// downstream instead of reading as historical.
	Active *bool `json:"active,omitempty"`
}

// Audit is the tamper-evident head of the cluster's audit chain.
type Audit struct {
	ChainHeadID   string     `json:"chainHeadId,omitempty"`
	ChainHeadHash string     `json:"chainHeadHash,omitempty"`
	LastEventAt   *time.Time `json:"lastEventAt,omitempty"`
	TotalEntries  int        `json:"totalEntries"`
}

const (
	statusHealthy  = "healthy"
	statusDegraded = "degraded"

	// apiFetchTimeout bounds the optional local API call so a slow or dead
	// hanko-api cannot delay the reconciliation loop.
	apiFetchTimeout = 5 * time.Second
)

// Collector builds Summary values. The zero value is not usable; construct it
// with New.
type Collector struct {
	reader     client.Reader
	namespace  string
	apiURL     string
	apiToken   string
	httpClient *http.Client
}

// New returns a Collector observing Keycloak instances in namespace through
// reader. apiURL and apiToken are optional: when both are set the collector
// also fetches the richer summary from the local hankoShell API supervision
// endpoint.
func New(reader client.Reader, namespace, apiURL, apiToken string) *Collector {
	return &Collector{
		reader:     reader,
		namespace:  namespace,
		apiURL:     strings.TrimRight(strings.TrimSpace(apiURL), "/"),
		apiToken:   strings.TrimSpace(apiToken),
		httpClient: &http.Client{Timeout: apiFetchTimeout},
	}
}

// RequireHTTPS secures the optional enterprise API summary client before use.
func (c *Collector) RequireHTTPS() error {
	if c.apiURL == "" || c.apiToken == "" {
		return nil
	}
	secured, err := httpsecurity.RequireHTTPS(c.httpClient, c.apiURL)
	if err != nil {
		return err
	}
	c.httpClient = secured
	return nil
}

// Collect never fails: it returns whatever could be observed, degrading the
// summary instead of erroring so a heartbeat is never blocked by supervision.
func (c *Collector) Collect(ctx context.Context) *Summary {
	summary := &Summary{
		ObservedAt: time.Now().UTC(),
		Source:     "operator",
		Components: c.keycloakComponents(ctx),
	}
	if c.apiURL == "" || c.apiToken == "" {
		return summary
	}
	api, err := c.fetchAPISummary(ctx)
	if err != nil {
		// Only the error class reaches the Hub, never credentials or full
		// request context.
		summary.Components = append(summary.Components, Component{
			Name:   "hanko-api",
			Status: statusDegraded,
			Detail: "supervision endpoint unreachable",
		})
		return summary
	}
	summary.Source = "api"
	summary.Components = append(summary.Components, api.Components...)
	summary.Alerts = api.Alerts
	summary.Audit = api.Audit
	return summary
}

// keycloakComponents maps every observed HankoKeycloakInstance to a component
// health entry. Phase Ready is healthy; every other phase is degraded.
func (c *Collector) keycloakComponents(ctx context.Context) []Component {
	var list hankoshv1alpha1.HankoKeycloakInstanceList
	if err := c.reader.List(ctx, &list, client.InNamespace(c.namespace)); err != nil {
		return []Component{{
			Name:   "keycloak-instances",
			Status: statusDegraded,
			Detail: "unable to list HankoKeycloakInstance resources",
		}}
	}
	components := make([]Component, 0, len(list.Items))
	for _, instance := range list.Items {
		component := Component{
			Name:   "keycloak/" + instance.Name,
			Status: statusHealthy,
		}
		if instance.Status.Phase != "Ready" {
			component.Status = statusDegraded
			component.Detail = "phase " + defaultPhase(instance.Status.Phase)
		}
		components = append(components, component)
	}
	return components
}

func defaultPhase(phase string) string {
	if phase == "" {
		return "Pending"
	}
	return phase
}

// fetchAPISummary retrieves the bounded summary from the local hankoShell API.
func (c *Collector) fetchAPISummary(ctx context.Context) (*Summary, error) {
	ctx, cancel := context.WithTimeout(ctx, apiFetchTimeout)
	defer cancel()
	url := c.apiURL + "/internal/supervision/summary"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build supervision request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch supervision summary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) //nolint:errcheck // drain for connection reuse
		return nil, fmt.Errorf("supervision endpoint returned %d", resp.StatusCode)
	}
	var out Summary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode supervision summary: %w", err)
	}
	return &out, nil
}
