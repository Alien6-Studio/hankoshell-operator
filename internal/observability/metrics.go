// Package observability owns the bounded, provider-independent operational contract.
package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// kinds is the complete supported label vocabulary. Object identities never label metrics.
var kinds = []string{"HankoApplication", "HankoEmailProvider", "HankoIAMProfile", "HankoImport", "HankoIssuer", "HankoKeycloakInstance", "HankoMeshService", "HankoOperation", "HankoOrganization", "HankoRealm", "HankoResourceServer", "HankoRole", "HankoServiceAccount", "HankoSnapshot", "HankoTenant", "HankoTheme", "HankoWorkloadTrust"}

// Metrics keeps vectors private so callers cannot create arbitrary label values.
type Metrics struct {
	reconciles       *prometheus.CounterVec
	reconcileSeconds *prometheus.HistogramVec
	requests         *prometheus.CounterVec
	requestSeconds   *prometheus.HistogramVec
	verification     *prometheus.CounterVec
	events           *prometheus.CounterVec
	instances        *prometheus.GaugeVec
	rotations        *prometheus.GaugeVec
	overdue          *prometheus.GaugeVec
	inventory        prometheus.Gauge
	leader           prometheus.Gauge
}

func New() *Metrics {
	return &Metrics{
		reconciles:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hanko_operator_reconcile_total", Help: "Completed reconciliation attempts by kind and bounded outcome."}, []string{"kind", "outcome"}),
		reconcileSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "hanko_operator_reconcile_duration_seconds", Help: "Reconciliation attempt duration.", Buckets: prometheus.DefBuckets}, []string{"kind"}),
		requests:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hanko_operator_provider_requests_total", Help: "Provider HTTP attempts by provider, method and status class."}, []string{"provider", "method", "outcome"}),
		requestSeconds:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "hanko_operator_provider_request_duration_seconds", Help: "Provider HTTP duration including bounded response reads.", Buckets: prometheus.DefBuckets}, []string{"provider", "method"}),
		verification:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hanko_operator_verification_total", Help: "Fleet, IAM and image verification decisions."}, []string{"domain", "outcome"}),
		events:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hanko_operator_events_total", Help: "Sanitized Event submissions, not API persistence acknowledgements."}, []string{"reason", "type"}),
		instances:        prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "hanko_operator_instances", Help: "Current instance counts from the bounded inventory."}, []string{"state"}),
		rotations:        prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "hanko_operator_rotations", Help: "Scheduled credential rotations by kind and current state."}, []string{"kind", "state"}),
		overdue:          prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "hanko_operator_rotation_overdue_seconds", Help: "Oldest overdue scheduled credential rotation by kind."}, []string{"kind"}),
		inventory:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "hanko_operator_inventory_complete", Help: "One only when all bounded inventory lists succeeded without truncation."}),
		leader:           prometheus.NewGauge(prometheus.GaugeOpts{Name: "hanko_operator_leader", Help: "One after this running manager acquired the reconciliation lease."}),
	}
}

var Default = New()

func (m *Metrics) Register(reg prometheus.Registerer) {
	reg.MustRegister(m.reconciles, m.reconcileSeconds, m.requests, m.requestSeconds, m.verification, m.events, m.instances, m.rotations, m.overdue, m.inventory, m.leader)
}

func vocabulary(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "other"
}

func (m *Metrics) Reconcile(kind, outcome string, elapsed time.Duration) {
	kind = vocabulary(kind, kinds...)
	m.reconciles.WithLabelValues(kind, vocabulary(outcome, "success", "requeue", "error", "panic")).Inc()
	m.reconcileSeconds.WithLabelValues(kind).Observe(elapsed.Seconds())
}

func (m *Metrics) Provider(provider, method string, status int, err error, elapsed time.Duration) {
	provider = vocabulary(provider, "keycloak", "authentik")
	method = vocabulary(method, http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions)
	outcome := "transport_error"
	if err == nil {
		switch {
		case status >= 200 && status < 300:
			outcome = "2xx"
		case status >= 300 && status < 400:
			outcome = "3xx"
		case status >= 400 && status < 500:
			outcome = "4xx"
		case status >= 500 && status < 600:
			outcome = "5xx"
		default:
			outcome = "other"
		}
	}
	m.requests.WithLabelValues(provider, method, outcome).Inc()
	m.requestSeconds.WithLabelValues(provider, method).Observe(elapsed.Seconds())
}

func (m *Metrics) Verification(domain string, err error) {
	outcome := "accepted"
	if err != nil {
		outcome = "refused"
	}
	m.verification.WithLabelValues(vocabulary(domain, "iam", "fleet", "image"), outcome).Inc()
}

func (m *Metrics) Event(reason, eventType string) {
	reason = EventReason(reason)
	m.events.WithLabelValues(reason, vocabulary(eventType, "Normal", "Warning")).Inc()
}

func (m *Metrics) Leader(active bool) {
	if active {
		m.leader.Set(1)
	} else {
		m.leader.Set(0)
	}
}

// Inventory publishes only complete samples. A failure invalidates the previous
// snapshot; stale partial counts must never look like recovery.
func (m *Metrics) Inventory(complete bool, instances map[string]int, rotations map[string]map[string]int, overdue map[string]float64) {
	m.inventory.Set(0)
	m.instances.Reset()
	m.rotations.Reset()
	m.overdue.Reset()
	if !complete {
		return
	}
	for _, state := range []string{"ready", "degraded", "pending"} {
		m.instances.WithLabelValues(state).Set(float64(instances[state]))
	}
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount", "HankoKeycloakInstance"} {
		for _, state := range []string{"scheduled", "overdue", "failed"} {
			m.rotations.WithLabelValues(kind, state).Set(float64(rotations[kind][state]))
		}
		m.overdue.WithLabelValues(kind).Set(overdue[kind])
	}
	m.inventory.Set(1)
}
