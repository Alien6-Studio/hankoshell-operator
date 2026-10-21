package observability

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
)

func TestMetricsCardinalityAndSecretSentinels(t *testing.T) {
	m := New()
	registry := prometheus.NewRegistry()
	m.Register(registry)
	for index := 0; index < 2000; index++ {
		arbitrary := fmt.Sprintf("sentinel-credential-%d", index)
		m.Provider(arbitrary, arbitrary, 0, errors.New(arbitrary), time.Millisecond)
		m.Reconcile(arbitrary, arbitrary, time.Millisecond)
		m.Verification(arbitrary, errors.New(arbitrary))
		m.Event(arbitrary, arbitrary)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if len(family.Metric) > 1 {
			t.Fatalf("unbounded labels in %s: %d", family.GetName(), len(family.Metric))
		}
		data, marshalErr := json.Marshal(family)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if strings.Contains(string(data), "sentinel-credential") {
			t.Fatalf("secret in metrics %s", family.GetName())
		}
	}
	m.Inventory(true, map[string]int{"ready": 3, "degraded": 2}, nil, nil)
	m.Inventory(false, nil, nil, nil)
	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "hanko_operator_inventory_complete" && family.Metric[0].Gauge.GetValue() != 0 {
			t.Fatal("incomplete inventory looks healthy")
		}
		if family.GetName() == "hanko_operator_instances" {
			t.Fatal("stale inventory survived failure")
		}
	}
}
func TestEventsDiscardUntrustedTextAndBoundReasonVocabulary(t *testing.T) {
	delegate := events.NewFakeRecorder(4)
	recorder := SafeRecorder(delegate)
	recorder.Eventf(&corev1.Pod{}, nil, "attacker-type", "attacker-reason", "attacker-action", "credential=%s", "secret-sentinel")
	event := <-delegate.Events
	for _, forbidden := range []string{"attacker", "secret-sentinel", "credential="} {
		if strings.Contains(event, forbidden) {
			t.Fatalf("untrusted event content: %s", event)
		}
	}
	if !strings.Contains(event, "UnclassifiedEvent") {
		t.Fatal("missing bounded fallback reason")
	}
	for reason, message := range EventMessages() {
		recorder.Eventf(&corev1.Pod{}, nil, "Normal", reason, "Finalize", "secret-sentinel")
		if event = <-delegate.Events; !strings.Contains(event, message) || strings.Contains(event, "secret-sentinel") {
			t.Fatalf("catalog drift: %s", event)
		}
	}
}

func TestTenantFleetRefusalsPreserveOnlyReviewedReasons(t *testing.T) {
	if TenantRefusalReason("BundleTenantConflict") != "BundleTenantConflict" {
		t.Fatal("bundle ownership refusal lost its Event identity")
	}
	for reason := range tenantEventReasons {
		if TenantRefusalReason(reason) != reason {
			t.Fatal("reviewed Fleet refusal lost its Event identity", reason)
		}
	}
	for _, reason := range []string{"FleetAttackerSecret", "FleetSignatureInvalid\nsecret", "ClientCreated", "secret-sentinel", ""} {
		if TenantRefusalReason(reason) != "TenantReconcileRefused" {
			t.Fatal("unreviewed tenant reason escaped the catalog")
		}
	}
	delegate := events.NewFakeRecorder(1)
	SafeRecorder(delegate).Eventf(&corev1.Pod{}, nil, "Warning", TenantRefusalReason("FleetSignatureInvalid"), "Reconcile", "secret-sentinel")
	if event := <-delegate.Events; !strings.Contains(event, "FleetSignatureInvalid") || strings.Contains(event, "secret-sentinel") {
		t.Fatal("Fleet refusal lost identity or leaked details")
	}
}

func TestCustomMetricSeriesUpperBound(t *testing.T) {
	m := New()
	registry := prometheus.NewRegistry()
	m.Register(registry)
	for _, kind := range append(append([]string{}, kinds...), "unknown") {
		for _, outcome := range []string{"success", "requeue", "error", "panic", "unknown"} {
			m.Reconcile(kind, outcome, time.Second)
		}
	}
	for _, provider := range []string{"keycloak", "authentik", "unknown"} {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "unknown"} {
			for _, status := range []int{200, 300, 400, 500, 199} {
				m.Provider(provider, method, status, nil, time.Second)
			}
			m.Provider(provider, method, 0, errors.New("withheld"), time.Second)
		}
	}
	for _, domain := range []string{"iam", "fleet", "image", "unknown"} {
		m.Verification(domain, nil)
		m.Verification(domain, errors.New("withheld"))
	}
	for reason := range EventMessages() {
		for _, eventType := range []string{"Normal", "Warning", "unknown"} {
			m.Event(reason, eventType)
		}
	}
	m.Inventory(true, nil, nil, nil)
	m.Leader(true)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	series := 0
	for _, family := range families {
		for _, metric := range family.Metric {
			if metric.Histogram != nil {
				series += len(metric.Histogram.Bucket) + 3
			} else {
				series++
			}
		}
	}
	if series != 1114 {
		t.Fatalf("custom series bound changed: %d", series)
	}
}
