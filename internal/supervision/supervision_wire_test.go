package supervision_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/supervision"
)

func TestCollectPreservesAlertCoverageThroughAPIAndHeartbeatJSON(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		fragment   string
		wantCounts string
	}{
		{name: "observed zero", fragment: `,"alerts":{"openBySeverity":{}}`, wantCounts: "{}"},
		{name: "observed counts", fragment: `,"alerts":{"openBySeverity":{"HIGH":2}}`, wantCounts: `{"HIGH":2}`},
		{name: "explicit null counts", fragment: `,"alerts":{"openBySeverity":null}`, wantCounts: "null"},
		{name: "legacy missing counts", fragment: `,"alerts":{}`, wantCounts: "null"},
		{name: "explicit null digest", fragment: `,"alerts":null`},
		{name: "absent digest"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/internal/supervision/summary" || request.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("collector must use the authenticated supervision endpoint")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"observedAt":"2026-09-09T10:00:00Z","source":"api"` + scenario.fragment + `}`))
			}))
			defer server.Close()
			scheme := runtime.NewScheme()
			if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).Build()
			collector := supervision.New(reader, "auth", server.URL, "fixture-token")
			summary := collector.Collect(context.Background())
			if summary.Source != "api" {
				t.Fatalf("API summary was not collected: %#v", summary)
			}
			// Serialize the real heartbeat type used by the Hub client; checking
			// only the collector's Go map misses the omitempty regression.
			encoded, err := json.Marshal(hub.OperatorStatus{Phase: "Synced", Supervision: summary})
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Supervision map[string]json.RawMessage `json:"supervision"`
			}
			if err := json.Unmarshal(encoded, &payload); err != nil {
				t.Fatal(err)
			}
			rawAlerts, present := payload.Supervision["alerts"]
			if scenario.wantCounts == "" {
				if present || summary.Alerts != nil {
					t.Fatalf("absent digest fabricated alert coverage: %s", encoded)
				}
				return
			}
			var alerts map[string]json.RawMessage
			if !present || json.Unmarshal(rawAlerts, &alerts) != nil {
				t.Fatalf("API digest was lost in heartbeat: %s", encoded)
			}
			if string(alerts["openBySeverity"]) != scenario.wantCounts {
				t.Fatalf("counts changed across API/heartbeat: got %s, want %s", alerts["openBySeverity"], scenario.wantCounts)
			}
		})
	}
}
