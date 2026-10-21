package supervision

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

type listErrorReader struct {
	client.Reader
}

func (listErrorReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("list unavailable")
}

type errorTransport struct{}

func (errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network unavailable")
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	return scheme
}

func keycloakInstance(name, phase string) *hankoshv1alpha1.HankoKeycloakInstance {
	return &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"},
		Status:     hankoshv1alpha1.HankoKeycloakInstanceStatus{Phase: phase},
	}
}

func fakeReader(t *testing.T, objects ...client.Object) client.Reader {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
}

func TestCollectReportsNativeKeycloakHealth(t *testing.T) {
	reader := fakeReader(t, keycloakInstance("main", "Ready"), keycloakInstance("probing", "Probing"))
	collector := New(reader, "auth", "", "")

	summary := collector.Collect(context.Background())
	if summary.Source != "operator" {
		t.Fatalf("source: got %q, want %q", summary.Source, "operator")
	}
	if len(summary.Components) != 2 {
		t.Fatalf("component count: got %d, want 2", len(summary.Components))
	}
	byName := map[string]Component{}
	for _, c := range summary.Components {
		byName[c.Name] = c
	}
	if byName["keycloak/main"].Status != "healthy" {
		t.Fatalf("ready instance must be healthy: %#v", byName["keycloak/main"])
	}
	if got := byName["keycloak/probing"]; got.Status != "degraded" || got.Detail != "phase Probing" {
		t.Fatalf("non-ready instance must be degraded with its phase: %#v", got)
	}
	if summary.Alerts != nil || summary.Audit != nil {
		t.Fatal("native summary must not carry alert or audit sections")
	}
}

func TestCollectMergesAPISummaryWhenConfigured(t *testing.T) {
	apiSummary := Summary{
		Source:     "api",
		Components: []Component{{Name: "keycloak", Status: "healthy"}},
		Alerts:     &Alerts{OpenBySeverity: map[string]int{"HIGH": 2}},
		Audit:      &Audit{ChainHeadID: "ae_7", TotalEntries: 7},
	}
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/internal/supervision/summary" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(apiSummary)
	}))
	defer server.Close()

	collector := New(fakeReader(t, keycloakInstance("main", "Ready")), "auth", server.URL, "secret-token")
	summary := collector.Collect(context.Background())

	if gotAuth != "Bearer secret-token" {
		t.Fatalf("authorization header: got %q", gotAuth)
	}
	if summary.Source != "api" {
		t.Fatalf("source: got %q, want %q", summary.Source, "api")
	}
	// Native Keycloak components come first, API components are appended.
	if len(summary.Components) != 2 {
		t.Fatalf("component count: got %d, want 2", len(summary.Components))
	}
	if summary.Alerts == nil || summary.Alerts.OpenBySeverity["HIGH"] != 2 {
		t.Fatalf("alert digest was not merged: %#v", summary.Alerts)
	}
	if summary.Audit == nil || summary.Audit.ChainHeadID != "ae_7" {
		t.Fatalf("audit head was not merged: %#v", summary.Audit)
	}
}

func TestCollectDegradesWhenAPIUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	collector := New(fakeReader(t, keycloakInstance("main", "Ready")), "auth", server.URL, "wrong-token")
	summary := collector.Collect(context.Background())

	if summary.Source != "operator" {
		t.Fatalf("source must stay %q on API failure, got %q", "operator", summary.Source)
	}
	last := summary.Components[len(summary.Components)-1]
	if last.Name != "hanko-api" || last.Status != "degraded" {
		t.Fatalf("API failure must surface as a degraded hanko-api component: %#v", last)
	}
	if summary.Alerts != nil || summary.Audit != nil {
		t.Fatal("failed API fetch must not fabricate alert or audit sections")
	}
}

func TestCollectDegradesWhenKeycloakListFails(t *testing.T) {
	collector := New(listErrorReader{}, "auth", "", "")
	summary := collector.Collect(context.Background())
	if len(summary.Components) != 1 || summary.Components[0].Name != "keycloak-instances" || summary.Components[0].Status != statusDegraded {
		t.Fatalf("list failure component = %#v", summary.Components)
	}
}

func TestCollectDefaultsEmptyKeycloakPhase(t *testing.T) {
	collector := New(fakeReader(t, keycloakInstance("main", "")), "auth", "", "")
	summary := collector.Collect(context.Background())
	if len(summary.Components) != 1 || summary.Components[0].Detail != "phase Pending" {
		t.Fatalf("empty phase component = %#v", summary.Components)
	}
}

func TestFetchAPISummaryRejectsMalformedEndpoint(t *testing.T) {
	collector := New(fakeReader(t), "auth", "://invalid", "token")
	if _, err := collector.fetchAPISummary(context.Background()); err == nil {
		t.Fatal("invalid API endpoint was accepted")
	}
}

func TestFetchAPISummarySurfacesTransportFailure(t *testing.T) {
	collector := New(fakeReader(t), "auth", "https://api.invalid", "token")
	collector.httpClient = &http.Client{Transport: errorTransport{}}
	if _, err := collector.fetchAPISummary(context.Background()); err == nil {
		t.Fatal("transport failure was ignored")
	}
}

func TestFetchAPISummaryRejectsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	t.Cleanup(server.Close)
	collector := New(fakeReader(t), "auth", server.URL, "token")
	if _, err := collector.fetchAPISummary(context.Background()); err == nil {
		t.Fatal("malformed supervision summary was accepted")
	}
}
