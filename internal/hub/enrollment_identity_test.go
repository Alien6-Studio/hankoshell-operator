package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentIdentityPayloadAndLegacyOmission(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		identity EnrollmentIdentity
		legacy   bool
	}{
		{name: "legacy", legacy: true},
		{name: "identified", identity: EnrollmentIdentity{ClusterName: "Paris Équipe_1", ClusterUID: "stable-namespace-uid"}},
		{name: "unnamed", identity: EnrollmentIdentity{ClusterUID: "stable-namespace-uid"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var body map[string]string
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Errorf("decode enrollment request: %v", err)
				}
				if request.Method != http.MethodPost || request.URL.Path != "/api/v1/operators/enroll" || body["enrollToken"] != "single-use-fixture" {
					t.Error("unexpected enrollment request contract")
				}
				for key, value := range map[string]string{"clusterName": scenario.identity.ClusterName, "clusterUID": scenario.identity.ClusterUID} {
					actual, present := body[key]
					if actual != value || present != (value != "") {
						t.Errorf("%s = %q, present = %v; want %q and omit empty fields", key, actual, present, value)
					}
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(EnrollResult{ClusterID: "cluster-fixture", TenantID: "tenant-fixture", Token: "bounded-fixture", ExpiresAt: time.Now().Add(time.Hour)})
			}))
			defer server.Close()
			var err error
			if scenario.legacy {
				_, err = Enroll(context.Background(), server.URL, "single-use-fixture")
			} else {
				_, err = EnrollWithIdentity(context.Background(), server.URL, "single-use-fixture", scenario.identity)
			}
			if err != nil {
				t.Fatalf("enroll: %v", err)
			}
		})
	}
}

func TestEnrollmentRejectionNeverRetriesWithoutIdentity(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls++
				if status == http.StatusBadRequest {
					var legacy struct {
						EnrollToken string `json:"enrollToken"`
					}
					decoder := json.NewDecoder(request.Body)
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&legacy); err == nil {
						t.Error("metadata was silently dropped for an old Hub")
					}
				}
				http.Error(w, "identity metadata rejected", status)
			}))
			defer server.Close()
			_, err := EnrollWithIdentity(context.Background(), server.URL, "single-use-fixture", EnrollmentIdentity{ClusterName: "Paris", ClusterUID: "stable-uid"})
			if err == nil || !strings.Contains(err.Error(), "identity metadata rejected") || calls != 1 {
				t.Fatalf("rejected enrollment: calls = %d, error = %v", calls, err)
			}
		})
	}
}
