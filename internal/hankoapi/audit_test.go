package hankoapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuditClientRecordsMetadataOnlyRotation(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/internal/operator/audit" || request.Header.Get("Authorization") != "Bearer audit-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	client, err := NewAuditClient(server.URL, "audit-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedAt := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	if err := client.RecordServiceAccountRotation(context.Background(), "auth", "keycloak", "operator", "rot_123", rotatedAt); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != serviceAccountRotatedAction || payload["rotationId"] != "rot_123" {
		t.Fatalf("unexpected audit payload: %#v", payload)
	}
	if _, leaked := payload["secret"]; leaked {
		t.Fatalf("audit payload contains credential material: %#v", payload)
	}
}

func TestAuditClientFailsClosedOnConfigurationAndDeliveryErrors(t *testing.T) {
	if _, err := NewAuditClient("http://external.example", "token", nil); err == nil {
		t.Fatal("unsafe plain HTTP audit endpoint was accepted")
	}
	if _, err := NewAuditClient("https://hanko.example", "", nil); err == nil {
		t.Fatal("empty audit token was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client, err := NewAuditClient(server.URL, "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RecordServiceAccountRotation(context.Background(), "auth", "keycloak", "operator", "rot_123", time.Now()); err == nil {
		t.Fatal("audit delivery failure was acknowledged")
	}
}
