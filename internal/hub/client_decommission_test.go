package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDecommissionAuthorizationWindow(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	command := &DecommissionCommand{RequestedAt: now.Add(-time.Hour), Deadline: now}
	if err := command.Validate(now); !errors.Is(err, ErrDecommissionExpired) {
		t.Fatalf("deadline is exclusive: %v", err)
	}
	command.Deadline = now.Add(time.Second)
	if err := command.Validate(now); err != nil {
		t.Fatal(err)
	}
}

func TestReportStatusDeliversDecommissionCommand(t *testing.T) {
	requestedAt := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	deadline := requestedAt.Add(24 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/operators/status" || request.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"decommission": map[string]any{"requestedAt": requestedAt, "deadline": deadline},
		})
	}))
	t.Cleanup(server.Close)

	ack, err := New(server.URL, "tenant-1", "token").ReportStatus(context.Background(), OperatorStatus{Phase: "Synced"})
	if err != nil {
		t.Fatal(err)
	}
	if ack == nil || ack.Decommission == nil {
		t.Fatal("decommission command was not delivered")
	}
	if !ack.Decommission.RequestedAt.Equal(requestedAt) || !ack.Decommission.Deadline.Equal(deadline) {
		t.Fatalf("command window = %v..%v, want %v..%v",
			ack.Decommission.RequestedAt, ack.Decommission.Deadline, requestedAt, deadline)
	}
}

func TestReportStatusToleratesLegacyAckBodies(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     "",
		"legacy":    `{"ok":true}`,
		"malformed": `{`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := body
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, payload)
			}))
			t.Cleanup(server.Close)
			ack, err := New(server.URL, "tenant-1", "token").ReportStatus(context.Background(), OperatorStatus{Phase: "Synced"})
			if err != nil {
				t.Fatalf("heartbeat must survive a %s ack body: %v", name, err)
			}
			if ack == nil || ack.Decommission != nil {
				t.Fatalf("no command may be inferred from a %s ack body", name)
			}
		})
	}
}

func TestConfirmDecommission(t *testing.T) {
	var received map[string]map[string]int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/operators/decommission/confirm" || request.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"clusterID":"cluster-1"}`)
	}))
	t.Cleanup(server.Close)

	client := New(server.URL, "tenant-1", "token")
	if err := client.ConfirmDecommission(context.Background(), map[string]int{"secrets": 2}); err != nil {
		t.Fatal(err)
	}
	if received["removedResources"]["secrets"] != 2 {
		t.Fatalf("inventory not transmitted, got %v", received)
	}
}

func TestConfirmDecommissionSurfacesRevocationAndFailures(t *testing.T) {
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "revoked", http.StatusUnauthorized)
	}))
	t.Cleanup(unauthorized.Close)
	err := New(unauthorized.URL, "tenant-1", "token").ConfirmDecommission(context.Background(), nil)
	if !errors.Is(err, ErrDecommissionUnauthorized) {
		t.Fatalf("401 must map to ErrDecommissionUnauthorized, got %v", err)
	}

	conflict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no pending decommission", http.StatusConflict)
	}))
	t.Cleanup(conflict.Close)
	err = New(conflict.URL, "tenant-1", "token").ConfirmDecommission(context.Background(), nil)
	if err == nil || errors.Is(err, ErrDecommissionUnauthorized) {
		t.Fatalf("409 must fail without the revocation sentinel, got %v", err)
	}
}
