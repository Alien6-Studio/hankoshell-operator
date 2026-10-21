package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportStatusCarriesAgentVersion(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil || json.Unmarshal(body, &payload) != nil {
			http.Error(w, "unreadable status", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	client := New(server.URL, "tenant-1", "token")
	if _, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Synced", AgentVersion: "defc534"}); err != nil {
		t.Fatal(err)
	}
	if payload["agentVersion"] != "defc534" {
		t.Fatalf("agentVersion not marshaled: %#v", payload)
	}

	payload = nil
	if _, err := client.ReportStatus(context.Background(), OperatorStatus{Phase: "Synced"}); err != nil {
		t.Fatal(err)
	}
	// Older-style reports must not send an empty field the Hub would have to
	// distinguish from "unknown": omitempty keeps the wire format additive.
	if _, present := payload["agentVersion"]; present {
		t.Fatalf("empty agentVersion must be omitted: %#v", payload)
	}
}
