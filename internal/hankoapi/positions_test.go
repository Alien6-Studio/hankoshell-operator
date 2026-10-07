package hankoapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsurePositionCreatesThenAdoptsByGroup(t *testing.T) {
	positions := []position{}
	patches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"positions": positions})
		case http.MethodPost:
			positions = append(positions, position{ID: "pos_1", GroupID: "group-1"})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(positions[0])
		case http.MethodPatch:
			patches++
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewPositionClient(server.URL, "operator-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := PositionSpec{Title: "R&D", GroupID: "group-1", RoleIDs: []string{"TRUNX_DEVELOPER"}}
	first, err := client.EnsurePosition(context.Background(), "shared", spec)
	if err != nil || first != "pos_1" {
		t.Fatalf("first EnsurePosition() = %q, %v", first, err)
	}
	second, err := client.EnsurePosition(context.Background(), "shared", spec)
	if err != nil || second != first || patches != 1 {
		t.Fatalf("second EnsurePosition() = %q, %v, patches=%d", second, err, patches)
	}
}

func TestNewPositionClientAllowsOnlySafeEndpoints(t *testing.T) {
	if _, err := NewPositionClient("http://hanko-api.auth.svc:8080", "token", nil); err != nil {
		t.Fatalf("cluster-local API URL rejected: %v", err)
	}
	if _, err := NewPositionClient("http://hanko.example", "token", nil); err == nil {
		t.Fatal("expected external plain HTTP URL to fail")
	}
	if _, err := NewPositionClient("https://hanko.example", "", nil); err == nil {
		t.Fatal("expected empty token to fail")
	}
}
