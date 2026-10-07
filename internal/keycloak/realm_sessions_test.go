package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogoutAllRealmSessionsUsesAdministrativeEndpoint(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case "/admin/realms/acme/logout-all":
			if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer token" {
				t.Fatalf("logout request = %s headers=%v", request.Method, request.Header)
			}
			called = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)

	client := New(server.URL, "operator", "secret")
	if err := client.LogoutAllRealmSessions(t.Context(), "acme"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("realm logout endpoint was not called")
	}
}
