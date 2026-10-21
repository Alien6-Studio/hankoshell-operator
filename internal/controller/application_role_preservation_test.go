package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestApplicationWithoutDeclaredRolesPreservesProviderRoles(t *testing.T) {
	var calls, deletions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "expires_in": 300})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/managed/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "native-client", "clientId": "application"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/managed/clients/native-client/roles":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "foreign-role"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/admin/realms/managed/clients/native-client/roles/foreign-role":
			deletions.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	app := &api.HankoApplication{Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: "application"}}
	kc := keycloak.New(server.URL, "operator", "fixture-credential", keycloak.WithInsecureHTTP())
	if err := (&HankoApplicationReconciler{}).reconcileRoles(context.Background(), app, kc); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || deletions.Load() != 0 {
		t.Fatalf("undeclared role authority reached provider: calls=%d deletions=%d", calls.Load(), deletions.Load())
	}
}
