package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestKeycloakIncompleteCollectionCannotProduceObservationProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			body = map[string]any{"access_token": "fixture-token", "expires_in": 300}
		case "/admin/realms/provider-realm/clients":
			body = []map[string]string{{"id": "client-uuid", "clientId": "client-id"}}
		case "/admin/realms/provider-realm/clients/client-uuid":
			body = map[string]any{"authorizationServicesEnabled": true}
		case "/admin/realms/provider-realm/clients/client-uuid/authz/resource-server/scope":
			// An oversized page cannot count as a complete provider observation.
			body = make([]map[string]string, 101)
		default:
			http.Error(w, "unexpected operation", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" && r.Method != http.MethodGet {
			http.Error(w, "writes denied", http.StatusForbidden)
			return
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	driver := NewKeycloakDriver(keycloak.New(server.URL, "fixture", "fixture-secret", keycloak.WithInsecureHTTP()))
	state, err := driver.Observe(context.Background(), contractPlan(t, contractModel(), iamcontract.Preconditions{}))
	if !errors.Is(err, iamcontract.ErrObservationIncomplete) || state.Observation.Complete || state.Observation.StateHash != "" {
		t.Fatal("incomplete provider read produced observation proof", err)
	}
}
