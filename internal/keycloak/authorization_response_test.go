package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizationCreateReadsNativeObjectID(t *testing.T) {
	for _, test := range []struct {
		name, body, location, expected string
		valid                          bool
	}{
		{"scope representation", `{"id":"scope-id"}`, "", "scope-id", true},
		{"resource representation", `{"_id":"resource-id"}`, "", "resource-id", true},
		{"Location", `{}`, "/scope/location-id", "location-id", true},
		{"missing ID", `{}`, "", "", false},
		{"malformed", `not JSON`, "", "", false},
		{"oversized", strings.Repeat("a", (1<<20)+1), "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":60}`))
					return
				}
				if test.location != "" {
					w.Header().Set("Location", test.location)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := New(server.URL, "operator", "secret")
			id, err := client.authorizationCreate(context.Background(), "/admin/realms/managed/clients/client/authz/resource-server/scope", nil)
			if (err == nil) != test.valid || id != test.expected {
				t.Fatalf("id=%q valid=%t error=%v", id, test.valid, err)
			}
		})
	}
}
