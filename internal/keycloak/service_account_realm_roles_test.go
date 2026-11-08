package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func serviceAccountServer(t *testing.T, enabled bool, mapped []string, writes *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/realm/clients":
			_, _ = w.Write([]byte(`[{"id":"client-uuid","clientId":"robot"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/realm/clients/client-uuid/service-account-user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sa-user", "enabled": enabled})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/realms/realm/roles/"):
			name := strings.TrimPrefix(r.URL.Path, "/admin/realms/realm/roles/")
			_ = json.NewEncoder(w).Encode(RealmRole{ID: name + "-id", Name: name})
		case r.URL.Path == "/admin/realms/realm/users/sa-user/role-mappings/realm":
			if r.Method == http.MethodGet {
				roles := make([]RealmRole, 0, len(mapped))
				for _, name := range mapped {
					roles = append(roles, RealmRole{ID: name + "-id", Name: name})
				}
				_ = json.NewEncoder(w).Encode(roles)
				return
			}
			body, _ := io.ReadAll(r.Body)
			var roles []RealmRole
			_ = json.Unmarshal(body, &roles)
			for _, role := range roles {
				*writes = append(*writes, r.Method+" "+role.Name)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestServiceAccountRealmRolesTouchOnlyDesiredAndPreviousRoles(t *testing.T) {
	var writes []string
	server := serviceAccountServer(t, true, []string{"default-roles-realm", "STALE", "KEPT", "UNMANAGED"}, &writes)
	defer server.Close()
	c := New(server.URL, "operator", "fixture-credential", WithInsecureHTTP())
	err := c.ReconcileServiceAccountRealmRoles(context.Background(), "realm", "robot", []string{"KEPT", "NEW"}, []string{"KEPT", "STALE", "GONE"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(writes)
	if !slices.Equal(writes, []string{"DELETE STALE", "POST NEW"}) {
		t.Fatalf("unexpected service-account writes: %v", writes)
	}
}

func TestServiceAccountRealmRolesRequireEnabledServiceAccount(t *testing.T) {
	var writes []string
	server := serviceAccountServer(t, false, nil, &writes)
	defer server.Close()
	c := New(server.URL, "operator", "fixture-credential", WithInsecureHTTP())
	err := c.ReconcileServiceAccountRealmRoles(context.Background(), "realm", "robot", []string{"NEW"}, nil)
	if !errors.Is(err, ErrServiceAccountUnavailable) || len(writes) != 0 {
		t.Fatalf("disabled service account was mutated: %v %v", err, writes)
	}
	if _, err := c.ReadServiceAccountRealmRoles(context.Background(), "realm", Application{}); !errors.Is(err, ErrApplicationPrecondition) {
		t.Fatal("unresolved client reached the service-account endpoint")
	}
}

func TestServiceAccountGrantWitnessCannotReachOtherUsers(t *testing.T) {
	witness := serviceAccountGrant{realm: "acme", clientUUID: "client-uuid", userID: "sa-user"}
	for _, test := range []struct {
		method, path string
		witness      *serviceAccountGrant
		allowed      bool
	}{
		{http.MethodPost, "/admin/realms/acme/users/sa-user/role-mappings/realm", &witness, true},
		{http.MethodGet, "/admin/realms/acme/clients/client-uuid/service-account-user", &witness, true},
		{http.MethodPost, "/admin/realms/acme/users/sa-user/role-mappings/realm", nil, false},
		{http.MethodPost, "/admin/realms/acme/users/admin-user/role-mappings/realm", &witness, false},
		{http.MethodDelete, "/admin/realms/foreign/users/sa-user/role-mappings/realm", &witness, false},
		{http.MethodPost, "/admin/realms/acme/users/sa-user/role-mappings/realm?first=0", &witness, false},
		{http.MethodPut, "/admin/realms/acme/clients/client-uuid/service-account-user", &witness, false},
		{http.MethodGet, "/admin/realms/acme/clients/other-uuid/service-account-user", &witness, false},
	} {
		request, err := http.NewRequest(test.method, "https://keycloak.test"+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.witness != nil {
			request = request.WithContext(context.WithValue(request.Context(), serviceAccountGrantKey{}, *test.witness))
		}
		granted, err := validateServiceAccountGrant(request, request.URL.EscapedPath())
		if !granted || (err == nil) != test.allowed {
			t.Fatalf("%s %s: granted=%v err=%v", test.method, test.path, granted, err)
		}
	}
}
