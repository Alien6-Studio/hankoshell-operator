package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssignClientRolesToGroupAddsOnlyMissing(t *testing.T) {
	var posted []clientRoleRef
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "trunx-dashboard"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/groups/group-uuid/role-mappings/clients/client-uuid":
			_ = json.NewEncoder(w).Encode([]clientRoleRef{{ID: "role-admin", Name: "TRUNX_ACCOUNT_ADMIN"}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/realms/acme/clients/client-uuid/roles/"):
			name := strings.TrimPrefix(r.URL.Path, "/admin/realms/acme/clients/client-uuid/roles/")
			_ = json.NewEncoder(w).Encode(clientRoleRef{ID: "id-" + name, Name: name})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/acme/groups/group-uuid/role-mappings/clients/client-uuid":
			postCalls++
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Errorf("decode role-mapping payload: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret")
	err := client.AssignClientRolesToGroup(context.Background(), "acme", "group-uuid",
		"trunx-dashboard", []string{"TRUNX_ACCOUNT_ADMIN", "TRUNX_DEVELOPER"})
	if err != nil {
		t.Fatalf("AssignClientRolesToGroup: %v", err)
	}
	if postCalls != 1 || len(posted) != 1 {
		t.Fatalf("expected one POST with the single missing role, got %d calls, payload %#v", postCalls, posted)
	}
	if posted[0].Name != "TRUNX_DEVELOPER" || posted[0].ID != "id-TRUNX_DEVELOPER" {
		t.Fatalf("posted role = %#v, want TRUNX_DEVELOPER with resolved id", posted[0])
	}
}

func TestAssignClientRolesToGroupAllPresentIsNoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "trunx-dashboard"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/groups/group-uuid/role-mappings/clients/client-uuid":
			_ = json.NewEncoder(w).Encode([]clientRoleRef{{ID: "role-dev", Name: "TRUNX_DEVELOPER"}})
		case r.Method == http.MethodPost:
			t.Errorf("unexpected POST %s: already-mapped roles must not be rewritten", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret")
	err := client.AssignClientRolesToGroup(context.Background(), "acme", "group-uuid",
		"trunx-dashboard", []string{"TRUNX_DEVELOPER"})
	if err != nil {
		t.Fatalf("AssignClientRolesToGroup: %v", err)
	}
}

func TestAssignClientRolesToGroupMissingClientFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == orgProbeTokenPath:
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/acme/clients":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret")
	err := client.AssignClientRolesToGroup(context.Background(), "acme", "group-uuid",
		"ghost", []string{"ANY"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("a missing client must surface as an error, got %v", err)
	}
}

func TestAssignClientRolesToGroupEmptyIsNoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s for an empty role list", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := New(server.URL, "client", "secret")
	if err := client.AssignClientRolesToGroup(context.Background(), "acme", "group-uuid", "trunx-dashboard", nil); err != nil {
		t.Fatalf("AssignClientRolesToGroup with no roles: %v", err)
	}
}
