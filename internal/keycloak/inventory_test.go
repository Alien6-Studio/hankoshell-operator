package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestInventoryClientPaginationAndPartialReadsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		count      int
		failSecond bool
		replace    bool
	}{{"two pages", 101, false, false}, {"second page denied", 101, true, false}, {"overflow", 1025, false, false}, {"identity replaced", 1, false, true}} {
		t.Run(test.name, func(t *testing.T) {
			fullReads := 0
			pages := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					writeAuthorizationJSON(w, map[string]any{"access_token": "inventory-token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "client-secret") {
					t.Error("inventory attempted mutation or credentials")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if r.URL.Path == "/admin/realms/realm/clients" {
					first, _ := strconv.Atoi(r.URL.Query().Get("first"))
					if r.URL.Query().Get("max") != "100" {
						t.Error("pagination absent")
					}
					pages++
					if test.failSecond && first >= 100 {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					values := []InventoryClient{}
					for i := first; i < min(first+100, test.count); i++ {
						values = append(values, InventoryClient{Application: Application{ID: fmt.Sprintf("uuid-%04d", i), ClientID: fmt.Sprintf("client-%04d", i)}})
					}
					writeAuthorizationJSON(w, values)
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/admin/realms/realm/clients/uuid-")
				number, err := strconv.Atoi(id)
				if err != nil {
					t.Error("unexpected route")
					w.WriteHeader(http.StatusNotFound)
					return
				}
				fullReads++
				uuid := "uuid-" + id
				if test.replace {
					uuid = "replacement"
				}
				writeAuthorizationJSON(w, map[string]any{"id": uuid, "clientId": fmt.Sprintf("client-%04d", number), "protocol": "openid-connect", "secret": "secret-value-sentinel", "attributes": map[string]string{}})
			}))
			defer server.Close()
			c := New(server.URL, "inventory", "credential", WithInsecureHTTP())
			got, err := c.InventoryClients(context.Background(), "realm")
			if test.failSecond || test.replace || test.count > 1024 {
				if err == nil || len(got) != 0 {
					t.Fatal("incomplete list escaped as complete")
				}
				if test.count > 1024 && !errors.Is(err, ErrAuthorizationReadLimit) {
					t.Fatal("overflow not classified")
				}
				return
			}
			if err != nil || len(got) != test.count || pages != 2 || fullReads != 101 {
				t.Fatal("full paginated exact-UUID reads not exercised")
			}
		})
	}
}
func TestInventoryCollectionsHaveIndependentPageCoverage(t *testing.T) {
	for _, family := range []string{"realm-roles", "client-roles", "groups", "organizations"} {
		t.Run(family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					writeAuthorizationJSON(w, map[string]any{"access_token": "token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet {
					t.Error("mutating inventory")
				}
				first, _ := strconv.Atoi(r.URL.Query().Get("first"))
				if first == 100 {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				values := []map[string]any{}
				for i := 0; i < 100; i++ {
					values = append(values, map[string]any{"id": fmt.Sprintf("id-%03d", i), "name": fmt.Sprintf("object-%03d", i)})
				}
				writeAuthorizationJSON(w, values)
			}))
			defer server.Close()
			c := New(server.URL, "inventory", "credential", WithInsecureHTTP())
			var err error
			switch family {
			case "realm-roles":
				_, err = c.InventoryRealmRoles(context.Background(), "realm")
			case "client-roles":
				_, err = c.InventoryClientRoles(context.Background(), "realm", "client")
			case "groups":
				_, err = c.InventoryGroups(context.Background(), "realm", "")
			case "organizations":
				_, err = c.InventoryOrganizations(context.Background(), "realm")
			}
			if err == nil {
				t.Fatal("partial first page accepted")
			}
		})
	}
}

func TestInventoryBoundaryRejectsWritesCredentialsAndUnrelatedReads(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	c := New(server.URL, "reader", "credential", WithInsecureHTTP())
	c.RestrictToInventory()
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{
		{http.MethodGet, "/admin/realms/realm/clients", true},
		{http.MethodPost, "/admin/realms/realm/clients", false},
		{http.MethodPut, "/admin/realms/realm", false},
		{http.MethodDelete, "/admin/realms/realm/roles/role", false},
		{http.MethodGet, "/admin/realms/realm/clients/client/client-secret", false},
		{http.MethodPost, "/admin/realms/realm/clients/client/client-secret", false},
		{http.MethodGet, "/admin/serverinfo", false},
		{http.MethodPatch, "/admin/realms/realm/clients/client", false},
		{http.MethodGet, "/admin/realms/realm/users", false},
		{http.MethodGet, "/admin/realms/realm/groups/group/members", false},
		{http.MethodGet, "/admin/realms/realm/organizations/org/members", false},
		{http.MethodGet, "/admin/realms/realm/authentication/required-actions/CONFIGURE_TOTP", false},
	} {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := c.do(req)
		if response != nil {
			response.Body.Close()
		}
		if (err == nil) != tc.allowed {
			t.Fatal("inventory transport boundary not enforced")
		}
	}
	if calls != 1 {
		t.Fatal("forbidden inventory operation reached the network")
	}
}
