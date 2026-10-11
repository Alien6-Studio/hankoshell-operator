package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDependentReaderTransportRefusesCredentialsAndUnrelatedAuthority(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	c := New(server.URL, "dependent", "secret-sentinel", WithInsecureHTTP())
	if c.RestrictToDependentClients("managed") != nil {
		t.Fatal("restriction rejected")
	}
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/admin/realms/managed/clients?first=0&max=100", true}, {"GET", "/admin/realms/managed/clients/client-uuid", true},
		{"POST", "/realms/master/protocol/openid-connect/token", true},
		{"GET", "/admin/realms/managed/clients/client-uuid/client-secret", false},
		{"POST", "/admin/realms/managed/clients/client-uuid/client-secret", false},
		{"PUT", "/admin/realms/managed/clients/client-uuid", false}, {"DELETE", "/admin/realms/managed/clients/client-uuid", false},
		{"GET", "/admin/realms/managed/users", false}, {"GET", "/admin/realms/managed/clients/client-uuid/service-account-user", false},
		{"GET", "/admin/realms/master/clients", false}, {"GET", "/admin/realms/unrelated/clients", false},
		{"GET", "/admin/realms/managed", false}, {"GET", "/admin/serverinfo", false}, {"GET", "/realms/managed/.well-known/openid-configuration", false},
		{"GET", "/admin/realms/managed/clients?clientId=foo", false}, {"GET", "/admin/realms/managed/clients?viewableOnly=true", false},
		{"GET", "/admin/realms/managed/clients/client-uuid%2fclient-secret", false},
		{"GET", "/admin/realms/managed/clients/..", false},
		{"GET", "/admin/realms/managed/clients?first=0&max=1000", false},
		{"GET", "/admin/realms/managed/clients?first=-1&max=100", false},
	} {
		req, _ := http.NewRequest(test.method, server.URL+test.path, nil)
		response, err := c.do(req)
		if response != nil {
			response.Body.Close()
		}
		if (err == nil) != test.allowed {
			t.Errorf("%s %s allowed=%t", test.method, test.path, test.allowed)
		}
	}
	if requests != 3 {
		t.Fatal("a forbidden route reached the server")
	}
	if c.RestrictToDependentClients("unrelated") == nil {
		t.Fatal("restriction could widen target realm")
	}
}

func TestDependentReaderCompleteInventoryAndSecretExclusion(t *testing.T) {
	for _, test := range []struct {
		name                     string
		count                    int
		fail, replace, malformed bool
	}{
		{"multiple pages", 101, false, false, false}, {"second page denied", 101, true, false, false}, {"overflow", 1025, false, false, false},
		{"replacement", 1, false, true, false}, {"malformed dependent", 1, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pages, exact := 0, 0
			entry := func(i int, full bool) map[string]any {
				id := fmt.Sprintf("uuid-%04d", i)
				if full && test.replace {
					id = "replacement"
				}
				attrs := map[string]string{"jwt.credential.issuer": "cluster-one", "jwt.credential.sub": "system:serviceaccount:workloads:worker", "secret": "secret-sentinel"}
				if test.malformed {
					delete(attrs, "jwt.credential.issuer")
				}
				return map[string]any{"id": id, "clientId": fmt.Sprintf("client-%04d", i), "clientAuthenticatorType": "federated-jwt", "enabled": true, "secret": "secret-sentinel", "attributes": attrs}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					writeAuthorizationJSON(w, map[string]any{"access_token": "fixture-token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "client-secret") {
					t.Error("forbidden network operation")
					w.WriteHeader(403)
					return
				}
				if r.URL.Path == "/admin/realms/managed/clients" {
					pages++
					first, _ := strconv.Atoi(r.URL.Query().Get("first"))
					if test.fail && first >= 100 {
						w.WriteHeader(403)
						return
					}
					page := []map[string]any{}
					for i := first; i < min(first+100, test.count); i++ {
						page = append(page, entry(i, false))
					}
					writeAuthorizationJSON(w, page)
					return
				}
				n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/admin/realms/managed/clients/uuid-"))
				exact++
				writeAuthorizationJSON(w, entry(n, true))
			}))
			defer server.Close()
			c := New(server.URL, "reader", "credential", WithInsecureHTTP())
			_ = c.RestrictToDependentClients("managed")
			all, err := c.ListKubernetesWorkloadTrustDependents(context.Background(), "managed")
			if test.fail || test.replace || test.malformed || test.count > 1024 {
				if err == nil || len(all) != 0 {
					t.Fatal("incomplete inventory escaped as success")
				}
				return
			}
			if err != nil || len(all) != 101 || pages != 2 || exact != 101 {
				t.Fatal("complete paginated exact inventory absent")
			}
			encoded, _ := json.Marshal(all)
			if strings.Contains(string(encoded), "secret-sentinel") {
				t.Fatal("secret-derived field escaped projection")
			}
		})
	}
}
