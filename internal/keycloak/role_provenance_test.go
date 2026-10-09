package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoleProvenanceObservedEdgesCyclesAndBounds(t *testing.T) {
	for _, test := range []struct {
		name          string
		length        int
		cycle, denied bool
	}{{"direct", 1, false, false}, {"composite", 3, false, false}, {"boundary", 33, false, false}, {"over-bound", 34, false, false}, {"cycle", 3, true, false}, {"denied", 3, false, true}} {
		t.Run(test.name, func(t *testing.T) {
			mutations := 0
			role := func(n int) RealmRole {
				return RealmRole{ID: fmt.Sprintf("id-%d", n), Name: fmt.Sprintf("role-%d", n), ContainerID: "realm", Composite: n < test.length-1 || test.cycle}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == orgProbeTokenPath {
					_, _ = w.Write([]byte(`{"access_token":"private-token-sentinel","expires_in":60}`))
					return
				}
				if r.Method != "GET" {
					mutations++
					w.WriteHeader(500)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/role-mappings") {
					if test.denied {
						w.WriteHeader(403)
						return
					}
					_ = json.NewEncoder(w).Encode(groupRoleMappings{RealmMappings: []RealmRole{role(0)}})
					return
				}
				if strings.HasSuffix(r.URL.Path, "/roles/role-0") {
					_ = json.NewEncoder(w).Encode(role(0))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/composites") {
					var n int
					_, _ = fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/admin/realms/acme/roles/role-"), "%d/composites", &n)
					next := n + 1
					if next == test.length {
						next = 0
					}
					_ = json.NewEncoder(w).Encode([]RealmRole{role(next)})
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			c := New(server.URL, "operator", "private-secret-sentinel", WithInsecureHTTP())
			paths, err := c.GetGroupRoleProvenance(context.Background(), "acme", "group")
			if test.cycle || test.length > 33 {
				if !errors.Is(err, ErrRoleProvenanceIncomplete) {
					t.Fatal("unsafe closure accepted", err)
				}
			} else if test.denied {
				if err == nil {
					t.Fatal("denied read ignored")
				}
			} else if err != nil || len(paths) != test.length || len(paths[len(paths)-1].Roles) != test.length {
				t.Fatal("direct/composite chain lost", err)
			}
			if mutations != 0 {
				t.Fatal("provenance introduced writes")
			}
		})
	}
}
