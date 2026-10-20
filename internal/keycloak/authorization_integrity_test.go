package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthorizationObservationResolvesSharedPrincipalsOnceAndRefreshesNextAttempt(t *testing.T) {
	var roles, clients atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			writeAuthorizationJSON(w, map[string]any{"access_token": "fixture-token", "expires_in": 300})
		case "/admin/realms/acme/roles/reader":
			writeAuthorizationJSON(w, RealmRole{ID: fmt.Sprintf("role-%d", roles.Add(1)), Name: "reader"})
		case "/admin/realms/acme/clients":
			writeAuthorizationJSON(w, []map[string]string{{"id": fmt.Sprintf("client-%d", clients.Add(1)), "clientId": "caller"}})
		default:
			t.Errorf("unexpected native request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := New(server.URL, "operator", "fixture", WithInsecureHTTP())
	model := AuthorizationModel{Realm: "acme"}
	for i := range 64 {
		model.Permissions = append(model.Permissions, AuthorizationPermission{Name: strconv.Itoa(i), Principals: []AuthorizationPrincipal{
			{Kind: "realm_role", Ref: "reader"}, {Kind: "application", Ref: "caller"}, {Kind: "service_account", Ref: "caller"},
			{Kind: "organization", Ref: "org", Groups: []AuthorizationGroupDefinition{{ID: "group-id"}}},
		}})
	}
	for attempt := int32(1); attempt <= 2; attempt++ {
		roleIDs, clientIDs := map[string]string{}, map[string]string{}
		names, err := c.authorizationPrincipalNames(t.Context(), model, roleIDs, clientIDs)
		if err != nil || roles.Load() != attempt || clients.Load() != attempt || len(names) != 3 {
			t.Fatal("shared principal resolution was repeated or reused across attempts", err, roles.Load(), clients.Load())
		}
		for _, permission := range model.Permissions {
			r, cs, gs := observedAuthorizationPrincipals(permission.Principals, roleIDs, clientIDs)
			if len(r) != 1 || r[0].ID != fmt.Sprintf("role-%d", attempt) || len(cs) != 2 || cs[0] != fmt.Sprintf("client-%d", attempt) || len(gs) != 1 {
				t.Fatal("observation lost a permission binding", r, cs, gs)
			}
		}
	}
}

func checkAuthorizationCollectionIdentity[T any](t *testing.T, path, idField, scenario string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeAuthorizationJSON(w, map[string]any{"access_token": "fixture-token", "expires_in": 300})
			return
		}
		items := []map[string]string{{idField: "id-1", "name": "name-1"}, {idField: "id-2", "name": "name-2"}}
		switch scenario {
		case "duplicate-id":
			items[1][idField] = "id-1"
		case "duplicate-name":
			items[1]["name"] = "name-1"
		case "missing-id":
			delete(items[1], idField)
		case "missing-name":
			delete(items[1], "name")
		case "overlapping-pages":
			items = nil
			if r.URL.Query().Get("first") == "0" {
				for i := range 100 {
					items = append(items, map[string]string{idField: strconv.Itoa(i), "name": "item-" + strconv.Itoa(i)})
				}
			} else {
				items = []map[string]string{{idField: "0", "name": "item-0"}}
			}
		}
		writeAuthorizationJSON(w, items)
	}))
	defer server.Close()
	c := New(server.URL, "operator", "fixture", WithInsecureHTTP())
	var sentinel T
	got := []T{sentinel}
	if err := readAuthorizationCollection(context.Background(), c, "/admin/realms/acme/clients/client-uuid/authz/resource-server"+path, &got); !errors.Is(err, ErrAuthorizationReadLimit) || !reflect.DeepEqual(got, []T{sentinel}) {
		t.Fatal("ambiguous or partial inventory escaped into reconciliation", err)
	}
}

func TestAuthorizationInventoryRejectsAmbiguousIdentitiesAcrossPages(t *testing.T) {
	for _, scenario := range []string{"duplicate-id", "duplicate-name", "missing-id", "missing-name", "overlapping-pages"} {
		t.Run(scenario, func(t *testing.T) {
			checkAuthorizationCollectionIdentity[authorizationScopeRepresentation](t, "/scope", "id", scenario)
			checkAuthorizationCollectionIdentity[authorizationResourceRepresentation](t, "/resource", "_id", scenario)
			checkAuthorizationCollectionIdentity[authorizationPolicyRepresentation](t, "/policy", "id", scenario)
			checkAuthorizationCollectionIdentity[authorizationPermissionRepresentation](t, "/permission", "id", scenario)
		})
	}
}

func TestAuthorizationTypedPoliciesMustMatchTheCompleteGenericInventory(t *testing.T) {
	for _, kind := range []string{"role", "client", "group"} {
		for _, scenario := range []string{"valid", "missing", "orphan", "renamed", "changed-type", "duplicated"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				generic := authorizationPolicyRepresentation{ID: "id", Name: "owned", Type: kind}
				index := authorizationPolicyIndex{byID: map[string]authorizationPolicyRepresentation{"id": generic}, byName: map[string]authorizationPolicyRepresentation{"owned": generic}}
				typed := []authorizationPolicyRepresentation{generic}
				switch scenario {
				case "missing":
					typed = nil
				case "orphan":
					typed[0].ID = "unknown"
				case "renamed":
					typed[0].Name = "other"
				case "changed-type":
					typed[0].Type = "scope"
				case "duplicated":
					typed = append(typed, generic)
				}
				err := mergeTypedAuthorizationPolicies(&index, kind, typed)
				if scenario == "valid" && err != nil || scenario != "valid" && !errors.Is(err, ErrAuthorizationReadLimit) {
					t.Fatal("typed identity boundary differs", err)
				}
			})
		}
	}
}

func TestAuthorizationPermissionReadBackRefusesInconsistentOrIncompleteBindings(t *testing.T) {
	for _, scenario := range []string{"valid", "missing-typed", "orphan", "renamed", "changed-type", "null-bindings", "duplicate-bindings", "missing-binding-id", "over-budget"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					writeAuthorizationJSON(w, map[string]any{"access_token": "fixture-token", "expires_in": 300})
					return
				}
				permission := authorizationPermissionRepresentation{ID: "permission-id", Name: "owned", Type: "scope"}
				switch {
				case strings.HasSuffix(r.URL.Path, "/permission"):
					writeAuthorizationJSON(w, []authorizationPermissionRepresentation{permission})
				case strings.HasSuffix(r.URL.Path, "/permission/scope"):
					items := []authorizationPermissionRepresentation{permission}
					switch scenario {
					case "missing-typed":
						items = []authorizationPermissionRepresentation{}
					case "orphan":
						items[0].ID = "unknown"
					case "renamed":
						items[0].Name = "other"
					case "changed-type":
						items[0].Type = "resource"
					}
					writeAuthorizationJSON(w, items)
				default:
					bindings := []map[string]string{{"id": "policy-id"}}
					switch scenario {
					case "null-bindings":
						bindings = nil
					case "duplicate-bindings":
						bindings = append(bindings, bindings[0])
					case "missing-binding-id":
						bindings = []map[string]string{{}}
					case "over-budget":
						bindings = nil
						for i := range MaxAuthorizationCollectionObjects + 1 {
							bindings = append(bindings, map[string]string{"id": strconv.Itoa(i)})
						}
					}
					writeAuthorizationJSON(w, bindings)
				}
			}))
			defer server.Close()
			c := New(server.URL, "operator", "fixture", WithInsecureHTTP())
			_, byName, err := c.loadAuthorizationPermissions(t.Context(), "/admin/realms/acme/clients/client-uuid/authz/resource-server")
			if scenario == "valid" {
				if err != nil || !reflect.DeepEqual(byName["owned"].Policies, []string{"policy-id"}) {
					t.Fatal("valid native permission was rejected", err)
				}
			} else if !errors.Is(err, ErrAuthorizationReadLimit) || byName != nil {
				t.Fatal("partial permission read-back was accepted", err)
			}
		})
	}
}

func TestAuthorizationMalformedInventoryCannotTriggerManagedWrites(t *testing.T) {
	for _, path := range []string{"/scope", "/resource", "/policy", "/permission"} {
		t.Run(path, func(t *testing.T) {
			f := newAuthorizationTestServer(t)
			model := authorizationTestModel()
			model.OwnerUID = "inventory-owner"
			first, err := f.client().ReconcileAuthorization(t.Context(), model, AuthorizationManagedObjects{})
			if err != nil {
				t.Fatal(err)
			}
			mutations := f.mutationCount()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/realms/acme/clients/client-uuid/authz/resource-server"+path {
					row := map[string]string{"id": "duplicate-id", "_id": "duplicate-id", "name": "duplicate-name", "type": "scope"}
					writeAuthorizationJSON(w, []map[string]string{row, row})
					return
				}
				f.ServeHTTP(w, r)
			}))
			defer server.Close()
			c := New(server.URL, "operator", "fixture", WithInsecureHTTP())
			if _, err := c.ObserveAuthorization(t.Context(), model); !errors.Is(err, ErrAuthorizationReadLimit) {
				t.Fatal("malformed inventory became an observation", err)
			}
			if _, err := c.ReconcileAuthorization(t.Context(), model, first.ManagedObjects); !errors.Is(err, ErrAuthorizationReadLimit) {
				t.Fatal("malformed inventory reached managed reconciliation", err)
			}
			if f.mutationCount() != mutations {
				t.Fatal("incomplete native read triggered a write")
			}
		})
	}
}
