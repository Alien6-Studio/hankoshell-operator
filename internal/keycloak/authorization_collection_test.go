package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestAuthorizationCollectionReadsAllPagesWithinBudget(t *testing.T) {
	for _, count := range []int{0, 99, 100, 101, MaxAuthorizationCollectionObjects, MaxAuthorizationCollectionObjects + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					writeAuthorizationJSON(w, map[string]any{"access_token": "fixture-token", "expires_in": 300})
					return
				}
				first, _ := strconv.Atoi(r.URL.Query().Get("first"))
				if r.Method != http.MethodGet || r.URL.Query().Get("fields") != "*" || r.URL.Query().Get("max") != "100" || first != int(requests.Add(1)-1)*100 {
					http.Error(w, "invalid pagination", http.StatusBadRequest)
					return
				}
				items := []authorizationScopeRepresentation{}
				for i := first; i < min(first+100, count); i++ {
					items = append(items, authorizationScopeRepresentation{ID: strconv.Itoa(i), Name: "scope" + strconv.Itoa(i)})
				}
				writeAuthorizationJSON(w, items)
			}))
			defer server.Close()
			c := New(server.URL, "fixture", "fixture-secret", WithInsecureHTTP())
			got := []authorizationScopeRepresentation{{ID: "prior-result"}}
			err := readAuthorizationCollection(context.Background(), c, "/admin/realms/acme/clients/client/authz/resource-server/scope?fields=*", &got)
			if count > MaxAuthorizationCollectionObjects {
				if !errors.Is(err, ErrAuthorizationReadLimit) || len(got) != 1 || got[0].ID != "prior-result" {
					t.Fatal("partial over-budget collection escaped as complete", err)
				}
				return
			}
			if err != nil || len(got) != count || int(requests.Load()) != count/100+1 {
				t.Fatal("bounded complete read or pagination failed", err, len(got), requests.Load())
			}
			for i, item := range got {
				if item.ID != strconv.Itoa(i) {
					t.Fatal("page was omitted or duplicated")
				}
			}
		})
	}
}

func TestAuthorizationLaterPageOwnershipAndCleanup(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c, ctx := f.client(), context.Background()
	model := authorizationTestModel()
	model.OwnerUID = "paginated-owner"
	state, err := c.ReconcileAuthorization(ctx, model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for i := range 101 {
		id := fmt.Sprintf("000-native-%03d", i)
		f.scopes[id] = authorizationScopeRepresentation{ID: id, Name: id}
	}
	f.mu.Unlock()
	before := f.mutationCount()
	observed, err := c.ObserveAuthorization(ctx, model)
	if err != nil || observed.Drifted || !observed.Observation.Complete {
		t.Fatal("owned semantics beyond the first page were not observed", err)
	}
	if _, err := c.ReconcileAuthorization(ctx, model, state.ManagedObjects); err != nil || f.mutationCount() != before {
		t.Fatal("later-page ownership was mistaken for missing state", err)
	}
	f.ignoreDeletes = true
	if err := c.DeleteAuthorizationOwned(ctx, model, state.ResourceServerID, state.ManagedObjects); !errors.Is(err, ErrAuthorizationReadBack) {
		t.Fatal("later-page delete acknowledgement falsely proved retirement", err)
	}
	f.ignoreDeletes = false
	if err := c.DeleteAuthorizationOwned(ctx, model, state.ResourceServerID, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if !f.enabled || len(f.scopes) != 101 {
		t.Fatal("cleanup removed later-page native objects or missed owned objects")
	}
}

func TestAuthorizationCollectionOverflowRefusesObservationAndReconciliation(t *testing.T) {
	f := newAuthorizationTestServer(t)
	c, ctx := f.client(), context.Background()
	model := authorizationTestModel()
	model.OwnerUID = "read-budget-owner"
	state, err := c.ReconcileAuthorization(ctx, model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for i := range MaxAuthorizationCollectionObjects {
		id := fmt.Sprintf("000-native-%04d", i)
		f.scopes[id] = authorizationScopeRepresentation{ID: id, Name: id}
	}
	f.mu.Unlock()
	before := f.mutationCount()
	if _, err := c.ObserveAuthorization(ctx, model); !errors.Is(err, ErrAuthorizationReadLimit) {
		t.Fatal("oversize collection reported complete observation", err)
	}
	if _, err := c.ReconcileAuthorization(ctx, model, state.ManagedObjects); !errors.Is(err, ErrAuthorizationReadLimit) || f.mutationCount() != before {
		t.Fatal("oversize scope collection caused writes or accepted truncation", err)
	}
}
