//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The default connection has real write authority: absence of mutation must come
// from tenant routing, not a forbidden credential or an unreachable test server.
func TestRealKeycloakTenantRouting(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	var before map[string]any
	if f.admin(http.MethodGet, "/admin/realms/managed", nil, &before) != http.StatusOK {
		t.Fatal("cannot inspect fixture realm")
	}
	realm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed"), Spec: api.HankoRealmSpec{DisplayName: "Tenant routing qualification"}}
	realm.Labels = map[string]string{"hanko.sh/tenant": "dedicated"}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&api.HankoRealm{}).WithObjects(realm).Build()
	pool := keycloak.NewPool(f.kc)
	r := &controller.HankoRealmReconciler{Client: kube, Pool: pool}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}
	assertBlocked := func() {
		t.Helper()
		_, err := r.Reconcile(ctx, req)
		f.requireNoError(err)
		fixtureGet(f, ctx, kube, realm)
		if realm.Status.Phase != "Error" {
			t.Fatal("unregistered tenant was not refused")
		}
		found := false
		for _, c := range realm.Status.Conditions {
			if c.Type == "Synced" && c.Status == metav1.ConditionFalse && c.Reason == "TenantClientUnavailable" {
				found = true
			}
		}
		if !found {
			t.Fatal("distinct missing registration reason absent")
		}
		var actual map[string]any
		if f.admin(http.MethodGet, "/admin/realms/managed", nil, &actual) != http.StatusOK {
			t.Fatal("cannot inspect fixture realm")
		}
		fixtureEqual(t, "shared provider preserved by refused tenant", actual, before)
	}
	assertBlocked()
	restricted, _ := f.serviceClient("fixture-no-admin")
	pool.Register("qualification/dedicated", restricted)
	// An explicitly registered but forbidden client must not trigger fallback.
	_, _ = r.Reconcile(ctx, req)
	var unchanged map[string]any
	if f.admin(http.MethodGet, "/admin/realms/managed", nil, &unchanged) != http.StatusOK {
		t.Fatal("cannot inspect fixture realm")
	}
	fixtureEqual(t, "forbidden dedicated provider does not fall back", unchanged, before)
	pool.Register("qualification/dedicated", f.kc)
	fixtureReconcile(f, ctx, r, realm)
	fixtureGet(f, ctx, kube, realm)
	if realm.Status.Phase != "Ready" {
		t.Fatalf("registered provider did not resume reconciliation: phase=%s", realm.Status.Phase)
	}
	if f.admin(http.MethodGet, "/admin/realms/managed", nil, &before) != http.StatusOK {
		t.Fatal("cannot inspect fixture realm")
	}
	if before["displayName"] != realm.Spec.DisplayName {
		t.Fatal("registered tenant did not reach the real provider")
	}
	pool.Remove("qualification/dedicated")
	assertBlocked()
}
