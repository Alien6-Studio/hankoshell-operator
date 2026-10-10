//go:build keycloak_integration

package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealKeycloakInventoryPaginationAndSecondPageDenial(t *testing.T) {
	f := newKeycloakFixture(t)
	_, secret := f.serviceClient("bounded-inventory-reader")
	f.grantClientRoles("bounded-inventory-reader", "managed", []string{"view-realm", "view-clients", "view-users", "view-identity-providers", "view-authorization", "view-organizations"})
	base := "/admin/realms/managed"
	for i := 0; i < 101; i++ {
		f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": fmt.Sprintf("inventory-client-%03d", i), "protocol": "openid-connect", "enabled": true, "publicClient": true, "standardFlowEnabled": true, "redirectUris": []string{fmt.Sprintf("https://app-%03d.example.test/callback", i)}}, nil)
	}
	f.admin(http.MethodPut, base+"/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, base+"/admin-events?max=1000", nil, &events)
		return len(events)
	}
	for _, denied := range []bool{false, true} {
		f.run(fmt.Sprintf("second-page-denied=%t", denied), func(t *testing.T) {
			proxy, routes, ca := newAdoptionInventoryProxy(t, f, "bounded-inventory-reader", secret, func(r *http.Request) bool {
				return denied && r.URL.Path == base+"/clients" && r.URL.Query().Get("first") == "100"
			})
			var kube client.Client = &inventoryUIDClient{Client: newFakeClient(t)}
			source := &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta("inventory-source"), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "inventory-admin"}, TLSCARef: "inventory-ca"}}
			operation := &api.HankoImport{ObjectMeta: fixtureMeta("inventory-pagination"), Spec: api.HankoImportSpec{SourceRef: source.Name, Realms: []string{"managed"}, DryRun: true}}
			for _, o := range []client.Object{source, operation, &corev1.Secret{ObjectMeta: fixtureMeta("inventory-admin"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(proxy.BaseURL()), "HANKO_KC_CLIENT_ID": []byte("bounded-inventory-reader"), "HANKO_KC_CLIENT_SECRET": []byte(secret)}}, &corev1.Secret{ObjectMeta: fixtureMeta("inventory-ca"), Data: map[string][]byte{"ca.crt": ca}}} {
				f.requireNoError(kube.Create(context.Background(), o))
			}
			reconciler := &controller.HankoImportReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(f.kc), RequireHTTPS: true}
			iamconformance.NoMutation(t, writes, func() error {
				_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)})
				return err
			})
			fixtureGet(f, context.Background(), kube, operation)
			if operation.Status.Phase != "Done" || operation.Status.Coverage.Complete == denied {
				t.Fatal("terminal completion and inventory coverage confused")
			}
			if !denied && operation.Status.Discovered.Applications != 101 {
				t.Fatal("first page silently truncated client discovery")
			}
			if len(routes()) < 2 {
				t.Fatal("production inventory path not exercised")
			}
			f.requireNoCredentials("bounded pagination status", fixtureJSON(t, operation.Status))
		})
	}
	t.Logf("Keycloak %s: authenticated bounded multi-page inventory; second-page denial is incomplete; zero Admin writes", f.version)
}
