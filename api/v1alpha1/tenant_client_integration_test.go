//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func checkTenantClientIsolation(t *testing.T, ctx context.Context, kube client.Client) {
	const ns = "tenant-routing"
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	var providerCalls atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer provider.Close()
	shared := keycloak.New(provider.URL, "fixture", "fixture")
	pool := keycloak.NewPool(shared)
	for _, mode := range []string{"manage", "observe", "delete"} {
		objects := []client.Object{
			&api.HankoRealm{},
			&api.HankoApplication{Spec: api.HankoApplicationSpec{RealmRef: "acme", ClientID: "application"}},
			&api.HankoServiceAccount{Spec: api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "service-account"}},
			&api.HankoOrganization{Spec: api.HankoOrganizationSpec{RealmRef: "acme", Name: "organization"}},
			&api.HankoRole{Spec: api.HankoRoleSpec{RealmRef: "acme", Name: "role"}},
			&api.HankoResourceServer{Spec: api.HankoResourceServerSpec{RealmRef: "acme", Audience: "audience", ApplicationRef: "application"}},
		}
		for index, obj := range objects {
			t.Run(fmt.Sprintf("%s-%T", mode, obj), func(t *testing.T) {
				obj.SetName(fmt.Sprintf("%s-%d", mode, index))
				obj.SetNamespace(ns)
				labels := map[string]string{"hanko.sh/tenant": "unregistered"}
				if mode == "observe" {
					labels["hanko.sh/imported-by"] = "inventory"
				}
				obj.SetLabels(labels)
				obj.SetFinalizers([]string{"fixture.test/retain"})
				if err := kube.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
				if mode == "delete" {
					if err := kube.Delete(ctx, obj); err != nil {
						t.Fatal(err)
					}
				}
				var reconciler reconcile.Reconciler
				switch obj.(type) {
				case *api.HankoRealm:
					reconciler = &controller.HankoRealmReconciler{Client: kube, Pool: pool}
				case *api.HankoApplication:
					reconciler = &controller.HankoApplicationReconciler{Client: kube, Pool: pool}
				case *api.HankoServiceAccount:
					reconciler = &controller.HankoServiceAccountReconciler{Client: kube, Pool: pool}
				case *api.HankoOrganization:
					reconciler = &controller.HankoOrganizationReconciler{Client: kube, Pool: pool}
				case *api.HankoRole:
					reconciler = &controller.HankoRoleReconciler{Client: kube, Pool: pool}
				case *api.HankoResourceServer:
					reconciler = &controller.HankoResourceServerReconciler{Client: kube, Pool: pool}
				}
				result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if err != nil || result.RequeueAfter == 0 {
					t.Fatalf("missing route was not deferred: %v %v", result, err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(obj)
				var stored struct {
					Status struct {
						Phase      string
						Conditions []metav1.Condition
					}
				}
				if err := json.Unmarshal(raw, &stored); err != nil {
					t.Fatal(err)
				}
				refused := false
				for _, condition := range stored.Status.Conditions {
					if condition.Type == "Synced" && condition.Reason == "TenantClientUnavailable" && condition.Status == metav1.ConditionFalse && condition.ObservedGeneration == obj.GetGeneration() {
						refused = true
					}
				}
				if !refused || stored.Status.Phase != "Error" || len(obj.GetFinalizers()) != 1 {
					t.Fatal("API storage lost the fail-closed routing status or cleanup protection")
				}
				if providerCalls.Load() != 0 {
					t.Fatal("unregistered tenant reached default provider")
				}
			})
		}
	}
	t.Run("registration-before-disconnected-Hub", func(t *testing.T) {
		var active atomic.Pointer[keycloak.Pool]
		var hubCalls atomic.Int64
		hubServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hubCalls.Add(1)
			if kc := active.Load().Get(ns + "/dedicated"); kc == nil || kc.BaseURL() != "https://dedicated.example" {
				t.Error("Hub contacted before tenant registration")
			}
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer hubServer.Close()
		tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "dedicated", Namespace: ns}, Spec: api.HankoTenantSpec{
			IsolationMode: "keycloak", KeycloakSecretRef: &corev1.LocalObjectReference{Name: "dedicated"}, HubEndpoint: hubServer.URL, HubTenantID: "tenant-id", HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub"},
		}}
		dedicated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "dedicated", Namespace: ns}, Data: map[string][]byte{
			"HANKO_KEYCLOAK_URL": []byte("https://dedicated.example"), "HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("fixture-credential"),
		}}
		hubSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub", Namespace: ns}, Data: map[string][]byte{
			"hub_token": []byte("fixture-token"), "expires_at": []byte(time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)),
		}}
		for _, obj := range []client.Object{tenant, dedicated, hubSecret} {
			if err := kube.Create(ctx, obj); err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			current := keycloak.NewPool(shared)
			active.Store(current)
			r := &controller.HankoTenantReconciler{Client: kube, APIReader: kube, Pool: current, HubHTTPClient: hubServer.Client()}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
				t.Fatal(err)
			}
			if current.Get(ns+"/dedicated") == nil {
				t.Fatal("Hub outage prevented registration after restart")
			}
		}
		before := hubCalls.Load()
		delete(dedicated.Data, "HANKO_KC_CLIENT_SECRET")
		if err := kube.Update(ctx, dedicated); err != nil {
			t.Fatal(err)
		}
		r := &controller.HankoTenantReconciler{Client: kube, APIReader: kube, Pool: active.Load(), HubHTTPClient: hubServer.Client()}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
			t.Fatal(err)
		}
		if active.Load().Get(ns+"/dedicated") != nil || hubCalls.Load() != before {
			t.Fatal("invalid credential retained routing or contacted Hub")
		}
	})
}
