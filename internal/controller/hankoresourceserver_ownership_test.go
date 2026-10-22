package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestResourceServerBackingApplicationBoundary(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, scenario := range []string{"valid", "Observe application", "unmarked", "foreign owner", "stale application", "protected client", "provider drift"} {
			t.Run(fmt.Sprintf("%t/%s", imported, scenario), func(t *testing.T) {
				obj, objects := validResourceServerObjects(ModeManage)
				app := objects[1].(*api.HankoApplication)
				if imported {
					objects[0].SetLabels(map[string]string{importedByLabel: "inventory"})
				}
				var foreign atomic.Bool
				var writes atomic.Int64
				foreign.Store(scenario == "unmarked" || scenario == "foreign owner")
				if scenario == "Observe application" {
					app.Spec.Mode = ModeObserve
				}
				if scenario == "stale application" {
					app.Status.AppliedGeneration = 0
				}
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.URL.Path == "/realms/master/protocol/openid-connect/token" {
						_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic", "expires_in": 300})
						return
					}
					if req.Method != http.MethodGet {
						writes.Add(1)
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if req.URL.Path == "/admin/realms/acme/clients" {
						_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": app.Spec.ClientID}})
						return
					}
					attrs := map[string]string{"hanko.sh/application-owner": string(app.UID)}
					if foreign.Load() {
						attrs["hanko.sh/application-owner"] = "foreign-uid"
						if scenario == "unmarked" {
							delete(attrs, "hanko.sh/application-owner")
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "client-uuid", "clientId": app.Spec.ClientID, "serviceAccountsEnabled": true, "attributes": attrs})
				}))
				defer provider.Close()
				driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), state: authorization.State{Observation: successfulIAMObservation()}}
				if scenario == "provider drift" {
					driver.capabilityHook = func() { foreign.Store(true) }
				}
				backend := resourceServerClient(t, objects...)
				r := &HankoResourceServerReconciler{Client: backend, Pool: keycloak.NewPool(keycloak.New(provider.URL, "operator", "synthetic", keycloak.WithInsecureHTTP())),
					ProtectedRealm: "acme", DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
				if scenario == "protected client" {
					r.ProtectedClientIDs = []string{app.Spec.ClientID}
				}
				_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if scenario == "valid" {
					if err != nil || len(driver.reconcile) != 1 {
						t.Fatalf("owned application rejected: err=%v calls=%d", err, len(driver.reconcile))
					}
				} else if len(driver.reconcile) != 0 || writes.Load() != 0 {
					t.Fatalf("unowned backing client reached mutation: err=%v driver=%d writes=%d", err, len(driver.reconcile), writes.Load())
				}
			})
		}
	}
}
