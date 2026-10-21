//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Native exchange success does not promote the operator's stronger capability.
// Audit events and full client snapshots independently prove no provider mutation.
func qualifyDelegationRefusal(e *exchangeExperiment) {
	f := e.f
	operator, _ := f.serviceClient("delegation-refusal-operator")
	f.grantClientRoles("delegation-refusal-operator", "managed", []string{"manage-clients"})
	f.admin(http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)
		if len(events) >= 1000 {
			f.t.Fatal("delegation audit inventory is not complete")
		}
		return len(events)
	}
	beforeWrites := writes()
	beforeClients := []map[string]any{f.client("managed", e.actor.name), f.client("managed", e.subject.name), f.client("managed", e.api.name)}
	for _, mode := range []string{"Manage", "Observe", "Imported"} {
		f.run("operator refuses unqualified delegation "+mode, func(t *testing.T) {
			realm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}
			app := &api.HankoApplication{ObjectMeta: fixtureMeta("api"), Spec: api.HankoApplicationSpec{RealmRef: realm.Name, ClientID: e.api.name, Protocol: "oidc"}}
			actor := &api.HankoServiceAccount{ObjectMeta: fixtureMeta("actor"), Spec: api.HankoServiceAccountSpec{RealmRef: realm.Name, ClientID: e.actor.name}}
			subject := &api.HankoServiceAccount{ObjectMeta: fixtureMeta("subject"), Spec: api.HankoServiceAccountSpec{RealmRef: realm.Name, ClientID: e.subject.name}}
			obj := &api.HankoResourceServer{ObjectMeta: fixtureMeta("delegation"), Spec: api.HankoResourceServerSpec{
				RealmRef: realm.Name, ApplicationRef: app.Name, Audience: e.api.name, Mode: mode,
				Scopes: []api.AuthorizationScope{{Name: "read"}}, Resources: []api.AuthorizationResource{{Name: "invoice", Scopes: []string{"read"}}},
				Permissions: []api.AuthorizationPermission{{Name: "delegated-read", Resources: []string{"invoice"}, Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "service_account", Ref: subject.Name}}, Delegation: &api.AuthorizationDelegation{
					Actor: api.AuthorizationDelegationIdentity{Kind: "service_account", Ref: actor.Name}, Subject: api.AuthorizationDelegationIdentity{Kind: "service_account", Ref: subject.Name},
				}}},
			}}
			if mode == "Imported" {
				obj.Spec.Mode = "Manage"
				obj.Labels = map[string]string{controller.ImportedByLabel: "inventory"}
			}
			kube := newFakeClient(t, realm, app, actor, subject, obj)
			for range 2 {
				r := &controller.HankoResourceServerReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(operator)}
				_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if !errors.Is(err, authorization.ErrCapabilityUnsupported) {
					t.Fatal("operator did not refuse native profile", err)
				}
			}
			f.requireNoError(kube.Get(context.Background(), client.ObjectKeyFromObject(obj), obj))
			if obj.Status.AppliedPlanHash != "" || obj.Status.EvaluatedPlanHash != "" || len(obj.Finalizers) != 0 || obj.Status.Capabilities.BoundedDelegation || len(obj.Status.Findings) != 1 || obj.Status.Findings[0].Code != "DelegationUnsupported" {
				t.Fatal("unsupported delegation claimed executable authority")
			}
			data, err := json.Marshal(obj.Status)
			f.requireNoError(err)
			f.requireNoCredentials("delegation refusal status", data)
		})
	}
	fixtureEqual(f.t, "refused delegation creates no admin events", writes(), beforeWrites)
	fixtureEqual(f.t, "refused delegation preserves native clients", []map[string]any{f.client("managed", e.actor.name), f.client("managed", e.subject.name), f.client("managed", e.api.name)}, beforeClients)
}
