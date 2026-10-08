//go:build keycloak_integration

package controller_test

import (
	"context"
	"errors"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"net/http"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type failEvidenceStatusClient struct {
	client.Client
	fail bool
}
type failEvidenceStatusWriter struct {
	client.SubResourceWriter
	owner *failEvidenceStatusClient
}

func (c *failEvidenceStatusClient) Status() client.SubResourceWriter {
	return &failEvidenceStatusWriter{SubResourceWriter: c.Client.Status(), owner: c}
}
func (w *failEvidenceStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if w.owner.fail {
		w.owner.fail = false
		return errors.New("injected Kubernetes status failure")
	}
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

// checkRealKeycloakEvidenceRecovery proves status recovery through actual domain
// adapters and the same scoped identity as the shared conformance fixture.
func checkRealKeycloakEvidenceRecovery(t *testing.T, f *keycloakFixture, kc *keycloak.Client, credential string) {
	ctx := context.Background()
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)
		return len(events)
	}
	for _, domain := range []string{"role", "authorization"} {
		f.run(domain+" status patch recovery", func(t *testing.T) {
			realm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}
			var obj client.Object
			objects := []client.Object{realm}
			if domain == "role" {
				obj = &api.HankoRole{ObjectMeta: fixtureMeta("evidence-role"), Spec: api.HankoRoleSpec{RealmRef: "managed", Name: "evidence-role", Description: "desired"}}
			} else {
				f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "evidence-api", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true}, nil)
				objects = append(objects, &api.HankoApplication{ObjectMeta: fixtureMeta("evidence-app"), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: "evidence-api"}})
				obj = &api.HankoResourceServer{ObjectMeta: fixtureMeta("evidence-server"), Spec: api.HankoResourceServerSpec{RealmRef: "managed", ApplicationRef: "evidence-app", Audience: "urn:evidence", Scopes: []api.AuthorizationScope{{Name: "read", Description: "desired"}}, Resources: []api.AuthorizationResource{{Name: "document", Scopes: []string{"read"}, URIs: []string{"/document"}}}, Permissions: []api.AuthorizationPermission{{Name: "allow", Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "application", Ref: "evidence-app"}}}}}}
			}
			objects = append(objects, obj)
			k8s := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objects...).WithStatusSubresource(&api.HankoRole{}, &api.HankoResourceServer{}).Build()
			fault := &failEvidenceStatusClient{Client: k8s, fail: true}
			var reconciler fixtureReconciler
			if domain == "role" {
				reconciler = &controller.HankoRoleReconciler{Client: fault, DriverFactory: func(string, map[string]string) roles.Driver { return roles.NewKeycloakDriver(kc) }}
			} else {
				reconciler = &controller.HankoResourceServerReconciler{Client: fault, DriverFactory: func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(kc) }}
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			if _, err := reconciler.Reconcile(ctx, request); err == nil {
				t.Fatal("injected status failure was ignored")
			}
			fixtureGet(f, ctx, k8s, obj)
			if domain == "role" && obj.(*api.HankoRole).Status.AppliedGeneration != 0 {
				t.Fatal("failed patch stored application proof")
			}
			if domain == "authorization" && obj.(*api.HankoResourceServer).Status.AppliedGeneration != 0 {
				t.Fatal("failed patch stored application proof")
			}
			iamconformance.NoMutation(t, writes, func() error { _, err := reconciler.Reconcile(ctx, request); return err })
			fixtureGet(f, ctx, k8s, obj)
			var applied, observed, evaluated string
			if domain == "role" {
				s := obj.(*api.HankoRole).Status
				applied, observed, evaluated = s.AppliedPlanHash, s.ObservedStateHash, s.EvaluatedPlanHash
				if s.AppliedGeneration != 1 || s.DriftState != "InSync" {
					t.Fatal("role proof did not recover")
				}
			} else {
				s := obj.(*api.HankoResourceServer).Status
				applied, observed, evaluated = s.AppliedPlanHash, s.ObservedStateHash, s.EvaluatedPlanHash
				if s.AppliedGeneration != 1 || s.DriftState != "InSync" {
					t.Fatal("authorization proof did not recover")
				}
			}
			if applied != evaluated || !iamcontract.ValidDigest(observed) {
				t.Fatal("proof lacks matching read-back")
			}
			iamconformance.NoSecrets(t, []string{credential, f.adminToken}, obj)
		})
	}
}
