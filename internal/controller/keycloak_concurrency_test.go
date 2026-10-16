//go:build keycloak_integration

package controller_test

import (
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealKeycloakConcurrentCredentialBudget(t *testing.T) {
	f := newKeycloakFixture(t)
	_, secret := f.serviceClient("concurrent-reader")
	f.grantClientRoles("concurrent-reader", "managed", []string{"view-realm"})
	upstream, err := url.Parse(f.baseURL)
	f.requireNoError(err)
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(upstream); r.Out.Host = upstream.Host },
		Transport: f.http.Transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "fixture upstream unavailable", http.StatusBadGateway)
		},
	}
	var tokens, active, maximum, reads atomic.Int32
	var throttle atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isToken := r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token"
		if !isToken && (r.Method != http.MethodGet || r.URL.Path != "/admin/realms/managed") {
			http.Error(w, "fixture route denied", http.StatusForbidden)
			return
		}
		current := active.Add(1)
		defer active.Add(-1)
		for previous := maximum.Load(); current > previous; previous = maximum.Load() {
			if maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		if isToken {
			tokens.Add(1)
		} else if throttle.Load() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "fixture throttled", http.StatusTooManyRequests)
			return
		} else {
			reads.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	kc, err := keycloak.NewWithTLS(server.URL, "concurrent-reader", secret, ca)
	f.requireNoError(err)
	views := []*keycloak.Client{kc, kc.WithMutationGuard(nil), kc.WithMutationGuard(nil).WithMutationGuard(nil)}
	wave := func(throttled bool) {
		var wg sync.WaitGroup
		for index := range 128 {
			connection := views[index%len(views)]
			wg.Go(func() {
				observed, err := connection.GetRealm(t.Context(), "managed")
				if throttled {
					var status *keycloak.StatusError
					if !errors.As(err, &status) || status.Code != http.StatusTooManyRequests {
						t.Error("throttled read lost its numeric status")
					}
				} else if err != nil || observed == nil || observed.URLName() != "managed" {
					t.Error("concurrent read failed")
				}
			})
		}
		wg.Wait()
	}
	wave(false)
	if tokens.Load() != 1 || reads.Load() != 128 || maximum.Load() > 8 {
		t.Fatal("guarded views multiplied token requests or exceeded the shared network budget")
	}
	throttle.Store(true)
	wave(true)
	time.Sleep(1100 * time.Millisecond)
	throttle.Store(false)
	wave(false)
	if tokens.Load() != 1 || reads.Load() != 256 || maximum.Load() > 8 {
		t.Fatal("cooldown recovery lost credential sharing or request bounds")
	}
	t.Logf("Keycloak %s: 3 guarded views, 256 successful concurrent HTTPS reads, 128 bounded refusals, %d token request, peak %d in flight", f.version, tokens.Load(), maximum.Load())
	qualifyConcurrentApplications(t, f)
	qualifyConcurrentIAMKinds(t, f)
}

func qualifyConcurrentIAMKinds(t *testing.T, f *keycloakFixture) {
	t.Helper()
	if f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"organizationsEnabled": true}, nil) != http.StatusNoContent {
		t.Fatal("fixture cannot enable native organizations")
	}
	writer, _ := f.serviceClient("parallel-iam-writer")
	f.grantClientRoles("parallel-iam-writer", "managed", []string{"view-realm", "manage-realm", "manage-clients", "manage-users", "manage-organizations", "manage-authorization"})
	kube := newFakeClient(t, &api.HankoRealm{ObjectMeta: fixtureMeta("managed")})
	pool := keycloak.NewPool(writer)
	apps := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: newScheme(t), Pool: pool}
	roles := &controller.HankoRoleReconciler{Client: kube, APIReader: kube, Pool: pool}
	orgs := &controller.HankoOrganizationReconciler{Client: kube, APIReader: kube, Pool: pool, ProjectionMode: hankoapi.ProjectionDisabled}
	grants := &controller.HankoResourceServerReconciler{Client: kube, APIReader: kube, Pool: pool}
	var leaves, servers []client.Object
	for index := range 6 {
		name := fmt.Sprintf("parallel-%02d", index)
		leaves = append(leaves,
			&api.HankoApplication{ObjectMeta: fixtureMeta(name), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: name, Type: "m2m"}},
			&api.HankoRole{ObjectMeta: fixtureMeta(name), Spec: api.HankoRoleSpec{RealmRef: "managed", Name: name}},
			&api.HankoOrganization{ObjectMeta: fixtureMeta(name), Spec: api.HankoOrganizationSpec{RealmRef: "managed", Name: name, Slug: name}})
		servers = append(servers, &api.HankoResourceServer{ObjectMeta: fixtureMeta(name), Spec: api.HankoResourceServerSpec{
			RealmRef: "managed", ApplicationRef: name, Audience: "urn:" + name,
			Scopes: []api.AuthorizationScope{{Name: "read"}}, Resources: []api.AuthorizationResource{{Name: "document", Scopes: []string{"read"}}},
			Permissions: []api.AuthorizationPermission{{Name: "readers", Scopes: []string{"read"}, Resources: []string{"document"}, Principals: []api.AuthorizationPrincipal{{Kind: "realm_role", Ref: name}}}},
		}})
	}
	run := func(objects []client.Object) {
		var workers sync.WaitGroup
		for _, obj := range objects {
			workers.Go(func() {
				request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
				var err error
				switch obj.(type) {
				case *api.HankoApplication:
					_, err = apps.Reconcile(t.Context(), request)
				case *api.HankoRole:
					_, err = roles.Reconcile(t.Context(), request)
				case *api.HankoOrganization:
					_, err = orgs.Reconcile(t.Context(), request)
				case *api.HankoResourceServer:
					_, err = grants.Reconcile(t.Context(), request)
				}
				if err != nil {
					t.Error("parallel IAM reconciliation failed", err)
				}
			})
		}
		workers.Wait()
	}
	for _, obj := range leaves {
		f.requireNoError(kube.Create(t.Context(), obj))
	}
	run(leaves)
	for _, obj := range servers {
		f.requireNoError(kube.Create(t.Context(), obj))
	}
	run(servers)
	identities := map[string]string{}
	for wave := range 2 {
		if wave > 0 {
			run(leaves)
			run(servers)
		}
		for _, obj := range append(leaves, servers...) {
			fixtureGet(f, t.Context(), kube, obj)
			var phase, identity, kind string
			switch value := obj.(type) {
			case *api.HankoApplication:
				phase, kind = value.Status.Phase, "application"
				native, err := writer.GetApplication(t.Context(), "managed", value.Spec.ClientID)
				f.requireNoError(err)
				identity = native.ID
			case *api.HankoRole:
				phase, kind = value.Status.Phase, "role"
				native, err := writer.GetRealmRole(t.Context(), "managed", value.Spec.Name)
				f.requireNoError(err)
				identity = native.ID
			case *api.HankoOrganization:
				phase, kind, identity = value.Status.Phase, "organization", value.Status.GroupID
			case *api.HankoResourceServer:
				phase, kind, identity = value.Status.Phase, "grant", value.Status.AppliedPlanHash
			}
			key := kind + "/" + obj.GetName()
			if phase != "Ready" || identity == "" || wave > 0 && identities[key] != identity {
				t.Fatal("parallel IAM lost Ready, native identity or stable applied plan", kind)
			}
			identities[key] = identity
		}
	}
	t.Log("four shared IAM reconciler kinds: parallel native writes and repeat observations preserve identities and plans; Kubernetes is fake")
}

func qualifyConcurrentApplications(t *testing.T, f *keycloakFixture) {
	t.Helper()
	writer, _ := f.serviceClient("concurrent-application-writer")
	f.grantClientRoles("concurrent-application-writer", "managed", []string{"manage-clients"})
	kube := newFakeClient(t)
	r := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: newScheme(t), Pool: keycloak.NewPool(writer)}
	objects := make([]*api.HankoApplication, 32)
	for index := range objects {
		name := fmt.Sprintf("concurrent-app-%02d", index)
		objects[index] = &api.HankoApplication{ObjectMeta: fixtureMeta(name), Spec: api.HankoApplicationSpec{
			RealmRef: "managed", ClientID: name, Type: "spa", RedirectURIs: []string{"https://concurrency.example.test/callback"}}}
		f.requireNoError(kube.Create(t.Context(), objects[index]))
	}
	ids := make(map[string]string)
	for wave := range 2 {
		var wg sync.WaitGroup
		for _, object := range objects {
			key := client.ObjectKeyFromObject(object)
			wg.Go(func() {
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
					t.Error("concurrent application reconciliation failed")
				}
			})
		}
		wg.Wait()
		for _, object := range objects {
			fixtureGet(f, t.Context(), kube, object)
			if object.Status.Phase != "Ready" || object.Status.AppliedGeneration != object.Generation {
				t.Fatal("concurrent application lost converged status")
			}
			native, err := writer.GetApplication(t.Context(), "managed", object.Spec.ClientID)
			f.requireNoError(err)
			if native.ID == "" || wave == 1 && ids[object.Name] != native.ID {
				t.Fatal("repeat wave duplicated or replaced native application identity")
			}
			ids[object.Name] = native.ID
		}
	}
	observed, err := writer.ListApps(t.Context(), "managed")
	f.requireNoError(err)
	count := 0
	for _, app := range observed {
		if strings.HasPrefix(app.ClientID, "concurrent-app-") {
			count++
		}
	}
	if count != len(objects) {
		t.Fatal("concurrent reconciliation did not retain exactly one native client per object")
	}
	t.Log("32 simultaneous application reconciliations, two waves: Ready/status generations and native UUIDs preserved; Kubernetes client is fake, not an installed scale bound")
}
