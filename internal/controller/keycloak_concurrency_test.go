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
