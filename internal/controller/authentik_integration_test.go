//go:build authentik_integration

package controller_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authentik"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestRealAuthentikPortableCorpus(t *testing.T) {
	upstream, err := url.Parse(os.Getenv("AUTHENTIK_FIXTURE_UPSTREAM"))
	if err != nil || upstream.Scheme != "http" || upstream.Hostname() != "127.0.0.1" {
		t.Fatal("use scripts/authentik-fixture.py with a loopback-only real server")
	}
	var mutex sync.Mutex
	writes := 0
	providerCreates := 0
	applicationCreates := 0
	lostPath := ""
	// #nosec G704 -- Test-only destination is validated as loopback HTTP, published by the disposable fixture runner.
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(502) }
	proxy.ModifyResponse = func(response *http.Response) error {
		mutex.Lock()
		defer mutex.Unlock()
		if response.Request.Method != "GET" {
			writes++
			if response.Request.Method == "POST" && response.Request.URL.Path == "/api/v3/providers/oauth2/" {
				providerCreates++
			}
			if response.Request.Method == "POST" && response.Request.URL.Path == "/api/v3/core/applications/" {
				applicationCreates++
			}
		}
		if lostPath != "" && response.Request.Method == "POST" && response.Request.URL.Path == lostPath && response.StatusCode < 300 {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			response.Body = io.NopCloser(strings.NewReader("lost acknowledgement"))
			response.StatusCode = 503
			response.ContentLength = -1
			response.Header.Del("Content-Length")
			lostPath = ""
		}
		return nil
	}
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		proxy.ServeHTTP(w, r)
	}))
	defer edge.Close()
	data, err := readAuthentikFixture("connection.json")
	if err != nil {
		t.Fatal("fixture connection is unavailable")
	}
	var config authentik.Connection
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("fixture connection is malformed")
	}
	config.Endpoint = edge.URL
	config.CASecret = "provider-ca"
	tokenData := []byte(os.Getenv("HANKO_FIXTURE_TOKEN"))
	deniedToken := []byte(os.Getenv("HANKO_FIXTURE_DENIED_TOKEN"))
	if len(tokenData) == 0 || len(tokenData) > 16384 || len(deniedToken) == 0 || len(deniedToken) > 16384 {
		t.Fatal("private in-memory fixture credentials unavailable")
	}
	configMap, token, ca := experimentalObjects(t, edge.URL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.TLS.Certificates[0].Certificate[0]}))
	configJSON, _ := json.Marshal(config)
	configMap.Data["connection.json"] = string(configJSON)
	token.Data["token"] = tokenData
	corpus, err := iamconformance.ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	count := func() int { mutex.Lock(); defer mutex.Unlock(); return writes }
	for _, fixture := range corpus.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			raw, _ := json.Marshal(fixture.Manifest)
			// Decode with the registered Kubernetes serializer, preserving the identical
			// source spec. Only provider-selection metadata differs between executors.
			scheme := newScheme(t)
			target, err := scheme.New(api.GroupVersion.WithKind(fixture.Manifest.Kind))
			if err != nil {
				t.Fatal(err)
			}
			if json.Unmarshal(raw, target) != nil {
				t.Fatal("fixture manifest is malformed")
			}
			obj := target.(client.Object)
			obj.SetNamespace("auth")
			obj.SetUID(types.UID("portable-" + fixture.Name))
			obj.SetGeneration(1)
			obj.SetLabels(map[string]string{experimentalSelector: "experimental"})
			kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap.DeepCopy(), token.DeepCopy(), ca.DeepCopy(), obj).WithStatusSubresource(&api.HankoApplication{}, &api.HankoRole{}, &api.HankoRealm{}, &api.HankoIAMProfile{}, &api.HankoOrganization{}, &api.HankoServiceAccount{}, &api.HankoResourceServer{}, &api.HankoWorkloadTrust{}).Build()
			makeReconciler := func() reconcile.Reconciler {
				switch obj.(type) {
				case *api.HankoApplication:
					return &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, ExperimentalAuthentik: true, ExperimentalAuthentikConnections: []string{"experimental"}}
				case *api.HankoRealm:
					return &controller.HankoRealmReconciler{Client: kube}
				case *api.HankoIAMProfile:
					return &controller.HankoIAMProfileReconciler{Client: kube}
				case *api.HankoRole:
					return &controller.HankoRoleReconciler{Client: kube}
				case *api.HankoOrganization:
					return &controller.HankoOrganizationReconciler{Client: kube}
				case *api.HankoServiceAccount:
					return &controller.HankoServiceAccountReconciler{Client: kube}
				case *api.HankoResourceServer:
					return &controller.HankoResourceServerReconciler{Client: kube}
				case *api.HankoWorkloadTrust:
					return &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: kube}
				default:
					t.Fatal("unassigned portable fixture kind")
					return nil
				}
			}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			if fixture.Expected["authentik"].Classification == "unsupported" {
				iamconformance.NoMutation(t, count, func() error { _, err := makeReconciler().Reconcile(ctx, req); return err })
				if err := kube.Get(ctx, req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(obj)
				var status struct {
					Status struct {
						Phase string `json:"phase"`
					} `json:"status"`
				}
				_ = json.Unmarshal(data, &status)
				if status.Status.Phase != "Error" || len(obj.GetFinalizers()) > 0 {
					t.Fatal("unsupported fixture was not refused before mutation")
				}
				if err := iamconformance.CheckPortableObservation(fixture, "authentik", data); err != nil {
					t.Fatal(err)
				}
				iamconformance.NoSecrets(t, []string{string(tokenData), string(deniedToken)}, obj)
				return
			}
			app := obj.(*api.HankoApplication)
			r := makeReconciler()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			mutex.Lock()
			lostPath = "/api/v3/providers/oauth2/"
			if fixture.Name == "web" {
				lostPath = "/api/v3/core/applications/"
			}
			mutex.Unlock()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, req.NamespacedName, app); err != nil {
				t.Fatal(err)
			}
			if app.Status.Phase != "Error" {
				t.Fatal("lost acknowledgement was promoted to applied proof")
			}
			r = makeReconciler() // Process restart discards all local driver state.
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, req.NamespacedName, app); err != nil {
				t.Fatal(err)
			}
			if app.Status.Phase != "Ready" || app.Status.AppliedPlanHash == "" || !app.Status.ObservationComplete {
				t.Fatalf("real provider failed fixture %s; phase=%s", fixture.Name, app.Status.Phase)
			}
			observed, _ := json.Marshal(app)
			if err := iamconformance.CheckPortableObservation(fixture, "authentik", observed); err != nil {
				t.Fatal(err)
			}
			before := count()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if count() != before {
				t.Fatal("real provider replay duplicated writes")
			}
			var deniedSecret corev1.Secret
			if err := kube.Get(ctx, client.ObjectKeyFromObject(token), &deniedSecret); err != nil {
				t.Fatal(err)
			}
			deniedSecret.Data["token"] = deniedToken
			if err := kube.Update(ctx, &deniedSecret); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			deniedSecret.Data["token"] = tokenData
			if err := kube.Update(ctx, &deniedSecret); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, req.NamespacedName, app); err != nil {
				t.Fatal(err)
			}
			if app.Status.AppliedPlanHash != "" {
				t.Fatal("denied administration retained applied evidence")
			}
			iamconformance.NoSecrets(t, []string{string(tokenData), string(deniedToken)}, app)
			if err := kube.Delete(ctx, app); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
		})
	}
	mutex.Lock()
	defer mutex.Unlock()
	if providerCreates != 2 || applicationCreates != 2 {
		t.Fatalf("restart repeated native creation: providers=%d applications=%d", providerCreates, applicationCreates)
	}
}

// os.Root prevents a fixture file from escaping the runner's private directory.
// File names are a fixed inventory, never supplied by a provider response.
func readAuthentikFixture(name string) ([]byte, error) {
	directory := os.Getenv("AUTHENTIK_FIXTURE_DIRECTORY")
	if !filepath.IsAbs(directory) || !strings.HasPrefix(filepath.Base(directory), "hanko-authentik-") {
		return nil, authentik.ErrUnsupported
	}
	if name != "connection.json" {
		return nil, authentik.ErrUnsupported
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, authentik.ErrUnsupported
	}
	defer root.Close()
	data, err := root.ReadFile(name)
	if err != nil || len(data) > 16384 {
		return nil, authentik.ErrUnsupported
	}
	return data, nil
}
