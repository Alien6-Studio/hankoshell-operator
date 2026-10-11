//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This qualifies the actual production trust controller and native Admin
// semantics. Kubernetes storage/discovery have separate real-server tests; this
// test explicitly injects public discovery evidence and never claims JWT auth.
func TestRealKeycloakWorkloadTrustController(t *testing.T) {
	f := newKeycloakFixtureWithTransportAndDiscovery(t, false, false, true)
	ctx := context.Background()
	hash, err := workloadtrust.APICAHash(f.ca)
	f.requireNoError(err)
	trust := &api.HankoWorkloadTrust{ObjectMeta: fixtureMeta("shared-trust"), Spec: api.HankoWorkloadTrustSpec{Mode: "Manage", RealmRef: "managed", SourceRef: "trust-observer", WriterRef: "trust-writer", DependentReaderRef: "dependent-reader", KeycloakAlias: "p62-shared", Provider: "Kubernetes", Kubernetes: api.KubernetesWorkloadTrustSpec{Issuer: "https://current-cluster.example.test", AssertionMaxAgeSeconds: 600, ClusterAnchor: api.WorkloadClusterAnchor{KubeSystemNamespaceUID: "cluster-uid", APIServerCAHash: hash}}}}
	proxyURL, proxyCA, routes := newWorkloadTrustACKProxy(t, f)
	objects := []client.Object{trust, &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.Secret{ObjectMeta: fixtureMeta("trust-ca"), Data: map[string][]byte{"ca.crt": proxyCA}}}
	profiles := []struct {
		name  string
		roles []string
	}{{"trust-observer", []string{"view-identity-providers", "view-realm"}}, {"trust-writer", []string{"manage-identity-providers", "view-realm"}}, {"dependent-reader", []string{"view-clients"}}}
	for _, p := range profiles {
		_, secret := f.serviceClient("p62-" + p.name)
		f.grantClientRoles("p62-"+p.name, "managed", p.roles)
		objects = append(objects, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta(p.name), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "trust-ca", AdminRef: corev1.LocalObjectReference{Name: p.name}}}, &corev1.Secret{ObjectMeta: fixtureMeta(p.name + "-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(proxyURL), "HANKO_KC_CLIENT_ID": []byte("p62-" + p.name), "HANKO_KC_CLIENT_SECRET": []byte(secret)}})
		objects[len(objects)-2].(*api.HankoKeycloakInstance).Spec.AdminRef.Name = p.name + "-credential"
	}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&api.HankoWorkloadTrust{}, &api.HankoServiceAccount{}).WithObjects(objects...).Build()
	r := &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: kube, ClusterConfig: &rest.Config{Host: f.baseURL, TLSClientConfig: rest.TLSClientConfig{CAData: f.ca}}, DiscoveryCheck: func(_ context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		jwks := i.Issuer + "/jwks"
		if i.DiscoveryURL != "" {
			jwks = i.DiscoveryURL + "/protocol/openid-connect/certs"
		}
		return workloadtrust.DiscoveryEvidence{Issuer: i.Issuer, JWKSURL: jwks, KeysHash: workloadtrust.Digest("public-fixture", 1)}, nil
	}}
	run := func(n int) {
		for range n {
			fixtureReconcile(f, ctx, r, trust)
		}
		fixtureGet(f, ctx, kube, trust)
	}
	run(4)
	fixtureEqual(t, "native trust controller Ready", trust.Status.Phase, "Ready")
	base := "/admin/realms/managed/identity-provider/instances/p62-shared"
	var native map[string]any
	f.admin(http.MethodGet, base, nil, &native)
	id := native["internalId"].(string)
	fixtureEqual(t, "planned exact native UUID", id, trust.Status.ProviderID)
	config := native["config"].(map[string]any)
	fixtureEqual(t, "native UID marker", config["hanko.sh/workload-trust-owner"], string(trust.UID))
	fixtureEqual(t, "native typed age", config["fedClientAssertionMaxExp"], "600")
	journal, err := workloadtrust.ParseJournal(config["hanko.sh/workload-trust-journal"].(string))
	f.requireNoError(err)
	fixtureEqual(t, "journal exact native UUID", journal.ProviderID, id)
	run(2)
	var again map[string]any
	f.admin(http.MethodGet, base, nil, &again)
	fixtureEqual(t, "idempotent native document", again, native)
	containmentPath := qualifyWorkloadBinding(f, kube, r, trust, proxyURL, routes)
	if _, err := f.kc.EnsureIdentityProvider(ctx, "managed", keycloak.IdentityProvider{Alias: "p62-shared", ProviderID: "kubernetes", Enabled: false}); err == nil {
		t.Fatal("generic native broker writer accepted independent ownership")
	}
	if err := f.kc.DeleteIdentityProvider(ctx, "managed", "p62-shared"); err == nil {
		t.Fatal("generic native alias cleanup accepted independent ownership")
	}
	flag := true
	f.requireNoError(f.kc.ConfigureIdentityProviderTrust(ctx, "managed", &flag, &flag))
	f.admin(http.MethodGet, base, nil, &again)
	fixtureEqual(t, "native realm broker paths preserve complete owned trust", again, native)
	trust.Spec.Kubernetes.AssertionMaxAgeSeconds = 900
	trust.Generation++
	f.requireNoError(kube.Update(ctx, trust))
	run(1)
	fixtureEqual(t, "shared-age review required", trust.Status.Conditions[0].Reason, "SharedAgeReviewRequired")
	a := workloadtrust.SharedAgeApproval{Contract: "hanko.sh/iam-contract/v1alpha1", PlanHash: trust.Status.EvaluatedPlanHash, DependenciesHash: trust.Status.DependentInventoryHash, ReviewHash: trust.Status.SharedAgeReviewHash}
	b, err := json.Marshal(a)
	f.requireNoError(err)
	trust.Annotations[workloadtrust.AgeApprovalKey] = string(b)
	f.requireNoError(kube.Update(ctx, trust))
	run(2)
	fixtureEqual(t, "reviewed age Ready", trust.Status.Phase, "Ready")
	f.admin(http.MethodGet, base, nil, &again)
	fixtureEqual(t, "update preserves UUID", again["internalId"], id)
	fixtureEqual(t, "accepted POST with lost ACK does not repeat", routes()["POST /admin/realms/managed/identity-provider/instances"], 1)
	fixtureEqual(t, "accepted age PUT with lost ACK does not repeat", routes()["PUT "+base], 1)
	// The public discovery document is real native Keycloak OIDC metadata. It
	// characterizes provider source resolution; injected Kubernetes evidence
	// above does not claim that this fixture issuer is a Kubernetes workload.
	trust.Spec.Kubernetes.DiscoveryURL = "https://localhost:8443/realms/managed"
	trust.Spec.Kubernetes.Issuer = trust.Spec.Kubernetes.DiscoveryURL
	trust.Spec.QualifiedKeycloakVersion = f.version
	trust.Generation++
	f.requireNoError(kube.Update(ctx, trust))
	run(2)
	if f.version == "26.7.5" {
		fixtureEqual(t, "26.7 override refused before native PUT", trust.Status.Conditions[0].Reason, "UnsupportedDiscoveryOverride")
		fixtureEqual(t, "opaque override not written", routes()["PUT "+base], 1)
		trust.Spec.Kubernetes.DiscoveryURL = ""
		trust.Spec.Kubernetes.Issuer = "https://current-cluster.example.test"
		trust.Spec.QualifiedKeycloakVersion = ""
		trust.Generation++
		f.requireNoError(kube.Update(ctx, trust))
		run(2)
	} else {
		fixtureEqual(t, "26.8 override qualified native read-back", trust.Status.Phase, "Ready")
		f.admin(http.MethodGet, base, nil, &again)
		resolved := again["config"].(map[string]any)
		fixtureEqual(t, "native resolved issuer", resolved["issuer"], trust.Spec.Kubernetes.Issuer)
		fixtureEqual(t, "native resolved JWKS", resolved["jwksUrl"], trust.Spec.Kubernetes.DiscoveryURL+"/protocol/openid-connect/certs")
	}
	f.admin(http.MethodGet, base, nil, &again)
	beforeUnknown := adoptionClone(t, again)
	again["config"].(map[string]any)["unreviewed-security-key"] = "excluded"
	f.admin(http.MethodPut, base, again, nil)
	beforeWrites := routes()["PUT "+base]
	run(2)
	fixtureEqual(t, "unknown native config blocks controller", trust.Status.Conditions[0].Reason, "UnsupportedNativeState")
	fixtureEqual(t, "unknown native config never round-tripped", routes()["PUT "+base], beforeWrites)
	f.admin(http.MethodPut, base, beforeUnknown, nil)
	run(2)
	// A native foreign dependent blocks provider deletion, even when disabled.
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "p62-foreign-dependent", "enabled": false, "clientAuthenticatorType": "federated-jwt", "attributes": map[string]string{"jwt.credential.issuer": "p62-shared", "jwt.credential.sub": "system:serviceaccount:workloads:worker"}}, nil)
	f.requireNoError(kube.Delete(ctx, trust))
	run(1)
	fixtureEqual(t, "foreign dependent blocks deletion", trust.Status.Conditions[0].Reason, "DependentClientsPresent")
	dependent := f.client("managed", "p62-foreign-dependent")
	f.admin(http.MethodDelete, "/admin/realms/managed/clients/"+dependent["id"].(string), nil, nil)
	fixtureReconcile(f, ctx, r, trust)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(trust), trust); err == nil || client.IgnoreNotFound(err) != nil {
		t.Fatal("zero-dependent owned cleanup did not release finalizer")
	}
	var providers []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances", nil, &providers)
	for _, p := range providers {
		if p["alias"] == "p62-shared" {
			t.Fatal("owned zero-dependent provider retained")
		}
	}
	fixtureEqual(t, "lost DELETE ACK cleanup runs once", routes()["DELETE "+base], 1)
	for route := range routes() {
		if route == "PUT "+containmentPath && routes()[route] == 1 {
			continue
		} // exact owned containment qualified above
		if strings.Contains(route, "client-secret") || strings.HasPrefix(route, "PUT /admin/realms/managed/clients") || strings.HasPrefix(route, "DELETE /admin/realms/managed/clients") {
			t.Fatal("trust controller dispatched a client credential/mutation route")
		}
	}
	// Writer retains native realm-wide IdP powers, but no client/user/realm/master
	// authority. The separate reader concession never modifies its mappings.
	_, writerSecret := f.serviceClient("p62-negative-writer")
	f.grantClientRoles("p62-negative-writer", "managed", []string{"manage-identity-providers", "view-realm"})
	for _, request := range []struct {
		method, path string
		body         any
	}{{"POST", "/admin/realms/managed/users", map[string]any{"username": "forbidden"}}, {"POST", "/admin/realms/managed/groups", map[string]any{"name": "forbidden"}}, {"PUT", "/admin/realms/managed", map[string]any{"sslRequired": "none"}}, {"DELETE", "/admin/realms/managed", nil}, {"POST", "/admin/realms", map[string]any{"realm": "forbidden"}}, {"GET", "/admin/realms/master/clients", nil}, {"PUT", "/admin/realms/master", map[string]any{"enabled": false}}, {"POST", "/admin/realms/managed/clients", map[string]any{"clientId": "forbidden"}}} {
		fixtureEqual(t, "trust-writer native negative permission", f.identityStatus("p62-negative-writer", writerSecret, request.method, request.path, request.body), http.StatusForbidden)
	}
	if strings.Contains(string(fixtureJSON(t, trust)), "client-secret") {
		t.Fatal("credential route in controller evidence")
	}
	// Independently exercise closed owner-only adoption against native storage.
	// Acknowledgement loss must preserve every pre-existing semantic field and
	// still require a separate, explicit mode change before normal reconciliation.
	observed := &api.HankoWorkloadTrust{ObjectMeta: fixtureMeta("observed-trust"), Spec: trust.Spec}
	observed.Spec.Mode = "Observe"
	observed.Spec.KeycloakAlias = "p62-observed"
	observed.Spec.Kubernetes.Issuer = "https://current-cluster.example.test"
	observed.Spec.Kubernetes.DiscoveryURL = ""
	observed.Spec.QualifiedKeycloakVersion = ""
	observed.Spec.Kubernetes.AssertionMaxAgeSeconds = 600
	f.requireNoError(kube.Create(ctx, observed))
	observedPath := "/admin/realms/managed/identity-provider/instances/p62-observed"
	f.admin(http.MethodPost, "/admin/realms/managed/identity-provider/instances", map[string]any{"alias": "p62-observed", "providerId": "kubernetes", "enabled": false, "displayName": "Existing public display", "config": map[string]string{"issuer": observed.Spec.Kubernetes.Issuer, "fedClientAssertionMaxExp": "600", "allowedClockSkew": "10", "syncMode": "LEGACY"}}, nil)
	var original map[string]any
	f.admin(http.MethodGet, observedPath, nil, &original)
	for range 2 {
		fixtureReconcile(f, ctx, r, observed)
	}
	fixtureGet(f, ctx, kube, observed)
	if len(observed.Finalizers) != 0 || observed.Status.AdoptionCandidate == nil || !observed.Status.AdoptionCandidate.Approvable {
		t.Fatal("native Observe did not emit a closed non-mutating candidate")
	}
	fixtureEqual(t, "native Observe has no PUT authority", routes()["PUT "+observedPath], 0)
	observed.Annotations = map[string]string{adoption.SourceAnnotation: "trust-observer", adoption.ContractAnnotation: string(adoption.Version), adoption.CandidateAnnotation: observed.Status.AdoptionCandidate.CandidateHash}
	f.requireNoError(kube.Update(ctx, observed))
	for range 4 {
		fixtureReconcile(f, ctx, r, observed)
	}
	fixtureGet(f, ctx, kube, observed)
	if len(observed.Finalizers) != 0 || observed.Spec.Mode != "Observe" || observed.Status.AdoptionReceipt == nil {
		t.Fatalf("native owner-only adoption did not recover: reason=%s", observed.Status.Conditions[0].Reason)
	}
	fixtureEqual(t, "native owner-only PUT with lost ACK runs once", routes()["PUT "+observedPath], 1)
	var acquired map[string]any
	f.admin(http.MethodGet, observedPath, nil, &acquired)
	config = acquired["config"].(map[string]any)
	for _, key := range []string{"hanko.sh/workload-trust-owner", "hanko.sh/workload-trust-journal", "hanko.sh/adoption-receipt"} {
		delete(config, key)
	}
	fixtureEqual(t, "owner-only acquisition preserves complete native semantics", acquired, original)
	observed.Spec.Mode = "Manage"
	observed.Generation++
	f.requireNoError(kube.Update(ctx, observed))
	for range 3 {
		fixtureReconcile(f, ctx, r, observed)
	}
	fixtureGet(f, ctx, kube, observed)
	fixtureEqual(t, "native adoption needs explicit Manage", observed.Status.Phase, "Ready")
	fixtureEqual(t, "normal reconciliation occurs only after explicit Manage", routes()["PUT "+observedPath], 2)
	t.Logf("Keycloak %s: production controller exact UUID/journal, lost POST/PUT/DELETE ACK recovery without repeat, version-specific discovery override, unsupported-field refusal, reviewed age and actual foreign-dependent deletion guard; zero client credential/mutation routes", f.version)
}

func newWorkloadTrustACKProxy(t *testing.T, f *keycloakFixture) (string, []byte, func() map[string]int) {
	t.Helper()
	upstream, err := url.Parse(f.baseURL)
	f.requireNoError(err)
	var mu sync.Mutex
	seen := map[string]int{}
	dropped := map[string]bool{}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(upstream); r.Out.Host = upstream.Host }, Transport: f.http.Transport}
	proxy.ModifyResponse = func(response *http.Response) error {
		r := response.Request
		method := r.Method
		if strings.Contains(r.URL.Path, "/identity-provider/instances") && method != http.MethodGet && (response.StatusCode == 201 || response.StatusCode == 204) {
			mu.Lock()
			key := method + " " + r.URL.Path
			drop := !dropped[key]
			dropped[key] = true
			mu.Unlock()
			if drop {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				return errors.New("fixture accepted write acknowledgement withheld")
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("fixture cannot withhold acknowledgement")
			return
		}
		conn, _, err := h.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	return s.URL, ca, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		copy := map[string]int{}
		for k, v := range seen {
			copy[k] = v
		}
		return copy
	}
}
