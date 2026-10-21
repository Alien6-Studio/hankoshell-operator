package controller

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type trustFixture struct {
	t                               *testing.T
	mu                              sync.Mutex
	server                          *httptest.Server
	kube                            client.Client
	r                               *HankoWorkloadTrustReconciler
	provider                        map[string]any
	dependents                      []map[string]any
	posts, puts, deletes, forbidden int
	failure                         string
	lostAck                         bool
}

func newTrustFixture(t *testing.T, mode string) *trustFixture {
	t.Helper()
	f := &trustFixture{t: t, dependents: []map[string]any{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	hash, err := workloadtrust.APICAHash(ca)
	if err != nil {
		t.Fatal(err)
	}
	trust := &api.HankoWorkloadTrust{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "auth", UID: "trust-uid", Generation: 1}, Spec: api.HankoWorkloadTrustSpec{Mode: mode, RealmRef: "managed", SourceRef: "observer", WriterRef: "writer", DependentReaderRef: "reader", KeycloakAlias: "cluster", Provider: "Kubernetes", Kubernetes: api.KubernetesWorkloadTrustSpec{Issuer: "https://current.example.test", AssertionMaxAgeSeconds: 600, ClusterAnchor: api.WorkloadClusterAnchor{KubeSystemNamespaceUID: "cluster-uid", APIServerCAHash: hash}}}}
	objects := []client.Object{trust, &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "auth", UID: "realm-cr-uid", Generation: 1, Labels: map[string]string{importedByLabel: "realm-import"}}}, &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "realm-import", Namespace: "auth", UID: "realm-import-uid"}, Spec: api.HankoImportSpec{SourceRef: "observer"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "auth", UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}}}
	for _, name := range []string{"observer", "writer", "reader"} {
		objects = append(objects, &api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", UID: types.UID("instance-" + name), Generation: 1}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: name}, TLSCARef: "ca"}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", UID: types.UID("secret-" + name)}, Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(f.server.URL), "HANKO_KC_CLIENT_ID": []byte(name), "HANKO_KC_CLIENT_SECRET": []byte("credential-sentinel-" + name)}})
	}
	f.kube = fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithStatusSubresource(&api.HankoWorkloadTrust{}, &api.HankoServiceAccount{}, &api.HankoMeshService{}).WithObjects(objects...).Build()
	f.r = &HankoWorkloadTrustReconciler{Client: f.kube, APIReader: f.kube, ClusterConfig: &rest.Config{Host: f.server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, DiscoveryCheck: func(_ context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		return workloadtrust.DiscoveryEvidence{Issuer: i.Issuer, JWKSURL: i.Issuer + "/jwks", KeysHash: workloadtrust.Digest("public", 1)}, nil
	}}
	probe, probeErr := keycloak.NewWithTLS(f.server.URL, "writer", "credential-sentinel-writer", ca)
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	if _, probeErr = probe.ValidateEffectiveFederatedClientFlow(context.Background(), "managed"); probeErr != nil {
		t.Fatal("fixture flow:", probeErr)
	}
	return f
}

func (f *trustFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/token") {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": r.Form.Get("client_id"), "expires_in": 300})
		return
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	path := r.URL.Path
	if strings.Contains(path, "client-secret") || r.Method != http.MethodGet && (principal != "writer" || !strings.Contains(path, "/identity-provider/instances")) {
		f.forbidden++
		w.WriteHeader(403)
		return
	}
	if strings.HasPrefix(path, "/admin/realms/managed/clients") && principal != "reader" {
		f.forbidden++
		w.WriteHeader(403)
		return
	}
	if principal == "reader" && !strings.HasPrefix(path, "/admin/realms/managed/clients") {
		f.forbidden++
		w.WriteHeader(403)
		return
	}
	if f.failure == "outage" || f.failure == "inventory denied" && strings.Contains(path, "/clients") {
		w.WriteHeader(403)
		return
	}
	base := "/admin/realms/managed/identity-provider/instances"
	if r.Method == http.MethodPost && path == base || r.Method == http.MethodPut && path == base+"/cluster" {
		var next map[string]any
		if json.NewDecoder(r.Body).Decode(&next) != nil {
			w.WriteHeader(400)
			return
		}
		f.provider = next
		if r.Method == http.MethodPost {
			f.posts++
		} else {
			f.puts++
		}
		if f.failure == "readback drift" {
			f.provider["enabled"] = false
		}
		if f.lostAck {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if r.Method == http.MethodDelete && path == base+"/cluster" {
		f.deletes++
		f.provider = nil
		if f.lostAck {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(204)
		return
	}
	var value any
	switch path {
	case "/admin/realms/managed":
		value = map[string]any{"id": "realm-uuid", "realm": "managed", "clientAuthenticationFlow": "clients"}
	case "/admin/realms/managed/authentication/flows":
		value = []any{map[string]any{"id": "flow-uuid", "alias": "clients", "providerId": "client-flow", "builtIn": f.failure != "custom flow", "topLevel": true}}
	case "/admin/realms/managed/authentication/flows/clients/executions":
		value = []any{map[string]any{"id": "execution-uuid", "providerId": "federated-jwt", "requirement": "ALTERNATIVE"}}
		if f.failure == "disabled flow" {
			value = []any{map[string]any{"id": "execution-uuid", "providerId": "federated-jwt", "requirement": "DISABLED"}}
		}
		if f.failure == "missing flow" {
			value = []any{}
		}
	case base:
		value = []any{}
		if f.provider != nil {
			value = []any{f.provider}
		}
	case base + "/cluster":
		if f.provider == nil {
			w.WriteHeader(404)
			return
		}
		value = f.provider
	case base + "/cluster/mappers":
		value = []any{}
		if f.failure == "mapper" {
			value = []any{map[string]any{"id": "unqualified"}}
		}
	case "/admin/realms/managed/clients":
		value = f.dependents
		if f.failure == "null inventory" {
			value = nil
		}
	default:
		if strings.HasPrefix(path, "/admin/realms/managed/clients/") {
			for _, d := range f.dependents {
				if path == "/admin/realms/managed/clients/"+d["id"].(string) {
					value = d
				}
			}
		}
		if value == nil {
			w.WriteHeader(404)
			return
		}
	}
	_ = json.NewEncoder(w).Encode(value)
}

func (f *trustFixture) current() *api.HankoWorkloadTrust {
	f.t.Helper()
	var t api.HankoWorkloadTrust
	if err := f.kube.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: "trust"}, &t); err != nil {
		f.t.Fatal(err)
	}
	return &t
}
func (f *trustFixture) update(change func(*api.HankoWorkloadTrust)) {
	f.t.Helper()
	t := f.current()
	change(t)
	if err := f.kube.Update(context.Background(), t); err != nil {
		f.t.Fatal(err)
	}
}
func (f *trustFixture) run(n int) {
	f.t.Helper()
	for j := 0; j < n; j++ {
		if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "auth", Name: "trust"}}); err != nil {
			f.t.Fatal(err)
		}
	}
}
func (f *trustFixture) reason() string {
	return conditionReason(f.current().Status.Conditions, "Ready")
}
func (f *trustFixture) native(change func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.provider)
}
func (f *trustFixture) foreign() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provider = map[string]any{"internalId": "foreign-uuid", "alias": "cluster", "providerId": "kubernetes", "enabled": true, "hideOnLogin": true, "config": map[string]any{"issuer": "https://current.example.test", "allowedClockSkew": "0", "fedClientAssertionMaxExp": "600"}}
}

func TestWorkloadTrustCreateLostACKIdempotenceAndSharedAgeReview(t *testing.T) {
	f := newTrustFixture(t, ModeManage)
	f.lostAck = true
	f.run(4)
	if f.current().Status.Phase != "Ready" || f.posts != 1 || f.puts != 0 || f.forbidden != 0 {
		t.Fatalf("not exactly one qualified create: reason=%s, post=%d put=%d", f.reason(), f.posts, f.puts)
	}
	f.update(func(t *api.HankoWorkloadTrust) { t.Spec.Kubernetes.AssertionMaxAgeSeconds = 900; t.Generation++ })
	f.run(1)
	if f.reason() != "SharedAgeReviewRequired" || f.puts != 0 {
		t.Fatal("age changed without inventory review")
	}
	s, err := f.r.workloadSnapshot(context.Background(), client.ObjectKey{Namespace: "auth", Name: "trust"}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(s.plan.AgeReview(600))
	f.update(func(t *api.HankoWorkloadTrust) { t.Annotations[workloadtrust.AgeApprovalKey] = string(a) })
	f.run(2)
	if f.current().Status.Phase != "Ready" || f.puts != 1 {
		t.Fatalf("age update not acknowledged exactly once: %s", f.reason())
	}
	encoded, _ := json.Marshal(f.current())
	if strings.Contains(string(encoded), "credential-sentinel") {
		t.Fatal("credential entered evidence")
	}
}

func TestWorkloadTrustObserveAndExplicitOwnerOnlyAdoption(t *testing.T) {
	f := newTrustFixture(t, ModeObserve)
	f.foreign()
	f.run(2)
	observed := f.current()
	if f.posts+f.puts+f.deletes != 0 || len(observed.Finalizers) != 0 || observed.Status.AdoptionCandidate == nil || !observed.Status.AdoptionCandidate.Approvable || observed.Status.Dependents != nil || observed.Status.DependentInventoryHash != "" {
		t.Fatal("Observe violated ownership boundary")
	}
	candidate := observed.Status.AdoptionCandidate.CandidateHash
	f.update(func(t *api.HankoWorkloadTrust) {
		t.Annotations = map[string]string{adoption.SourceAnnotation: "observer", adoption.ContractAnnotation: string(adoption.Version), adoption.CandidateAnnotation: candidate}
	})
	f.lostAck = true
	f.run(4)
	if f.puts != 1 || f.current().Spec.Mode != ModeObserve || len(f.current().Finalizers) != 0 || f.current().Status.AdoptionReceipt == nil {
		t.Fatalf("owner-only adoption did not recover: %s", f.reason())
	}
	f.native(func(p map[string]any) {
		c := p["config"].(map[string]any)
		if c["issuer"] != "https://current.example.test" || c["fedClientAssertionMaxExp"] != "600" {
			t.Fatal("acquisition rewrote semantics")
		}
	})
	f.update(func(t *api.HankoWorkloadTrust) { t.Spec.Mode = ModeManage; t.Generation++ })
	f.run(3)
	if f.current().Status.Phase != "Ready" || f.puts != 2 {
		t.Fatalf("explicit Manage did not seal approved generation: %s", f.reason())
	}
}

func TestWorkloadTrustStatusLossAndRestartUseNativeJournal(t *testing.T) {
	f := newTrustFixture(t, ModeManage)
	f.run(3)
	before := f.current()
	id := before.Status.ProviderID
	before.Status = api.HankoWorkloadTrustStatus{}
	if err := f.kube.Status().Update(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	// A new reconciler has no previous status or in-memory execution authority.
	f.r = &HankoWorkloadTrustReconciler{Client: f.kube, APIReader: f.kube, ClusterConfig: f.r.ClusterConfig, DiscoveryCheck: f.r.DiscoveryCheck}
	f.run(2)
	after := f.current()
	if after.Status.Phase != "Ready" || after.Status.ProviderID != id || f.posts != 1 || f.puts+f.deletes != 0 {
		t.Fatal("status loss/restart repeated a native write or lost exact ownership")
	}
}

func TestWorkloadTrustFailsClosedBeforeNativeWrites(t *testing.T) {
	for _, failure := range []string{"disabled flow", "missing flow", "custom flow", "inventory denied", "null inventory", "outage", "mapper", "unknown config", "foreign marker", "anchor UID", "anchor CA", "duplicate alias"} {
		t.Run(failure, func(t *testing.T) {
			f := newTrustFixture(t, ModeManage)
			f.foreign()
			f.failure = failure
			switch failure {
			case "unknown config":
				f.native(func(p map[string]any) { p["config"].(map[string]any)["unknownSecuritySwitch"] = "enabled" })
			case "foreign marker":
				f.native(func(p map[string]any) { p["config"].(map[string]any)[keycloak.WorkloadTrustOwnerKey] = "foreign-owner" })
			case "anchor UID":
				f.update(func(t *api.HankoWorkloadTrust) {
					t.Spec.Kubernetes.ClusterAnchor.KubeSystemNamespaceUID = "replacement"
				})
			case "anchor CA":
				f.update(func(t *api.HankoWorkloadTrust) {
					t.Spec.Kubernetes.ClusterAnchor.APIServerCAHash = workloadtrust.Digest("other", 1)
				})
			case "duplicate alias":
				other := f.current().DeepCopy()
				other.Name = "other"
				other.UID = "other-uid"
				other.ResourceVersion = ""
				if err := f.kube.Create(context.Background(), other); err != nil {
					t.Fatal(err)
				}
			}
			f.run(3)
			if f.posts+f.puts+f.deletes != 0 || f.current().Status.Phase == "Ready" || len(f.current().Finalizers) != 0 {
				t.Fatalf("unsafe state accepted: %s", f.reason())
			}
		})
	}
}

func TestWorkloadTrustProviderReplacementAndAbsenceCannotRecreate(t *testing.T) {
	for _, change := range []string{"UUID", "owner", "absent", "source"} {
		t.Run(change, func(t *testing.T) {
			f := newTrustFixture(t, ModeManage)
			f.run(3)
			f.native(func(p map[string]any) {
				switch change {
				case "UUID":
					p["internalId"] = "replacement-uuid"
				case "owner":
					p["config"].(map[string]any)[keycloak.WorkloadTrustOwnerKey] = "foreign"
				case "absent":
					f.provider = nil
				}
			})
			if change == "source" {
				var source api.HankoKeycloakInstance
				_ = f.kube.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: "observer"}, &source)
				source.UID = "replacement-source"
				if err := f.kube.Update(context.Background(), &source); err != nil {
					t.Fatal(err)
				}
			}
			f.run(2)
			if f.posts != 1 || f.puts+f.deletes != 0 || f.current().Status.Phase == "Ready" {
				t.Fatal("replaced ownership followed")
			}
		})
	}
}

func TestWorkloadTrustDeletionRequiresCompleteZeroDependencies(t *testing.T) {
	for _, caseName := range []string{"zero", "owned", "foreign", "ambiguous", "conflicting markers", "inventory denied", "UUID replaced"} {
		t.Run(caseName, func(t *testing.T) {
			f := newTrustFixture(t, ModeManage)
			f.run(3)
			if caseName == "inventory denied" {
				f.failure = caseName
			}
			if caseName == "UUID replaced" {
				f.native(func(p map[string]any) { p["internalId"] = "replacement-uuid" })
			}
			if caseName == "owned" || caseName == "foreign" || caseName == "ambiguous" || caseName == "conflicting markers" {
				f.dependents = []map[string]any{{"id": "dependent-uuid", "clientId": "dependent", "enabled": false, "clientAuthenticatorType": "federated-jwt", "attributes": map[string]string{"jwt.credential.issuer": "cluster", "jwt.credential.sub": "system:serviceaccount:workloads:worker", "hanko.sh/client-owner-kind": "HankoServiceAccount", "hanko.sh/client-owner-uid": "foreign"}}}
				if caseName == "owned" {
					a := &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "dependent", Namespace: "auth", UID: "owned-uid"}, Spec: api.HankoServiceAccountSpec{RealmRef: "managed", ClientID: "dependent"}}
					if err := f.kube.Create(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					f.dependents[0]["attributes"].(map[string]string)["hanko.sh/client-owner-uid"] = string(a.UID)
				}
				if caseName == "ambiguous" {
					delete(f.dependents[0]["attributes"].(map[string]string), "hanko.sh/client-owner-uid")
				}
				if caseName == "conflicting markers" {
					f.dependents[0]["attributes"].(map[string]string)[adoption.ApplicationOwnerKey] = "conflicting-owner"
				}
			}
			if err := f.kube.Delete(context.Background(), f.current()); err != nil {
				t.Fatal(err)
			}
			f.lostAck = true
			f.run(1)
			if caseName == "zero" {
				if f.deletes != 1 {
					t.Fatal("zero-dependent provider not deleted")
				}
			} else {
				if f.deletes != 0 || len(f.current().Finalizers) == 0 {
					t.Fatal("cleanup ignored uncertainty or dependency")
				}
				counts := f.current().Status.Dependents
				if caseName == "owned" && counts.Owned != 1 || caseName == "foreign" && counts.Foreign != 1 || (caseName == "ambiguous" || caseName == "conflicting markers") && counts.Ambiguous != 1 {
					t.Fatal("dependent classification missing")
				}
			}
		})
	}
}

func TestWorkloadTrustUncachedBarrierRejectsChangesDuringDiscovery(t *testing.T) {
	for _, changed := range []string{"target generation", "source credential", "CA identity", "namespace UID", "new competing trust"} {
		t.Run(changed, func(t *testing.T) {
			f := newTrustFixture(t, ModeManage)
			check := f.r.DiscoveryCheck
			once := false
			f.r.DiscoveryCheck = func(ctx context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
				if !once {
					once = true
					switch changed {
					case "target generation":
						f.update(func(t *api.HankoWorkloadTrust) { t.Generation++; t.Spec.Kubernetes.AssertionMaxAgeSeconds = 900 })
					case "source credential", "CA identity":
						name := "observer"
						if changed == "CA identity" {
							name = "ca"
						}
						var secret corev1.Secret
						if err := f.kube.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, &secret); err != nil {
							t.Fatal(err)
						}
						if changed == "source credential" {
							secret.Data["HANKO_KC_CLIENT_SECRET"] = []byte("replacement-credential-sentinel")
						} else {
							secret.UID = "replacement-ca"
						}
						if err := f.kube.Update(ctx, &secret); err != nil {
							t.Fatal(err)
						}
					case "namespace UID":
						var ns corev1.Namespace
						_ = f.kube.Get(ctx, client.ObjectKey{Name: "kube-system"}, &ns)
						ns.UID = "replacement"
						if err := f.kube.Update(ctx, &ns); err != nil {
							t.Fatal(err)
						}
					case "new competing trust":
						other := f.current().DeepCopy()
						other.Name = "competitor"
						other.UID = "competitor-uid"
						other.ResourceVersion = ""
						if err := f.kube.Create(ctx, other); err != nil {
							t.Fatal(err)
						}
					}
				}
				return check(ctx, i)
			}
			f.run(1)
			if f.posts+f.puts+f.deletes != 0 || len(f.current().Finalizers) != 0 || f.current().Status.Phase == "Ready" {
				t.Fatal("stale local authority survived uncached barrier")
			}
		})
	}
}

func TestWorkloadTrustUncertainCreateAndReadbackDriftRemainBlocked(t *testing.T) {
	f := newTrustFixture(t, ModeManage)
	f.run(1)
	s, err := f.r.workloadSnapshot(context.Background(), client.ObjectKey{Namespace: "auth", Name: "trust"}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.workloadCheckpoint(context.Background(), s, "CreateAttempted", true); err != nil {
		t.Fatal(err)
	}
	f.run(2)
	if f.posts != 0 || f.reason() != "OwnershipConflict" {
		t.Fatal("uncertain absent create was retried")
	}
	g := newTrustFixture(t, ModeManage)
	g.failure = "readback drift"
	g.run(3)
	if g.posts != 1 || g.current().Status.Phase == "Ready" || g.reason() != "OwnershipConflict" {
		t.Fatal("changed read-back was blindly repaired")
	}
}
