package controller_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authentik"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const experimentalSelector = "hanko.sh/provider-connection"
const experimentalJournal = "hanko.sh/experimental-provider-journal"

func experimentalObjects(t *testing.T, endpoint string, ca []byte) (*corev1.ConfigMap, *corev1.Secret, *corev1.Secret) {
	t.Helper()
	id := "00000000-0000-4000-8000-000000000001"
	config := authentik.Connection{SchemaVersion: 1, Provider: "authentik", Version: authentik.Version, Endpoint: endpoint, Realm: "portable", TokenSecret: "provider-token", CASecret: "provider-ca", AuthorizationFlow: id, InvalidationFlow: id, SigningKey: id, ScopeMappings: []string{id}}
	data, _ := json.Marshal(config)
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "experimental", Namespace: "auth", UID: "connection-uid"}, Data: map[string]string{"connection.json": string(data)}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "provider-token", Namespace: "auth", UID: "token-uid"}, Data: map[string][]byte{"token": []byte("PRIVATE-provider-sentinel")}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "provider-ca", Namespace: "auth", UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}}
}
func experimentalApp() *api.HankoApplication {
	return &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "experimental-spa", Namespace: "auth", UID: "application-uid", Generation: 1, Labels: map[string]string{experimentalSelector: "experimental"}}, Spec: api.HankoApplicationSpec{RealmRef: "portable", ClientID: "portable-spa", Type: "spa", RedirectURIs: []string{"https://app.example/callback"}, Mode: "Manage"}}
}
func TestExperimentalProviderControllerLifecycleAndBoundaries(t *testing.T) {
	var provider, application map[string]any
	writes := 0
	denied := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if denied {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("PRIVATE-provider-sentinel"))
			return
		}
		if r.Method != http.MethodGet {
			writes++
		}
		output := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.URL.Path == "/api/v3/providers/oauth2/" && r.Method == http.MethodGet {
			results := []any{}
			if provider != nil {
				results = append(results, provider)
			}
			output(map[string]any{"pagination": map[string]any{"count": len(results), "next": 0}, "results": results})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v3/providers/oauth2/") {
			if r.Method == http.MethodDelete {
				provider = nil
				w.WriteHeader(204)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&provider)
			provider["pk"] = 7
			output(provider)
			return
		}
		if r.URL.Path == "/api/v3/core/applications/" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&application)
			application["pk"] = "00000000-0000-4000-8000-000000000001"
			output(application)
			return
		}
		if r.Method == http.MethodDelete {
			application = nil
			w.WriteHeader(204)
			return
		}
		if application == nil {
			w.WriteHeader(404)
			return
		}
		output(application)
	}))
	defer server.Close()
	cert, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	config, token, trust := experimentalObjects(t, server.URL, ca)
	app := experimentalApp()
	kube := newFakeClient(t, config, token, trust, app)
	r := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, ExperimentalAuthentik: true, ExperimentalAuthentikConnections: []string{"experimental"}}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(ctx, req.NamespacedName, app); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	if writes != 0 || app.Annotations[experimentalJournal] == "" {
		t.Fatal("provider mutated before durable checkpoint")
	}
	reconcile()
	if app.Status.Phase != "Ready" || app.Status.BackendKind != "authentik" || !app.Status.ObservationComplete || app.Status.AppliedPlanHash == "" {
		t.Fatalf("experimental evidence incomplete: phase %s", app.Status.Phase)
	}
	before := writes
	reconcile()
	if writes != before {
		t.Fatal("idempotent reconciliation wrote provider")
	}
	iamconformance.NoSecrets(t, []string{string(token.Data["token"])}, app.Status, app.Annotations)
	denied = true
	reconcile()
	if app.Status.Phase != "Error" || app.Status.AppliedPlanHash != "" {
		t.Fatal("denied administration retained application proof")
	}
	denied = false
	r.ExperimentalAuthentik = false
	reconcile()
	if writes != before || len(app.Finalizers) == 0 {
		t.Fatal("disabled provider mutated or discarded cleanup authority")
	}
	r.ExperimentalAuthentik = true
	patch := client.MergeFrom(app.DeepCopy())
	app.Labels[experimentalSelector] = "different"
	if err := kube.Patch(ctx, app, patch); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if writes != before {
		t.Fatal("retargeted connection reused ownership")
	}
	patch = client.MergeFrom(app.DeepCopy())
	app.Labels[experimentalSelector] = "experimental"
	if err := kube.Patch(ctx, app, patch); err != nil {
		t.Fatal(err)
	}
	reconcile()
	// Restart reconstructs the same driver and journal from public identities.
	r = &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, ExperimentalAuthentik: true, ExperimentalAuthentikConnections: []string{"experimental"}}
	reconcile()
	if writes != before {
		t.Fatal("restart duplicated provider graph")
	}

	// Neither inherited realm policy nor operational bindings may be dropped by
	// retargeting an otherwise portable application.
	realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "portable", Namespace: "auth", Labels: map[string]string{experimentalSelector: "experimental"}}, Spec: api.HankoRealmSpec{OTPRequired: true}}
	if err := kube.Create(ctx, realm); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if app.Status.Phase != "Error" || writes != before {
		t.Fatal("inherited MFA policy was silently dropped")
	}
	if err := kube.Delete(ctx, realm); err != nil {
		t.Fatal(err)
	}
	app.Spec.RuntimeBindings = []api.ApplicationRuntimeBinding{{}}
	app.Generation++
	if err := kube.Update(ctx, app); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if app.Status.Phase != "Error" || writes != before {
		t.Fatal("runtime binding was silently dropped")
	}
	app.Spec.RuntimeBindings = nil
	app.Generation++
	if err := kube.Update(ctx, app); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if err := kube.Delete(ctx, app); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if provider != nil || application != nil {
		t.Fatal("owned deletion left provider state")
	}

	observed := experimentalApp()
	observed.UID = "observe-only-uid"
	observed.Spec.Mode = "Observe"
	if err := kube.Create(ctx, observed); err != nil {
		t.Fatal(err)
	}
	before = writes
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, req.NamespacedName, observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Phase != "Pending" || observed.Status.AppliedPlanHash != "" || observed.Status.OIDCEndpoints != nil || len(observed.Finalizers) > 0 || writes != before {
		t.Fatal("absent Observe was presented as synchronized or mutated provider")
	}
}
func TestExperimentalProviderRejectsUnsupportedIntentBeforeCheckpoint(t *testing.T) {
	config, token, ca := experimentalObjects(t, "https://provider.example", []byte("not read before rejection"))
	corpus, err := iamconformance.ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Fixtures {
		if fixture.Manifest.Kind != "HankoApplication" || fixture.Expected["authentik"].Classification != "unsupported" {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			app := experimentalApp()
			app.UID = types.UID("unsupported-" + fixture.Name)
			// Unmarshal into an empty spec so absent fields cannot inherit a supported
			// fixture's redirects or pattern.
			app.Spec = api.HankoApplicationSpec{}
			if err := json.Unmarshal(fixture.Manifest.Spec, &app.Spec); err != nil {
				t.Fatal(err)
			}
			kube := newFakeClient(t, config.DeepCopy(), token.DeepCopy(), ca.DeepCopy(), app)
			r := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, ExperimentalAuthentik: true, ExperimentalAuthentikConnections: []string{"experimental"}}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(app), app); err != nil {
				t.Fatal(err)
			}
			if app.Status.Phase != "Error" || len(app.Finalizers) > 0 || app.Annotations[experimentalJournal] != "" {
				t.Fatal("unsupported intent acquired execution authority")
			}
		})
	}
}
