//go:build native_workload_qualification

package controller_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type nativeAuthenticationInput struct {
	Endpoint, CA, Kubeconfig, Realm, Issuer, KeysHash, ExpectedUID, LegacyUID, Action string
	Credentials                                                                       map[string]string
}

// Only the fixture's Hanko CRs/connections and canonical recovery Secret use
// ephemeral storage. Namespace and workload UID reads use the real API server.
// Actual projected assertions remain exclusively in the Python/Pod fixture.
type nativeAuthenticationReader struct {
	client.Reader
	cluster client.Reader
}

func (r nativeAuthenticationReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	switch obj.(type) {
	case *corev1.Namespace, *corev1.ServiceAccount:
		return r.cluster.Get(ctx, key, obj, opts...)
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type nativeAuthenticationState struct {
	Trust  api.HankoWorkloadTrust
	Worker api.HankoServiceAccount
	Legacy api.HankoServiceAccount
	Secret *corev1.Secret
}

// TestNativeWorkloadAuthenticationController runs only inside the disposable
// six-cell native fixture. It receives connection credentials and public cluster
// configuration, never a workload assertion or an access token from that Pod.
func TestNativeWorkloadAuthenticationController(t *testing.T) {
	path := os.Getenv("HANKO_NATIVE_CONTROLLER_INPUT")
	if path == "" {
		t.Fatal("private fixture input required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal("private fixture input unavailable")
	}
	var input nativeAuthenticationInput
	if json.Unmarshal(data, &input) != nil {
		t.Fatal("invalid private fixture input")
	}
	ctx := context.Background()
	scheme := newScheme(t)
	config, err := clientcmd.BuildConfigFromFlags("", input.Kubeconfig)
	if err != nil {
		t.Fatal("fixture cluster connection unavailable")
	}
	cluster, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal("fixture API client unavailable")
	}
	var namespace corev1.Namespace
	if cluster.Get(ctx, client.ObjectKey{Name: "kube-system"}, &namespace) != nil {
		t.Fatal("current cluster UID unavailable")
	}
	if rest.LoadTLSFiles(config) != nil {
		t.Fatal("cluster CA unavailable")
	}
	hash, err := workloadtrust.APICAHash(config.CAData)
	if err != nil {
		t.Fatal("cluster CA unavailable")
	}
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: "auth", Name: name, UID: types.UID("fixture-" + name), Generation: 1}
	}
	kubeBinding := func(name, uid string) *api.KubernetesServiceAccountAuthentication {
		return &api.KubernetesServiceAccountAuthentication{TrustRef: "controller-trust", SourceRef: "controller-client-writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workload", ServiceAccountRef: name}, ExpectedUID: uid}, ExpirationSeconds: 600}
	}
	state := nativeAuthenticationState{Trust: api.HankoWorkloadTrust{ObjectMeta: meta("controller-trust"), Spec: api.HankoWorkloadTrustSpec{Mode: "Manage", RealmRef: input.Realm, SourceRef: "controller-observer", WriterRef: "controller-trust-writer", DependentReaderRef: "controller-dependent-reader", KeycloakAlias: "controller-kube", Provider: "Kubernetes", Kubernetes: api.KubernetesWorkloadTrustSpec{Issuer: input.Issuer, AssertionMaxAgeSeconds: 600, ClusterAnchor: api.WorkloadClusterAnchor{KubeSystemNamespaceUID: string(namespace.UID), APIServerCAHash: hash}}}}, Worker: api.HankoServiceAccount{ObjectMeta: meta("controller-worker"), Spec: api.HankoServiceAccountSpec{RealmRef: input.Realm, ClientID: "controller-worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: kubeBinding("worker", input.ExpectedUID)}}}, Legacy: api.HankoServiceAccount{ObjectMeta: meta("controller-secret"), Spec: api.HankoServiceAccountSpec{RealmRef: input.Realm, ClientID: "controller-secret", Attributes: map[string]string{"locale": "fr"}}}}
	statePath := filepath.Join(filepath.Dir(path), "controller-state.json")
	if saved, e := os.ReadFile(statePath); e == nil {
		if json.Unmarshal(saved, &state) != nil {
			t.Fatal("invalid durable fixture state")
		}
	}
	objects := []client.Object{&state.Trust, &state.Worker, &state.Legacy, &api.HankoRealm{ObjectMeta: meta(input.Realm)}, &corev1.Secret{ObjectMeta: meta("controller-ca"), Data: map[string][]byte{"ca.crt": []byte(input.CA)}}}
	for name, credential := range input.Credentials {
		objects = append(objects, &api.HankoKeycloakInstance{ObjectMeta: meta(name), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "controller-ca", AdminRef: corev1.LocalObjectReference{Name: name}}}, &corev1.Secret{ObjectMeta: meta(name), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(input.Endpoint), "HANKO_KC_CLIENT_ID": []byte(name), "HANKO_KC_CLIENT_SECRET": []byte(credential)}})
	}
	if state.Secret != nil {
		objects = append(objects, state.Secret)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.HankoWorkloadTrust{}, &api.HankoServiceAccount{}).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("fixture-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}).Build()
	reader := nativeAuthenticationReader{Reader: kube, cluster: cluster}
	trust := &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: reader, ClusterConfig: config, DiscoveryCheck: func(_ context.Context, intent workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		return workloadtrust.DiscoveryEvidence{Issuer: input.Issuer, JWKSURL: input.Issuer + "/openid/v1/jwks", KeysHash: input.KeysHash}, nil
	}}
	for range 4 {
		if _, err := trust.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&state.Trust)}); err != nil {
			t.Fatal("native trust reconcile failed")
		}
	}
	if kube.Get(ctx, client.ObjectKeyFromObject(&state.Trust), &state.Trust) != nil || state.Trust.Status.Phase != "Ready" {
		t.Fatal("native typed trust not ready")
	}
	w, err := keycloak.NewWithTLS(input.Endpoint, "controller-client-writer", input.Credentials["controller-client-writer"], []byte(input.CA))
	if err != nil {
		t.Fatal("native client connection unavailable")
	}
	r := &controller.HankoServiceAccountReconciler{Client: kube, APIReader: reader, OwnershipReader: reader, RuntimeClient: kube, WorkloadTrust: trust, Scheme: scheme, Pool: keycloak.NewPool(w)}
	account := &state.Worker
	if input.Action != "create" && input.Action != "contain" {
		account = &state.Legacy
	}
	if input.Action == "prepare-federated" || input.Action == "prepare-return" || input.Action == "prepare-fallback" {
		mode := "Kubernetes"
		auth := &api.ServiceAccountAuthentication{Mode: mode, Kubernetes: kubeBinding("controller-legacy", input.LegacyUID), Transition: &api.ServiceAccountAuthenticationTransition{Strategy: "CoordinatedCutover", RequestID: input.Action, PreparedWorkloadRevision: "projected-workload"}}
		if input.Action == "prepare-fallback" {
			auth.Mode = "Secret"
			auth.FallbackBinding = auth.Kubernetes
			auth.Kubernetes = nil
		}
		account.Spec.Authentication = auth
		account.Generation++
		for _, key := range []string{workloadauth.ApprovalKey, workloadauth.ReviewKey, workloadauth.CleanupKey} {
			delete(account.Annotations, key)
		}
		if kube.Update(ctx, account) != nil {
			t.Fatal("fixture transition preparation failed")
		}
	}
	if input.Action == "approve" || input.Action == "review" {
		j, err := workloadauth.ParseJournal(account.Annotations[workloadauth.JournalKey])
		if err != nil || j == nil {
			t.Fatal("native transaction journal unavailable")
		}
		if input.Action == "approve" {
			account.Annotations[workloadauth.ApprovalKey] = workloadauth.Encode(workloadauth.Approval{Strategy: "CoordinatedCutover", OwnerUID: j.OwnerUID, Generation: j.Generation, RequestID: j.RequestID, ExpectedClientUUID: j.ClientUUID, ReviewedStateHash: j.NativeStateHash, BindingRevision: j.BindingRevision, PreparedWorkloadRevision: j.PreparedWorkloadRevision, PreviousMode: j.PreviousMode, DesiredMode: j.DesiredMode, TrustUID: j.TrustUID, ProviderID: j.ProviderID, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash, PreparationApproved: true})
		} else {
			review := workloadauth.Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
			account.Annotations[workloadauth.ReviewKey] = workloadauth.Encode(review)
			var secret corev1.Secret
			if kube.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "hanko-sa-controller-secret"}, &secret) != nil {
				t.Fatal("canonical fixture Secret unavailable")
			}
			account.Annotations[workloadauth.CleanupKey] = workloadauth.Encode(workloadauth.Cleanup{Review: review, SecretUID: string(secret.UID)})
		}
		if kube.Update(ctx, account) != nil {
			t.Fatal("fixture review write failed")
		}
	}
	for range 4 {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(account)}); err != nil {
			t.Fatal("native authentication reconcile failed")
		}
		if kube.Get(ctx, client.ObjectKeyFromObject(account), account) != nil {
			t.Fatal("native authentication read-back failed")
		}
	}
	if input.Action == "approve" && account.Spec.Authentication.Mode == "Kubernetes" {
		journal, err := workloadauth.ParseJournal(account.Annotations[workloadauth.JournalKey])
		if err != nil || journal == nil || journal.Step != "ModeApplied" {
			for _, condition := range account.Status.Conditions {
				if condition.Type == "Synced" {
					t.Fatalf("native cutover not applied: %s", condition.Reason)
				}
			}
			t.Fatal("native cutover checkpoint missing")
		}
	}
	if input.Action == "create" || input.Action == "secret" || input.Action == "review" || input.Action == "approve" && account.Spec.Authentication.Mode == "Secret" {
		if account.Status.Phase != "Ready" {
			t.Fatalf("native method did not converge: %s", account.Status.Conditions[len(account.Status.Conditions)-1].Reason)
		}
	}
	if input.Action == "contain" {
		if account.Status.WorkloadBinding != nil || account.Status.Phase == "Ready" {
			t.Fatal("real UID replacement did not clear readiness")
		}
	}
	if kube.Get(ctx, client.ObjectKeyFromObject(&state.Worker), &state.Worker) != nil || kube.Get(ctx, client.ObjectKeyFromObject(&state.Legacy), &state.Legacy) != nil {
		t.Fatal("fixture persistence failed")
	}
	var secret corev1.Secret
	if kube.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "hanko-sa-controller-secret"}, &secret) == nil {
		state.Secret = &secret
	}
	encoded, err := json.Marshal(state)
	if err != nil || os.WriteFile(statePath, encoded, 0600) != nil {
		t.Fatal("private fixture persistence failed")
	}
	// This output is a public count/behavior report. Private canonical credentials
	// remain in the disposable fixture state, never in the uploaded evidence.
	t.Log("native controller action complete; workload assertions were not supplied to the controller")
}
