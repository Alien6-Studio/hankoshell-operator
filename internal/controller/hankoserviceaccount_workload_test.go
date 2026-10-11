package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type bindingFixture struct {
	*trustFixture
	account                        *api.HankoServiceAccount
	runtime                        *corev1.ConfigMap
	reconciler                     *HankoServiceAccountReconciler
	clientWrites, credentialRoutes int
}

func newBindingFixture(t *testing.T) *bindingFixture {
	t.Helper()
	f := &bindingFixture{trustFixture: newTrustFixture(t, "Manage")}
	f.run(4)
	f.account = &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "worker", UID: "identity-uid", Generation: 1}, Spec: api.HankoServiceAccountSpec{RealmRef: "managed", ClientID: "worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: "trust", SourceRef: "client-source", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workloads", ServiceAccountRef: "worker"}, ExpectedUID: "approved-uid"}, ExpirationSeconds: 600}}, RuntimeMetadata: &api.WorkloadRuntimeMetadataTarget{ApplicationRuntimeMetadataTarget: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}, ExpectedUID: "target-uid"}}}
	f.runtime = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "identity", UID: "target-uid", Labels: map[string]string{workloadbinding.TargetLabel: "workload-metadata"}, Annotations: workloadbinding.Authorization(f.account, f.account.Spec.Authentication.Kubernetes.Workload)}, Data: map[string]string{"unrelated": "preserve"}}
	for _, obj := range []client.Object{f.account, f.runtime, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "worker", UID: "approved-uid"}}, &api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "client-source", UID: "client-source-uid", Generation: 1}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "ca", AdminRef: corev1.LocalObjectReference{Name: "client-source"}}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "client-source", UID: "client-credential-uid"}, Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(f.server.URL), "HANKO_KC_CLIENT_ID": []byte("client-source"), "HANKO_KC_CLIENT_SECRET": []byte("credential-sentinel-client")}}} {
		if err := f.kube.Create(context.Background(), obj); err != nil {
			t.Fatal(err)
		}
	}
	previous := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/realms/managed/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL + "/realms/managed", "token_endpoint": f.server.URL + "/realms/managed/protocol/openid-connect/token"})
			return
		}
		if strings.Contains(request.URL.Path, "client-secret") {
			f.credentialRoutes++
			w.WriteHeader(403)
			return
		}
		if request.Header.Get("Authorization") != "Bearer client-source" || !strings.HasPrefix(request.URL.Path, "/admin/realms/managed/clients") {
			previous.ServeHTTP(w, request)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if request.Method == http.MethodGet {
			if request.URL.Path == "/admin/realms/managed/clients" {
				var matches []map[string]any
				for _, c := range f.dependents {
					if c["clientId"] == request.URL.Query().Get("clientId") {
						matches = append(matches, c)
					}
				}
				if matches == nil {
					matches = []map[string]any{}
				}
				_ = json.NewEncoder(w).Encode(matches)
				return
			}
			for _, c := range f.dependents {
				if request.URL.Path == "/admin/realms/managed/clients/"+c["id"].(string) {
					_ = json.NewEncoder(w).Encode(c)
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		if request.Method == http.MethodPut {
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || len(payload) != 3 || payload["enabled"] != false || payload["clientId"] != "worker" {
				t.Error("containment exceeded enabled-only boundary")
				w.WriteHeader(400)
				return
			}
			for _, c := range f.dependents {
				if request.URL.Path == "/admin/realms/managed/clients/"+c["id"].(string) && payload["id"] == c["id"] {
					c["enabled"] = false
					f.clientWrites++
					if f.lostAck {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = connection.Close()
						}
						return
					}
					w.WriteHeader(204)
					return
				}
			}
		}
		w.WriteHeader(403)
	})
	f.reconciler = &HankoServiceAccountReconciler{Client: f.kube, APIReader: f.kube, OwnershipReader: f.kube, RuntimeClient: f.kube, WorkloadTrust: f.r}
	return f
}

func (f *bindingFixture) reconcileBinding() {
	f.t.Helper()
	result, err := f.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.account)})
	if err != nil {
		f.t.Fatal(err)
	}
	if result.RequeueAfter != workloadBindingPoll {
		f.t.Fatal("binding must poll exact live references")
	}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account); err != nil {
		f.t.Fatal(err)
	}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.runtime), f.runtime); err != nil {
		f.t.Fatal(err)
	}
	b, _ := json.Marshal(f.account)
	if strings.Contains(string(b), "credential-sentinel") || strings.Contains(string(b), "eyJ") || f.credentialRoutes != 0 {
		f.t.Fatal("credential escaped workload boundary")
	}
}
func (f *bindingFixture) nativeClient(owner string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dependents = []map[string]any{{"id": "native-worker-uid", "clientId": "worker", "protocol": "openid-connect", "enabled": true, "clientAuthenticatorType": "federated-jwt", "serviceAccountsEnabled": true, "publicClient": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "fullScopeAllowed": false, "attributes": map[string]string{"hanko.sh/client-owner-kind": "HankoServiceAccount", "hanko.sh/client-owner-uid": owner, "jwt.credential.issuer": "cluster", "jwt.credential.sub": "system:serviceaccount:workloads:worker", "private-value": "credential-sentinel-unexported"}}}
}
func (f *bindingFixture) replaceWorkload() {
	f.t.Helper()
	var live corev1.ServiceAccount
	key := client.ObjectKey{Namespace: "workloads", Name: "worker"}
	if err := f.kube.Get(context.Background(), key, &live); err != nil {
		f.t.Fatal(err)
	}
	if err := f.kube.Delete(context.Background(), &live); err != nil {
		f.t.Fatal(err)
	}
	live = corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: "replacement-uid"}}
	if err := f.kube.Create(context.Background(), &live); err != nil {
		f.t.Fatal(err)
	}
}

func TestWorkloadBindingDeliversPublicMetadataWithoutAuthenticationActivation(t *testing.T) {
	f := newBindingFixture(t)
	f.reconcileBinding()
	if f.account.Status.Phase != "Pending" || f.account.Status.SecretRef != nil || f.account.Status.WorkloadBinding == nil || f.account.Status.RuntimeMetadata == nil || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationActivationPending" {
		t.Fatal("passive binding claimed authentication readiness")
	}
	var document workloadbinding.Document
	if json.Unmarshal([]byte(f.runtime.Data[workloadbinding.MetadataKey]), &document) != nil || document.Workload.ExpectedUID != "approved-uid" || document.AssertionAudience != f.server.URL+"/realms/managed" || document.TokenEndpoint != document.AssertionAudience+"/protocol/openid-connect/token" || document.ExpirationSeconds != 600 || document.AuthenticationActivation != "ManagedSeparately" {
		t.Fatal("public workload document has incorrect contract")
	}
	before := f.runtime.DeepCopy()
	f.reconcileBinding()
	if !reflect.DeepEqual(before, f.runtime) || f.clientWrites != 0 || f.posts != 1 || f.puts != 0 {
		t.Fatal("idempotent passive binding mutated native state/output")
	}
	if _, err := f.r.requireActiveWorkloadBinding(context.Background(), f.account); err == nil {
		t.Fatal("metadata was accepted as authentication")
	}
}

func TestWorkloadReplacementContainsOnlyOwnedNativeFederatedClient(t *testing.T) {
	for _, owner := range []string{"identity-uid", "foreign-uid"} {
		t.Run(owner, func(t *testing.T) {
			f := newBindingFixture(t)
			f.nativeClient(owner)
			if owner == "identity-uid" {
				f.reconcileBinding()
			}
			metadata := f.runtime.Data[workloadbinding.MetadataKey]
			f.replaceWorkload()
			f.lostAck = true
			f.reconcileBinding()
			f.reconcileBinding()
			if f.account.Status.WorkloadBinding != nil || f.account.Status.RuntimeMetadata != nil || f.account.Status.Phase == "Ready" || f.runtime.Data[workloadbinding.MetadataKey] != metadata {
				t.Fatal("replacement UID retained current readiness or received output")
			}
			want := 0
			if owner == "identity-uid" {
				want = 1
			}
			if f.clientWrites != want {
				t.Fatalf("containment writes %d want %d", f.clientWrites, want)
			}
			if owner == "identity-uid" && f.dependents[0]["enabled"] != false {
				t.Fatal("owned native client remained enabled")
			}
		})
	}
}

func TestWorkloadBindingRejectsDriftWithoutOutputWrites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bindingFixture)
		reason string
	}{
		{"projection", func(f *bindingFixture) { f.account.Spec.Authentication.Kubernetes.ExpirationSeconds = 900 }, "ProjectionExceedsTrustAge"},
		{"default", func(f *bindingFixture) {
			f.account.Spec.Authentication.Kubernetes.Workload.ServiceAccountRef = "default"
		}, "InvalidWorkloadBinding"},
		{"empty-uid", func(f *bindingFixture) { f.account.Spec.Authentication.Kubernetes.Workload.ExpectedUID = "" }, "InvalidWorkloadBinding"},
		{"missing-namespace", func(f *bindingFixture) { f.account.Spec.Authentication.Kubernetes.Workload.Namespace = "" }, "InvalidWorkloadBinding"},
		{"rotation", func(f *bindingFixture) {
			f.account.Spec.SecretRotationPolicy = &api.SecretRotationPolicy{Enabled: true}
		}, "SecretRotationIncompatible"},
		{"reserved", func(f *bindingFixture) {
			f.account.Spec.Attributes = map[string]string{"jwt.credential.issuer": "foreign"}
		}, "ReservedWorkloadAttribute"},
		{"connection", func(f *bindingFixture) { f.account.Spec.Authentication.Kubernetes.SourceRef = "missing" }, "SourceUnavailable"},
		{"target-uid", func(f *bindingFixture) { f.account.Spec.RuntimeMetadata.ExpectedUID = "replacement-target" }, "TargetNotAuthorized"},
		{"consent", func(f *bindingFixture) {
			delete(f.runtime.Annotations, workloadbinding.ConsentPrefix+"owner-uid")
			if err := f.kube.Update(context.Background(), f.runtime); err != nil {
				f.t.Fatal(err)
			}
		}, "TargetNotAuthorized"},
		{"binary", func(f *bindingFixture) {
			f.runtime.BinaryData = map[string][]byte{workloadbinding.MetadataKey: []byte("foreign")}
			if err := f.kube.Update(context.Background(), f.runtime); err != nil {
				f.t.Fatal(err)
			}
		}, "OutputConflict"},
		{"foreign-field", func(f *bindingFixture) {
			f.runtime.Data[workloadbinding.MetadataKey] = "foreign"
			if err := f.kube.Update(context.Background(), f.runtime); err != nil {
				f.t.Fatal(err)
			}
		}, "OutputConflict"},
		{"trust-generation", func(f *bindingFixture) { f.update(func(t *api.HankoWorkloadTrust) { t.Generation++ }) }, "WorkloadTrustNotReady"},
		{"trust-state", func(f *bindingFixture) { f.native(func(p map[string]any) { p["enabled"] = false }) }, "WorkloadTrustNotReady"},
		{"observe", func(f *bindingFixture) { f.account.Spec.Mode = "Observe" }, "ObserveOnly"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newBindingFixture(t)
			test.mutate(f)
			if err := f.kube.Update(context.Background(), f.account); err != nil {
				t.Fatal(err)
			}
			before := f.runtime.DeepCopy()
			f.reconcileBinding()
			if conditionReason(f.account.Status.Conditions, "WorkloadBindingReady") != test.reason {
				t.Fatalf("reason %s want %s", conditionReason(f.account.Status.Conditions, "WorkloadBindingReady"), test.reason)
			}
			if !reflect.DeepEqual(before, f.runtime) || f.clientWrites != 0 || f.account.Status.WorkloadBinding != nil {
				t.Fatal("invalid binding progressed")
			}
		})
	}
}

func TestWorkloadMetadataCleanupRequiresCurrentConsentAndPreservesOtherFields(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "consented", true: "revoked"}[revoke], func(t *testing.T) {
			f := newBindingFixture(t)
			f.reconcileBinding()
			if revoke {
				delete(f.runtime.Annotations, workloadbinding.ConsentPrefix+"owner-uid")
				if err := f.kube.Update(context.Background(), f.runtime); err != nil {
					t.Fatal(err)
				}
			}
			f.account.Spec.RuntimeMetadata = nil
			f.account.Generation++
			if err := f.kube.Update(context.Background(), f.account); err != nil {
				t.Fatal(err)
			}
			f.reconcileBinding()
			if f.runtime.Data["unrelated"] != "preserve" {
				t.Fatal("cleanup changed foreign data")
			}
			if revoke && f.runtime.Data[workloadbinding.MetadataKey] == "" || !revoke && (f.runtime.Data[workloadbinding.MetadataKey] != "" || f.account.Annotations[workloadbinding.JournalKey] != "") {
				t.Fatal("cleanup ignored current consent")
			}
		})
	}
}

type bindingPatchFailure struct {
	client.Client
	lost bool
}

func (c bindingPatchFailure) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		if c.lost {
			if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
		}
		return errors.New("ack unavailable")
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}
func TestWorkloadMetadataRecoversLostAcknowledgementAndRefusesFailedPatch(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "lost-ack"}[lost], func(t *testing.T) {
			f := newBindingFixture(t)
			f.reconciler.RuntimeClient = bindingPatchFailure{Client: f.kube, lost: lost}
			f.reconcileBinding()
			if (f.account.Status.RuntimeMetadata != nil) != lost {
				t.Fatal("delivery did not distinguish observed write from unconfirmed output")
			}
			if f.account.Annotations[workloadbinding.JournalKey] == "" {
				t.Fatal("delivery did not persist cleanup journal before write")
			}
		})
	}
}

func (f *bindingFixture) activeFixtureEvidence() {
	f.t.Helper()
	f.reconcileBinding()
	// This is synthetic future activation evidence. The passive controller never
	// emits it; native Admin and installed suites independently qualify writes.
	f.account.Status.Phase = "Ready"
	iamCondition(&f.account.Status.Conditions, f.account.Generation, "Synced", metav1.ConditionTrue, "FixtureNativeReadBack", "synthetic activation fixture")
	iamCondition(&f.account.Status.Conditions, f.account.Generation, "FederatedModeApplied", metav1.ConditionTrue, "FixtureNativeReadBack", "synthetic activation fixture")
	if err := f.kube.Status().Update(context.Background(), f.account); err != nil {
		f.t.Fatal(err)
	}
}

func TestWorkloadMeshAndGrantsRejectPassiveStaleOrForeignNativeEvidence(t *testing.T) {
	f := newBindingFixture(t)
	f.nativeClient("identity-uid")
	f.reconcileBinding()
	r := &HankoResourceServerReconciler{Client: f.kube, APIReader: f.kube, WorkloadTrust: f.r}
	rs := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Namespace: "auth"}, Spec: api.HankoResourceServerSpec{RealmRef: "managed"}}
	principal := api.AuthorizationPrincipal{Kind: "service_account", Ref: f.account.Name}
	if _, err := r.resolveAuthorizationPrincipal(context.Background(), rs, nil, principal); err == nil {
		t.Fatal("passive metadata granted IAM principal")
	}
	f.activeFixtureEvidence()
	if _, err := r.resolveAuthorizationPrincipal(context.Background(), rs, nil, principal); err != nil {
		t.Fatal(err)
	}
	f.replaceWorkload()
	// Ready/activation status deliberately remains forged stale. Live UID wins.
	if _, err := r.resolveAuthorizationPrincipal(context.Background(), rs, nil, principal); err == nil {
		t.Fatal("stale Ready permitted grant progression")
	}
	mesh := &api.HankoMeshService{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "worker", Generation: 1}, Spec: api.HankoMeshServiceSpec{TenantRef: "tenant", IdentityRef: f.account.Name, ResourceServerRef: "resource", ServiceRef: "worker", WorkloadServiceAccountRef: "worker"}, Status: api.HankoMeshServiceStatus{Phase: "Ready", WorkloadID: "worker", WorkloadServiceAccountUID: "approved-uid"}}
	tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "tenant", Generation: 1}, Spec: api.HankoTenantSpec{RealmRef: "managed", IsolationMode: "realm"}, Status: api.HankoTenantStatus{Phase: "Synced", ObservedGeneration: 1, TenantID: "tenant-uid", ClusterID: "cluster-uid"}}
	for _, obj := range []client.Object{mesh, tenant} {
		if err := f.kube.Create(context.Background(), obj); err != nil {
			t.Fatal(err)
		}
	}
	meshReconciler := &HankoMeshServiceReconciler{Client: f.kube, APIReader: f.kube, WorkloadTrust: f.r}
	if _, err := meshReconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mesh)}); workloadbinding.Reason(err) != "WorkloadUIDMismatch" {
		t.Fatalf("mesh did not report stale workload: %v", err)
	}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(mesh), mesh); err != nil {
		t.Fatal(err)
	}
	if mesh.Status.Phase != "Error" || mesh.Status.WorkloadServiceAccountUID != "" || mesh.Status.WorkloadID != "" {
		t.Fatal("mesh retained stale workload attestation")
	}
}

func TestWorkloadMeshRequiresSameNamespaceAndApprovedUIDKeepsResourceAudience(t *testing.T) {
	f := newBindingFixture(t)
	f.account.Spec.RuntimeMetadata = nil
	f.account.Spec.Authentication.Kubernetes.Workload.Namespace = "auth"
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.nativeClient("identity-uid")
	f.dependents[0]["attributes"].(map[string]string)["jwt.credential.sub"] = "system:serviceaccount:auth:worker"
	registration, objects := validMeshServiceObjects()
	registration.Namespace = "auth"
	registration.Spec.IdentityRef = "worker"
	registration.Spec.WorkloadServiceAccountRef = "worker"
	registration.Spec.TenantRef = "tenant"
	for _, obj := range objects {
		obj.SetNamespace("auth")
		switch value := obj.(type) {
		case *api.HankoServiceAccount:
			continue
		case *api.HankoTenant:
			value.Name = "tenant"
			value.Spec.RealmRef = "managed"
		case *api.HankoResourceServer:
			value.Spec.RealmRef = "managed"
		case *corev1.ServiceAccount:
			value.Name = "worker"
			value.UID = "approved-uid"
		case *corev1.Pod:
			value.Spec.ServiceAccountName = "worker"
		}
		if err := f.kube.Create(context.Background(), obj); err != nil {
			t.Fatal(err)
		}
	}
	f.activeFixtureEvidence()
	r := &HankoMeshServiceReconciler{Client: f.kube, APIReader: f.kube, NodeReader: f.kube, EgressReader: f.kube, WorkloadTrust: f.r}
	resolved, err := r.resolve(context.Background(), registration)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.workloadServiceAccountUID != "approved-uid" || resolved.audience != "https://orders.internal" || resolved.audience == f.server.URL+"/realms/managed" {
		t.Fatal("mesh lost anchor or replaced resource audience with assertion audience")
	}
	registration.Spec.WorkloadServiceAccountRef = "other"
	if _, err := r.resolve(context.Background(), registration); err == nil {
		t.Fatal("mesh accepted different service account")
	}
	registration.Spec.WorkloadServiceAccountRef = "worker"
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account); err != nil {
		t.Fatal(err)
	}
	f.account.Spec.Authentication.Kubernetes.Workload.Namespace = "workloads"
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	if _, err := r.statusReady(context.Background(), registration, resolved); workloadbinding.Reason(err) != "StaleSource" {
		t.Fatalf("mesh did not reject changed anchor: %v", err)
	}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(registration), registration); err != nil {
		t.Fatal(err)
	}
	if registration.Status.Phase != "Error" {
		t.Fatal("mesh write barrier accepted changed workload anchor")
	}
}

type bindingReadHook struct {
	client.Reader
	after  func(client.Object)
	denied bool
}

func (r *bindingReadHook) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.ServiceAccount); ok && r.denied {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, key.Name, errors.New("denied"))
	}
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if r.after != nil {
		r.after(obj)
	}
	return nil
}

func TestWorkloadBindingFreshEndBarrierRejectsSourceMutationAndReadOutage(t *testing.T) {
	t.Run("source-generation", func(t *testing.T) {
		f := newBindingFixture(t)
		reader := &bindingReadHook{Reader: f.kube}
		reader.after = func(obj client.Object) {
			if _, ok := obj.(*api.HankoServiceAccount); !ok {
				return
			}
			reader.after = nil
			var current api.HankoServiceAccount
			if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), &current); err != nil {
				t.Fatal(err)
			}
			current.Generation++
			if err := f.kube.Update(context.Background(), &current); err != nil {
				t.Fatal(err)
			}
		}
		f.r.APIReader = reader
		_, err := f.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.account)})
		if !errors.Is(err, iamcontract.ErrStale) {
			t.Fatalf("expected stale source, got %v", err)
		}
		if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.runtime), f.runtime); err != nil {
			t.Fatal(err)
		}
		if f.runtime.Data[workloadbinding.MetadataKey] != "" {
			t.Fatal("changed generation wrote output")
		}
	})
	t.Run("forbidden-SA", func(t *testing.T) {
		f := newBindingFixture(t)
		f.nativeClient("identity-uid")
		f.activeFixtureEvidence()
		reader := &bindingReadHook{Reader: f.kube, denied: true}
		f.r.APIReader = reader
		f.reconciler.APIReader = reader
		f.reconcileBinding()
		if f.clientWrites != 0 || f.account.Status.WorkloadBinding != nil || conditionReason(f.account.Status.Conditions, "WorkloadBindingReady") != "WorkloadUnavailable" {
			t.Fatal("uncertain read was treated as confirmed workload loss")
		}
	})
}

func TestWorkloadFederatedClientCannotEnterLegacySecretOperations(t *testing.T) {
	f := newBindingFixture(t)
	f.nativeClient("identity-uid")
	source, err := f.r.workloadConnection(context.Background(), "auth", "client-source")
	if err != nil {
		t.Fatal(err)
	}
	kc := source.client
	operations := []func() error{
		func() error {
			_, err := kc.GetServiceAccountSecretIfOwned(context.Background(), "managed", "worker", "identity-uid")
			return err
		},
		func() error {
			_, err := kc.RotateServiceAccountSecretIfOwned(context.Background(), "managed", "worker", "identity-uid")
			return err
		},
		func() error {
			return kc.SyncServiceAccountAttributesIfOwned(context.Background(), "managed", "worker", "identity-uid", map[string]string{"ordinary": "value"})
		},
		func() error {
			return kc.DeleteServiceAccountIfOwned(context.Background(), "managed", "worker", "identity-uid")
		},
	}
	for _, operation := range operations {
		if operation() == nil {
			t.Fatal("native federated client entered legacy Secret boundary")
		}
	}
	if f.credentialRoutes != 0 || f.clientWrites != 0 {
		t.Fatal("legacy boundary dispatched credentials or federated client mutation")
	}
}
