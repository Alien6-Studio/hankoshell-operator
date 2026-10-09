package controller_test

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// runtimeKube models API-server Secret StringData conversion and assigned UIDs;
// fake.Client deliberately does not implement either server behavior.
func runtimeKube(c client.Client) client.WithWatch {
	return interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, base client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("fixture-" + obj.GetNamespace() + "-" + obj.GetName()))
			}
			if s, ok := obj.(*corev1.Secret); ok {
				convertSecret(s)
			}
			return base.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, base client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := base.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			if s, ok := obj.(*corev1.Secret); ok && len(s.StringData) > 0 {
				var stored corev1.Secret
				if err := base.Get(ctx, client.ObjectKeyFromObject(s), &stored); err != nil {
					return err
				}
				convertSecret(&stored)
				if err := base.Update(ctx, &stored); err != nil {
					return err
				}
				*s = stored
			}
			return nil
		},
	})
}
func convertSecret(s *corev1.Secret) {
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	for k, v := range s.StringData {
		s.Data[k] = []byte(v)
	}
	s.StringData = nil
}
func runtimeTargets(app *api.HankoApplication, b api.ApplicationRuntimeBinding) []client.Object {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: b.Workload.Namespace, Name: b.Workload.ServiceAccountRef, UID: "worker-uid"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: b.Workload.Namespace, Name: b.PublicMetadata.ConfigMapRef, UID: "metadata-uid", Labels: map[string]string{applicationbinding.TargetLabel: "metadata"}, Annotations: applicationbinding.Authorization(app, b, string(sa.UID))}, Data: map[string]string{"owner": "preserved"}}
	objects := []client.Object{sa, cm}
	if b.Credentials != nil {
		objects = append(objects, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.Workload.Namespace, Name: b.Credentials.SecretRef, UID: "target-credential-uid", Labels: map[string]string{applicationbinding.TargetLabel: "credentials"}, Annotations: applicationbinding.Authorization(app, b, string(sa.UID))}, Data: map[string][]byte{"owner": []byte("preserved")}})
	}
	return objects
}
func providerWrites(m *mockKeycloak) map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := map[string]int{}
	for _, k := range []string{"create", "update", "delete", "createRole", "rotateSecret", "createProtocolMapper", "updateProtocolMapper", "deleteProtocolMapper", "createIDPMapper", "updateIDPMapper", "deleteIDPMapper"} {
		result[k] = m.counts[k]
	}
	return result
}
func TestRuntimeBindingRetryDoesNotRepeatProviderWrites(t *testing.T) {
	for _, fault := range []string{"secret-patch", "lost-ack", "status-patch"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			kc := newMockKeycloak(t)
			b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}, Credentials: &api.ApplicationRuntimeCredentialTarget{SecretRef: "identity"}}
			audience := "runtime-worker"
			app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "runtime-worker", UID: "application-uid", Generation: 1}, Spec: api.HankoApplicationSpec{RealmRef: "myrealm", ClientID: "runtime-worker", Type: "m2m", TokenClaims: []api.ApplicationTokenClaim{{Name: "audience", Claim: "aud", Value: &audience}}, RuntimeBindings: []api.ApplicationRuntimeBinding{b}}}
			objects := append([]client.Object{app}, runtimeTargets(app, b)...)
			base := runtimeKube(newFakeClient(t, objects...))
			failing := true
			targetPatches := 0
			kube := interceptor.NewClient(base, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
					if obj.GetNamespace() == "payments" {
						targetPatches++
						if failing && fault != "status-patch" && obj.GetName() == "identity" {
							if _, ok := obj.(*corev1.Secret); ok {
								failing = false
								if fault == "lost-ack" {
									if err := c.Patch(ctx, obj, p, opts...); err != nil {
										return err
									}
								}
								return errors.New("injected target failure")
							}
						}
					}
					return c.Patch(ctx, obj, p, opts...)
				},
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
					if a, ok := obj.(*api.HankoApplication); ok && sub == "status" && fault == "status-patch" && failing && condition(a, "RuntimeBindings") != nil && condition(a, "RuntimeBindings").Status == metav1.ConditionTrue {
						failing = false
						return errors.New("injected runtime status failure")
					}
					return c.SubResource(sub).Patch(ctx, obj, p, opts...)
				},
			})
			ar := newReconciler(t, kube, kc.client())
			ar.RuntimeClient = kube
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}
			if _, err := ar.Reconcile(ctx, req); err == nil {
				t.Fatal("fault did not fail reconciliation")
			}
			writes := providerWrites(kc)
			var cm corev1.ConfigMap
			if err := base.Get(ctx, client.ObjectKey{Namespace: "payments", Name: "identity"}, &cm); err != nil {
				t.Fatal(err)
			}
			revision := cm.Annotations[applicationbinding.RevisionAnnotation]
			if revision == "" {
				t.Fatalf("partial delivery not exercised; application conditions: %#v", getApp(t, kube, app.Name).Status.Conditions)
			}
			if _, err := ar.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(writes, providerWrites(kc)) {
				t.Fatalf("retry repeated provider mutations: %v -> %v", writes, providerWrites(kc))
			}
			actual := getApp(t, kube, app.Name)
			if actual.Status.Phase != "Ready" || condition(actual, "RuntimeBindings").Status != metav1.ConditionTrue || actual.Status.RuntimeBindings[0].BindingRevision != revision {
				t.Fatal("retry did not converge on original revision")
			}
			before := targetPatches
			if _, err := ar.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if targetPatches != before {
				t.Fatal("current outputs rewritten on retry")
			}
			// Rotation checkpoint survives lost provider evidence status, then converges
			// both outputs without a second rotation on runtime retries.
			actual = getApp(t, kube, app.Name)
			at := metav1.NewTime(time.Now().Add(time.Second).Truncate(time.Second))
			time.Sleep(time.Until(at.Time) + 20*time.Millisecond)
			actual.Spec.SecretRotationPolicy = &api.SecretRotationPolicy{Enabled: true, ForceRotateAt: &at}
			actual.Generation++
			if err := kube.Update(ctx, actual); err != nil {
				t.Fatal(err)
			}
			lost := true
			rotating := interceptor.NewClient(kube, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
				if sub == "status" && lost {
					lost = false
					return errors.New("injected rotation status failure")
				}
				return c.SubResource(sub).Patch(ctx, obj, p, opts...)
			}})
			ar.Client = rotating
			ar.OwnershipReader = rotating
			ar.RuntimeClient = rotating
			if _, err := ar.Reconcile(ctx, req); err == nil {
				t.Fatal("rotation status loss not exercised")
			}
			writes = providerWrites(kc)
			if writes["rotateSecret"] != 1 {
				t.Fatal("rotation not exercised")
			}
			if _, err := ar.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(writes, providerWrites(kc)) {
				t.Fatal("status loss repeated provider rotation/mutation")
			}
			actual = getApp(t, kube, app.Name)
			if actual.Status.RuntimeBindings[0].BindingRevision == revision {
				t.Fatal("rotation did not advance revision")
			}
			// Unavailable public metadata retains output and reports pending.
			kc.mu.Lock()
			kc.discoveryStatus = 503
			kc.mu.Unlock()
			if _, err := ar.Reconcile(ctx, req); err == nil {
				t.Fatal("metadata failure not surfaced")
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(&cm), &cm); err != nil {
				t.Fatal(err)
			}
			if cm.Annotations[applicationbinding.RevisionAnnotation] != actual.Status.RuntimeBindings[0].BindingRevision {
				t.Fatal("unavailable provider erased outputs")
			}
			if condition(getApp(t, kube, app.Name), "RuntimeBindings").Status != metav1.ConditionFalse {
				t.Fatal("provider failure left runtime Ready")
			}
		})
	}
}

func TestRuntimeApplicationDeletionRequiresCurrentConsent(t *testing.T) {
	ctx := context.Background()
	kc := newMockKeycloak(t)
	b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}, Credentials: &api.ApplicationRuntimeCredentialTarget{SecretRef: "identity"}}
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "delete-runtime", UID: "application-uid", Generation: 1}, Spec: api.HankoApplicationSpec{RealmRef: "myrealm", ClientID: "delete-runtime", Type: "m2m", RuntimeBindings: []api.ApplicationRuntimeBinding{b}}}
	kube := runtimeKube(newFakeClient(t, append([]client.Object{app}, runtimeTargets(app, b)...)...))
	ar := newReconciler(t, kube, kc.client())
	ar.RuntimeClient = kube
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}
	if _, err := ar.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var target corev1.Secret
	if err := kube.Get(ctx, client.ObjectKey{Namespace: "payments", Name: "identity"}, &target); err != nil {
		t.Fatal(err)
	}
	delete(target.Annotations, applicationbinding.ApplicationUID)
	if err := kube.Update(ctx, &target); err != nil {
		t.Fatal(err)
	}
	app = getApp(t, kube, app.Name)
	if err := kube.Delete(ctx, app); err != nil {
		t.Fatal(err)
	}
	before := providerWrites(kc)
	if _, err := ar.Reconcile(ctx, req); applicationbinding.Reason(err) != "CleanupConflict" {
		t.Fatal("revoked deletion consent accepted")
	}
	if !maps.Equal(before, providerWrites(kc)) {
		t.Fatal("provider deleted before runtime cleanup")
	}
	current := getApp(t, kube, app.Name)
	if len(current.Finalizers) == 0 {
		t.Fatal("cleanup conflict released finalizer")
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(&target), &target); err != nil {
		t.Fatal(err)
	}
	if len(target.Data["client_secret"]) == 0 {
		t.Fatal("revoked credential was cleared")
	}
	target.Annotations[applicationbinding.ApplicationUID] = string(app.UID)
	if err := kube.Update(ctx, &target); err != nil {
		t.Fatal(err)
	}
	if _, err := ar.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(&target), &target); err != nil {
		t.Fatal("target deleted")
	}
	if len(target.Data["client_secret"]) > 0 || string(target.Data["owner"]) != "preserved" {
		t.Fatal("finalizer cleanup did not preserve foreign fields")
	}
}
func TestObserveCannotAcquireRuntimeCleanupAuthority(t *testing.T) {
	kc := newMockKeycloak(t)
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "observe-journal", Namespace: "default", Annotations: map[string]string{applicationbinding.JournalAnnotation: "[]"}}, Spec: api.HankoApplicationSpec{RealmRef: "myrealm", ClientID: "observe-journal", Mode: "Observe", Type: "spa"}}
	kube := newFakeClient(t, app)
	ar := newReconciler(t, kube, kc.client())
	if _, err := ar.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); applicationbinding.Reason(err) != "CleanupConflict" {
		t.Fatal("Observe silently adopted retained output lifecycle")
	}
	if kc.count("discovery") != 0 || kc.count("getSecret") != 0 || kc.count("create") != 0 {
		t.Fatal("Observe journal conflict interacted with provider")
	}
}
