package decommission

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

const (
	testNamespace  = "auth"
	testRelease    = "hanko-operator"
	testTenant     = "hanko-tenant"
	testCredential = "hanko-hub-token"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sch := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	if err := hankoshv1alpha1.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	monitorGVK := schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}
	sch.AddKnownTypeWithName(monitorGVK, &unstructured.Unstructured{})
	sch.AddKnownTypeWithName(monitorGVK.GroupVersion().WithKind("ServiceMonitorList"), &unstructured.UnstructuredList{})
	ciliumGVK := schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}
	sch.AddKnownTypeWithName(ciliumGVK, &unstructured.Unstructured{})
	sch.AddKnownTypeWithName(ciliumGVK.GroupVersion().WithKind("CiliumNetworkPolicyList"), &unstructured.UnstructuredList{})
	return sch
}

func TestOptionalCiliumRemovalIsPinnedToRelease(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			ctx := context.Background()
			policy := &unstructured.Unstructured{}
			policy.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"})
			policy.SetNamespace(testNamespace)
			policy.SetName(testRelease)
			other := policy.DeepCopy()
			other.SetName("unrelated-policy")
			objects := append(releaseObjects(), policy, other)
			kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
			config := testConfig()
			config.CiliumPolicy = enabled
			engine := &Engine{Writer: kube, Reader: kube, Config: config}
			removed, err := engine.removeClusterSurface(ctx)
			if err != nil {
				t.Fatal(err)
			}
			err = kube.Get(ctx, client.ObjectKeyFromObject(policy), policy)
			if enabled && (!apierrors.IsNotFound(err) || removed["ciliumNetworkPolicies"] != 1) {
				t.Fatalf("enabled CNP must be removed and counted: removed=%v err=%v", removed, err)
			}
			if !enabled && (err != nil || removed["ciliumNetworkPolicies"] != 0) {
				t.Fatalf("disabled profile must never access CNP: removed=%v err=%v", removed, err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(other), other); err != nil {
				t.Fatalf("unrelated CNP must be retained: %v", err)
			}
		})
	}
}

func releaseObjects() []client.Object {
	monitor := &unstructured.Unstructured{}
	monitor.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"})
	monitor.SetNamespace(testNamespace)
	monitor.SetName(testRelease)
	return []client.Object{
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease + "-metrics"}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease + "-theme-jobs"}},
		monitor,
		&hankoshv1alpha1.HankoTenant{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testTenant}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "hanko-hub-tls"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "hanko-hub-enroll"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testCredential}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease, UID: "deployment-uid"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: testRelease + "-cluster-identity-reader", UID: "anchor-uid"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: testRelease + "-node-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: testRelease + "-cluster-identity-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: testRelease + "-node-reader"}},
	}
}

func testConfig() Config {
	return Config{
		Namespace:            testNamespace,
		ReleaseName:          testRelease,
		TenantName:           testTenant,
		CASecretNames:        []string{"hanko-hub-tls", "hanko-hub-enroll", "", testCredential},
		CredentialSecretName: testCredential,
	}
}

type cancelAfterDelete struct {
	client.Writer
	cancel  context.CancelFunc
	deletes int
}

func (w *cancelAfterDelete) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	err := w.Writer.Delete(ctx, object, options...)
	w.deletes++
	w.cancel()
	return err
}

func TestDeadlineStopsCleanupBeforeConfirmation(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "expired before cleanup", false: "cancelled during cleanup"}[expired], func(t *testing.T) {
			kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(releaseObjects()...).Build()
			var ctx context.Context
			var cancel context.CancelFunc
			if expired {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			writer := &cancelAfterDelete{Writer: kube, cancel: cancel}
			confirmed := false
			engine := &Engine{Writer: writer, Reader: kube, Config: testConfig(), Confirm: func(context.Context, map[string]int) error { confirmed = true; return nil }}
			if _, err := engine.Run(ctx); err == nil {
				t.Fatal("expired execution succeeded")
			}
			if confirmed {
				t.Fatal("expired command was confirmed")
			}
			wantDeletes := 1
			if expired {
				wantDeletes = 0
			}
			if writer.deletes != wantDeletes {
				t.Fatalf("cleanup continued after expiry: %d deletes", writer.deletes)
			}
			var deployment appsv1.Deployment
			if err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); err != nil {
				t.Fatalf("expired command deleted operator: %v", err)
			}
		})
	}
}

func TestExpiryAfterConfirmationReportsResidueWithoutFurtherDeletion(t *testing.T) {
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(releaseObjects()...).Build()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &Engine{Writer: kube, Reader: kube, Config: testConfig(), Confirm: func(context.Context, map[string]int) error { cancel(); return nil }}
	if _, err := engine.Run(ctx); !errors.Is(err, ErrAfterConfirmation) || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-confirmation residue not reported: %v", err)
	}
	var deployment appsv1.Deployment
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); err != nil {
		t.Fatalf("expired execution deleted operator: %v", err)
	}
}

func TestEngineRunRemovesReleaseAndRetainsCredential(t *testing.T) {
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(releaseObjects()...).Build()
	var confirmed map[string]int
	engine := &Engine{
		Writer: kube,
		Reader: kube,
		Config: testConfig(),
		Confirm: func(ctx context.Context, removedResources map[string]int) error {
			confirmed = removedResources
			// The confirmation must happen before self-deletion: the Deployment
			// and the HankoTenant (heartbeat channel) must still be standing so
			// a failed confirmation can be retried on the next re-delivery.
			var deployment appsv1.Deployment
			if err := kube.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); err != nil {
				t.Errorf("deployment already gone at confirmation time: %v", err)
			}
			var tenant hankoshv1alpha1.HankoTenant
			if err := kube.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testTenant}, &tenant); err != nil {
				t.Errorf("hanko tenant already gone at confirmation time: %v", err)
			}
			return nil
		},
	}

	removed, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want := map[string]int{"services": 1, "networkPolicies": 2, "serviceMonitors": 1, "hankoTenants": 1, "secrets": 2}
	for kind, count := range want {
		if removed[kind] != count {
			t.Fatalf("removed[%s] = %d, want %d (full inventory %v)", kind, removed[kind], count, removed)
		}
	}
	if confirmed == nil {
		t.Fatal("inventory was never confirmed to hub")
	}
	if confirmed["hankoTenants"] != 0 {
		t.Fatalf("tenant must be removed only after confirmation, confirmed inventory %v", confirmed)
	}

	ctx := context.Background()
	var credential corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testCredential}, &credential); err != nil {
		t.Fatalf("hub credential secret must be retained: %v", err)
	}
	var deployment appsv1.Deployment
	if err := kube.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); !apierrors.IsNotFound(err) {
		t.Fatalf("operator deployment must be deleted, got %v", err)
	}
	var anchor rbacv1.ClusterRole
	if err := kube.Get(ctx, types.NamespacedName{Name: testRelease + "-cluster-identity-reader"}, &anchor); !apierrors.IsNotFound(err) {
		t.Fatalf("anchor cluster role must be deleted, got %v", err)
	}

	// The fake client has no garbage collector, so cascaded children survive
	// here; assert the adoption that a real GC acts on.
	var role rbacv1.Role
	if err := kube.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &role); err != nil {
		t.Fatal(err)
	}
	assertOwner(t, role.OwnerReferences, "Deployment", testRelease, "deployment-uid")
	var nodeReader rbacv1.ClusterRole
	if err := kube.Get(ctx, types.NamespacedName{Name: testRelease + "-node-reader"}, &nodeReader); err != nil {
		t.Fatal(err)
	}
	assertOwner(t, nodeReader.OwnerReferences, "ClusterRole", testRelease+"-cluster-identity-reader", "anchor-uid")
}

func assertOwner(t *testing.T, refs []metav1.OwnerReference, kind, name string, uid types.UID) {
	t.Helper()
	if len(refs) != 1 || refs[0].Kind != kind || refs[0].Name != name || refs[0].UID != uid {
		t.Fatalf("owner references = %v, want single %s %q with UID %q", refs, kind, name, uid)
	}
}

func TestEngineRunContinuesAfterRevokedCredentialConfirmation(t *testing.T) {
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(releaseObjects()...).Build()
	engine := &Engine{
		Writer: kube, Reader: kube, Config: testConfig(),
		Confirm: func(context.Context, map[string]int) error { return hub.ErrDecommissionUnauthorized },
	}
	if _, err := engine.Run(context.Background()); err != nil {
		t.Fatalf("revoked credential must not abort local teardown: %v", err)
	}
	var deployment appsv1.Deployment
	err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("operator deployment must be deleted, got %v", err)
	}
}

func TestEngineRunAbortsBeforeSelfRemovalWhenConfirmationFails(t *testing.T) {
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(releaseObjects()...).Build()
	engine := &Engine{
		Writer: kube, Reader: kube, Config: testConfig(),
		Confirm: func(context.Context, map[string]int) error { return errors.New("hub unreachable") },
	}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("failed confirmation must abort the run")
	}
	var deployment appsv1.Deployment
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); err != nil {
		t.Fatalf("operator deployment must survive an unconfirmed run: %v", err)
	}
	var role rbacv1.Role
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &role); err != nil {
		t.Fatal(err)
	}
	if len(role.OwnerReferences) != 0 {
		t.Fatal("RBAC must not be adopted before hub confirmation")
	}
	var tenant hankoshv1alpha1.HankoTenant
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testTenant}, &tenant); err != nil {
		t.Fatalf("hanko tenant must survive an unconfirmed run to keep the heartbeat alive: %v", err)
	}
}

func TestEngineRunResumesAfterPartialRemoval(t *testing.T) {
	// A resumed run: cluster surface and cluster-scoped RBAC already gone.
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testCredential}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease, UID: "deployment-uid"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRelease}},
	).Build()
	engine := &Engine{
		Writer: kube, Reader: kube, Config: testConfig(),
		Confirm: func(context.Context, map[string]int) error { return hub.ErrDecommissionUnauthorized },
	}
	removed, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("nothing new should be inventoried on resume, got %v", removed)
	}
	var deployment appsv1.Deployment
	err = kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("operator deployment must be deleted on resume, got %v", err)
	}
}

const (
	testTransportNamespace = "continuum-hanko-canary"
	testTransportRelease   = "continuum-hanko-canary-node"
)

func transportConfig() Config {
	config := testConfig()
	config.Transport = &TransportConfig{
		Namespace:   testTransportNamespace,
		ReleaseName: testTransportRelease,
		SecretNames: []string{"hanko-mesh-policy-verifier"},
	}
	config.MeshProjection = &MeshProjectionConfig{
		Namespace:     testTransportNamespace,
		ConfigMapName: "hanko-mesh-policy",
		WriterName:    testRelease + "-mesh-policy",
	}
	return config
}

func transportObjects() []client.Object {
	return []client.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testTransportRelease + "-continuum-vpn"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: testTransportNamespace, Name: "sh.helm.release.v1." + testTransportRelease + ".v1",
			Labels: map[string]string{"owner": "helm", "name": testTransportRelease},
		}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "hanko-mesh-policy-verifier"}},
		// A foreign Secret in the transport namespace must never be touched.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "unrelated"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "hanko-mesh-policy"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testRelease + "-mesh-policy"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testRelease + "-mesh-policy"}},
	}
}

func TestEngineRunTearsDownTransportAfterConfirmation(t *testing.T) {
	objects := append(releaseObjects(), transportObjects()...)
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
	var confirmed map[string]int
	engine := &Engine{
		Writer: kube, Reader: kube, Config: transportConfig(),
		Confirm: func(ctx context.Context, removedResources map[string]int) error {
			confirmed = removedResources
			// The confirmation is the last message over the still-alive link:
			// the transport DaemonSet must still be standing here.
			var daemonSet appsv1.DaemonSet
			if err := kube.Get(ctx, types.NamespacedName{Namespace: testTransportNamespace, Name: testTransportRelease + "-continuum-vpn"}, &daemonSet); err != nil {
				t.Errorf("transport daemonset already gone at confirmation time: %v", err)
			}
			return nil
		},
	}
	removed, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Surface secrets (2) + verifier + helm bookkeeping = 4.
	want := map[string]int{"daemonSets": 1, "configMaps": 1, "roles": 1, "roleBindings": 1, "secrets": 4}
	for kind, count := range want {
		if removed[kind] != count {
			t.Fatalf("removed[%s] = %d, want %d (full inventory %v)", kind, removed[kind], count, removed)
		}
	}
	if confirmed["daemonSets"] != 1 || confirmed["configMaps"] != 1 {
		t.Fatalf("hub receipt must cover the planned transport teardown, confirmed inventory %v", confirmed)
	}
	ctx := context.Background()
	for _, gone := range []client.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testTransportRelease + "-continuum-vpn"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "hanko-mesh-policy"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "hanko-mesh-policy-verifier"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: "sh.helm.release.v1." + testTransportRelease + ".v1"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testRelease + "-mesh-policy"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: testTransportNamespace, Name: testRelease + "-mesh-policy"}},
	} {
		if err := kube.Get(ctx, client.ObjectKeyFromObject(gone), gone); !apierrors.IsNotFound(err) {
			t.Fatalf("%T %q must be deleted after confirmation, got %v", gone, gone.GetName(), err)
		}
	}
	var foreign corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: testTransportNamespace, Name: "unrelated"}, &foreign); err != nil {
		t.Fatalf("foreign secret in the transport namespace must be retained: %v", err)
	}
}

type daemonSetDeleteFailer struct {
	client.Client
}

func (f daemonSetDeleteFailer) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, isDaemonSet := object.(*appsv1.DaemonSet); isDaemonSet {
		return errors.New("simulated api failure")
	}
	return f.Client.Delete(ctx, object, options...)
}

func TestEngineRunWrapsPostConfirmationFailures(t *testing.T) {
	objects := append(releaseObjects(), transportObjects()...)
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
	engine := &Engine{
		Writer: daemonSetDeleteFailer{kube}, Reader: kube, Config: transportConfig(),
		Confirm: func(context.Context, map[string]int) error { return nil },
	}
	_, err := engine.Run(context.Background())
	if !errors.Is(err, ErrAfterConfirmation) {
		t.Fatalf("post-confirmation failure must wrap ErrAfterConfirmation, got %v", err)
	}
	// The remaining teardown is still attempted: the credential is already
	// surrendered, so aborting would only strand a dead operator.
	var deployment appsv1.Deployment
	if getErr := kube.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRelease}, &deployment); !apierrors.IsNotFound(getErr) {
		t.Fatalf("operator deployment must still be deleted, got %v", getErr)
	}
}

func TestConfigValidate(t *testing.T) {
	for name, config := range map[string]Config{
		"empty namespace": {ReleaseName: testRelease, TenantName: testTenant},
		"empty release":   {Namespace: testNamespace, TenantName: testTenant},
		"empty tenant":    {Namespace: testNamespace, ReleaseName: testRelease},
		"transport without namespace": {Namespace: testNamespace, ReleaseName: testRelease, TenantName: testTenant,
			Transport: &TransportConfig{ReleaseName: testTransportRelease}},
		"transport without release": {Namespace: testNamespace, ReleaseName: testRelease, TenantName: testTenant,
			Transport: &TransportConfig{Namespace: testTransportNamespace}},
		"projection without writer": {Namespace: testNamespace, ReleaseName: testRelease, TenantName: testTenant,
			MeshProjection: &MeshProjectionConfig{Namespace: testTransportNamespace, ConfigMapName: "hanko-mesh-policy"}},
	} {
		if config.Validate() == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if err := testConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := transportConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Config: Config{}}
	if _, err := engine.Run(context.Background()); err == nil {
		t.Fatal("run with invalid config must fail before any deletion")
	}
}
