package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/decommission"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

const decommissionTestRelease = "hanko-operator"

func decommissionTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := controllerTestScheme(t)
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func decommissionTestTenant(transport string) *hankoshv1alpha1.HankoTenant {
	return &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-tenant", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoTenantSpec{
			HubEndpoint: "https://hub.invalid", HubTransport: transport, IsolationMode: "realm",
			HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub-token"},
		},
	}
}

func decommissionReleaseObjects(tenant *hankoshv1alpha1.HankoTenant) []client.Object {
	namespace := tenant.Namespace
	return []client.Object{
		tenant,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "hub-token"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "hanko-hub-tls"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: decommissionTestRelease, UID: "deployment-uid"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: decommissionTestRelease}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: decommissionTestRelease}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: decommissionTestRelease}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: decommissionTestRelease + "-cluster-identity-reader", UID: "anchor-uid"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: decommissionTestRelease + "-node-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: decommissionTestRelease + "-cluster-identity-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: decommissionTestRelease + "-node-reader"}},
	}
}

func decommissionCommand() *hub.DecommissionCommand {
	now := time.Now()
	return &hub.DecommissionCommand{RequestedAt: now, Deadline: now.Add(time.Hour)}
}

type commandDeadlineReader struct {
	client.Reader
	t        *testing.T
	deadline time.Time
	reads    int
}

func (r *commandDeadlineReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	r.reads++
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(r.deadline) {
		r.t.Errorf("command deadline was not propagated: %v (%t)", deadline, ok)
	}
	return r.Reader.Get(ctx, key, object, options...)
}

func TestExecuteDecommissionRejectsExpiredAndMalformedCommands(t *testing.T) {
	now := time.Now()
	cases := map[string]*hub.DecommissionCommand{
		"nil":              nil,
		"missing deadline": {RequestedAt: now.Add(-time.Hour)},
		"missing request":  {Deadline: now.Add(time.Hour)},
		"future request":   {RequestedAt: now.Add(time.Hour), Deadline: now.Add(2 * time.Hour)},
		"reversed window":  {RequestedAt: now.Add(-time.Hour), Deadline: now.Add(-2 * time.Hour)},
		"expired":          {RequestedAt: now.Add(-2 * time.Hour), Deadline: now.Add(-time.Hour)},
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			tenant := decommissionTestTenant("")
			kube := controllerTestClient(decommissionTestScheme(t), decommissionReleaseObjects(tenant)...)
			r := &HankoTenantReconciler{Client: kube, ClusterIdentityReader: kube, Decommission: &decommission.Config{ReleaseName: decommissionTestRelease}}
			result, err := r.executeDecommission(context.Background(), tenant, client.MergeFrom(tenant.DeepCopy()), nil, command)
			reason := "DecommissionInvalid"
			if name == "expired" {
				reason = "DecommissionExpired"
			}
			assertDecommissionRefused(t, r, kube, tenant, result, err, reason)
			for _, object := range decommissionReleaseObjects(tenant)[1:] {
				if err := kube.Get(context.Background(), client.ObjectKeyFromObject(object), object); err != nil {
					t.Fatalf("refusal removed %T: %v", object, err)
				}
			}
		})
	}
}

func TestExecuteDecommissionRunsEngineAndConfirms(t *testing.T) {
	confirmed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/operators/decommission/confirm" {
			confirmed = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	tenant := decommissionTestTenant("")
	kube := controllerTestClient(decommissionTestScheme(t), decommissionReleaseObjects(tenant)...)
	command := decommissionCommand()
	reader := &commandDeadlineReader{Reader: kube, t: t, deadline: command.Deadline}
	reconciler := &HankoTenantReconciler{
		Client: kube, ClusterIdentityReader: reader,
		Decommission: &decommission.Config{ReleaseName: decommissionTestRelease, CASecretNames: []string{"hanko-hub-tls"}},
	}
	patch := client.MergeFrom(tenant.DeepCopy())
	result, err := reconciler.executeDecommission(context.Background(), tenant, patch, hub.New(server.URL, "tenant-1", "token"), command)
	if err != nil {
		t.Fatalf("execute decommission: %v", err)
	}
	if result != (ctrl.Result{}) {
		t.Fatalf("decommission must not requeue, got %+v", result)
	}
	if !confirmed {
		t.Fatal("inventory was not confirmed to hub")
	}
	if reader.reads == 0 {
		t.Fatal("bounded execution context was not observed")
	}
	ctx := context.Background()
	var deployment appsv1.Deployment
	if getErr := kube.Get(ctx, types.NamespacedName{Namespace: "test", Name: decommissionTestRelease}, &deployment); !apierrors.IsNotFound(getErr) {
		t.Fatalf("operator deployment must be deleted, got %v", getErr)
	}
	var credential corev1.Secret
	if getErr := kube.Get(ctx, types.NamespacedName{Namespace: "test", Name: "hub-token"}, &credential); getErr != nil {
		t.Fatalf("hub credential secret must be retained: %v", getErr)
	}
}

// assertDecommissionRefused checks the #369 contract: a refusal produces a
// bounded requeue with no simultaneous error, records the reason on the tenant
// condition, and remembers the degraded detail for stable heartbeat reporting.
func assertDecommissionRefused(t *testing.T, reconciler *HankoTenantReconciler, kube client.Client, tenant *hankoshv1alpha1.HankoTenant, result ctrl.Result, err error, wantReason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("refusals must not return an error (bounded requeue only), got %v", err)
	}
	if result.RequeueAfter != requeueOnError {
		t.Fatalf("refusal must requeue after %s, got %+v", requeueOnError, result)
	}
	assertTenantIdentityError(t, kube, tenant, wantReason)
	if reason, degraded := reconciler.degradedReason(tenant); !degraded || reason != wantReason {
		t.Fatalf("degraded detail = %q (%t), want %q remembered for stable heartbeats", reason, degraded, wantReason)
	}
	var deployment appsv1.Deployment
	if getErr := kube.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: decommissionTestRelease}, &deployment); getErr != nil {
		t.Fatalf("refused decommission must not delete anything: %v", getErr)
	}
}

func TestExecuteDecommissionRefusalsKeepCommandPendingOnHub(t *testing.T) {
	tests := map[string]struct {
		transport  string
		configure  func(*HankoTenantReconciler)
		wantReason string
	}{
		"not configured": {
			configure:  func(r *HankoTenantReconciler) { r.Decommission = nil },
			wantReason: "DecommissionUnsupported",
		},
		"continuum transport without teardown config": {
			transport:  "continuum",
			configure:  func(*HankoTenantReconciler) {},
			wantReason: "DecommissionBlocked",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tenant := decommissionTestTenant(test.transport)
			kube := controllerTestClient(decommissionTestScheme(t), decommissionReleaseObjects(tenant)...)
			reconciler := &HankoTenantReconciler{
				Client: kube, ClusterIdentityReader: kube,
				Decommission: &decommission.Config{ReleaseName: decommissionTestRelease},
			}
			test.configure(reconciler)
			patch := client.MergeFrom(tenant.DeepCopy())
			result, err := reconciler.executeDecommission(context.Background(), tenant, patch, nil, decommissionCommand())
			assertDecommissionRefused(t, reconciler, kube, tenant, result, err, test.wantReason)
		})
	}
}

func TestExecuteDecommissionTearsDownContinuumTransport(t *testing.T) {
	confirmed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/operators/decommission/confirm" {
			confirmed = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	tenant := decommissionTestTenant("continuum")
	transportNamespace := "continuum-hanko-canary"
	objects := append(decommissionReleaseObjects(tenant),
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: "continuum-node-continuum-vpn"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: transportNamespace, Name: "sh.helm.release.v1.continuum-node.v1",
			Labels: map[string]string{"owner": "helm", "name": "continuum-node"},
		}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: "hanko-mesh-policy"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: decommissionTestRelease + "-mesh-policy"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: decommissionTestRelease + "-mesh-policy"}},
	)
	kube := controllerTestClient(decommissionTestScheme(t), objects...)
	reconciler := &HankoTenantReconciler{
		Client: kube, ClusterIdentityReader: kube,
		MeshPolicyConfigMapName:      "hanko-mesh-policy",
		MeshPolicyConfigMapNamespace: transportNamespace,
		MeshPolicyProjectionClient:   kube,
		Decommission: &decommission.Config{
			ReleaseName: decommissionTestRelease,
			Transport:   &decommission.TransportConfig{Namespace: transportNamespace, ReleaseName: "continuum-node"},
		},
	}
	patch := client.MergeFrom(tenant.DeepCopy())
	result, err := reconciler.executeDecommission(context.Background(), tenant, patch, hub.New(server.URL, "tenant-1", "token"), decommissionCommand())
	if err != nil {
		t.Fatalf("execute decommission: %v", err)
	}
	if result != (ctrl.Result{}) {
		t.Fatalf("decommission must not requeue, got %+v", result)
	}
	if !confirmed {
		t.Fatal("inventory was not confirmed to hub")
	}
	ctx := context.Background()
	for _, gone := range []client.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: "continuum-node-continuum-vpn"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: "sh.helm.release.v1.continuum-node.v1"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: "hanko-mesh-policy"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: transportNamespace, Name: decommissionTestRelease + "-mesh-policy"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: decommissionTestRelease}},
	} {
		if getErr := kube.Get(ctx, client.ObjectKeyFromObject(gone), gone); !apierrors.IsNotFound(getErr) {
			t.Fatalf("%T %q must be deleted, got %v", gone, gone.GetName(), getErr)
		}
	}
	var credential corev1.Secret
	if getErr := kube.Get(ctx, types.NamespacedName{Namespace: "test", Name: "hub-token"}, &credential); getErr != nil {
		t.Fatalf("hub credential secret must be retained: %v", getErr)
	}
}

func TestExecuteDecommissionReportsEngineFailureForRedelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	tenant := decommissionTestTenant("")
	kube := controllerTestClient(decommissionTestScheme(t), decommissionReleaseObjects(tenant)...)
	reconciler := &HankoTenantReconciler{
		Client: kube, ClusterIdentityReader: kube,
		Decommission: &decommission.Config{ReleaseName: decommissionTestRelease},
	}
	patch := client.MergeFrom(tenant.DeepCopy())
	result, err := reconciler.executeDecommission(context.Background(), tenant, patch, hub.New(server.URL, "tenant-1", "token"), decommissionCommand())
	assertDecommissionRefused(t, reconciler, kube, tenant, result, err, "DecommissionFailed")
}
