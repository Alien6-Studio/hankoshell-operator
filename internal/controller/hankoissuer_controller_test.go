package controller_test

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
)

func TestHankoIssuerReconcilesExactAPIHostAllowlist(t *testing.T) {
	const namespace = "auth"
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: namespace},
	}
	hankoIssuer := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko", Namespace: namespace},
		Spec: hankoshv1alpha1.HankoIssuerSpec{
			Host: "auth.hanko.sh", RealmRef: realm.Name,
		},
	}
	trunxIssuer := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "trunx", Namespace: namespace},
		Spec: hankoshv1alpha1.HankoIssuerSpec{
			Host: "auth.trunx.io", RealmRef: realm.Name,
		},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-api", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "hanko-api"}},
		}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(realm, hankoIssuer, trunxIssuer, deployment).
		WithStatusSubresource(&hankoshv1alpha1.HankoIssuer{}).
		Build()
	r := &controller.HankoIssuerReconciler{Client: c}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: trunxIssuer.Name, Namespace: namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := deploymentEnv(t, c, namespace, "HANKO_PUBLIC_ISSUERS"); got != "auth.hanko.sh=alien6,auth.trunx.io=alien6" {
		t.Fatalf("issuer allowlist = %q", got)
	}
	var reconciled hankoshv1alpha1.HankoIssuer
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatal(err)
	}
	if reconciled.Status.Phase != "Ready" || reconciled.Status.ConfiguredHost != "auth.trunx.io" {
		t.Fatalf("issuer status = %+v", reconciled.Status)
	}

	if err := c.Delete(context.Background(), trunxIssuer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile deletion: %v", err)
	}
	if got := deploymentEnv(t, c, namespace, "HANKO_PUBLIC_ISSUERS"); got != "auth.hanko.sh=alien6" {
		t.Fatalf("issuer allowlist after deletion = %q", got)
	}
}

func TestHankoIssuerRejectsWildcardAndExcludesItFromDeployment(t *testing.T) {
	const namespace = "auth"
	realm := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: namespace}}
	issuer := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "wildcard", Namespace: namespace},
		Spec:       hankoshv1alpha1.HankoIssuerSpec{Host: "*.example.com", RealmRef: realm.Name},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-api", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "hanko-api"}},
		}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(realm, issuer, deployment).
		WithStatusSubresource(&hankoshv1alpha1.HankoIssuer{}).
		Build()
	r := &controller.HankoIssuerReconciler{Client: c}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: issuer.Name, Namespace: namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var reconciled hankoshv1alpha1.HankoIssuer
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatal(err)
	}
	if reconciled.Status.Phase != "Error" {
		t.Fatalf("issuer status = %+v", reconciled.Status)
	}
	if got := deploymentEnv(t, c, namespace, "HANKO_PUBLIC_ISSUERS"); got != "" {
		t.Fatalf("invalid host entered allowlist: %q", got)
	}
}

// TestSecurityHankoIssuerPreservesRealmBinding prevents the operator from
// flattening a host-to-realm declaration into a namespace-wide host allowlist.
// Without this binding, a host declared for one realm can be used to publish
// discovery metadata and tokens for every other realm exposed by the proxy.
func TestSecurityHankoIssuerPreservesRealmBinding(t *testing.T) {
	const namespace = "auth"
	alien6 := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: namespace}}
	other := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: namespace}}
	trunx := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "trunx", Namespace: namespace},
		Spec:       hankoshv1alpha1.HankoIssuerSpec{Host: "auth.trunx.io", RealmRef: alien6.Name},
	}
	otherIssuer := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: namespace},
		Spec:       hankoshv1alpha1.HankoIssuerSpec{Host: "auth.other.example", RealmRef: other.Name},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-api", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "hanko-api"}},
		}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(alien6, other, trunx, otherIssuer, deployment).
		WithStatusSubresource(&hankoshv1alpha1.HankoIssuer{}).
		Build()
	r := &controller.HankoIssuerReconciler{Client: c}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: trunx.Name, Namespace: namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The effective policy must retain both sides of each declaration. A host-only
	// value would silently make every listed authority valid for every realm.
	if got := deploymentEnv(t, c, namespace, "HANKO_PUBLIC_ISSUERS"); got != "auth.other.example=other,auth.trunx.io=alien6" {
		t.Fatalf("issuer realm policy = %q; host-to-realm binding was lost", got)
	}
}

func deploymentEnv(t *testing.T, c client.Client, namespace, name string) string {
	t.Helper()
	var deployment appsv1.Deployment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "hanko-api", Namespace: namespace}, &deployment); err != nil {
		t.Fatal(err)
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "hanko-api" {
			continue
		}
		for _, env := range container.Env {
			if env.Name == name {
				return env.Value
			}
		}
	}
	return ""
}
