//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkWorkloadTrustAdmission(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	makeTrust := func(name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoWorkloadTrust", "metadata": map[string]any{"name": name, "namespace": "auth"}, "spec": map[string]any{"realmRef": "existing", "sourceRef": "observer", "writerRef": "writer", "dependentReaderRef": "dependent-reader", "keycloakAlias": "cluster", "provider": "Kubernetes", "kubernetes": map[string]any{"issuer": "https://current.example.test", "clusterAnchor": map[string]any{"kubeSystemNamespaceUID": "approved-uid", "apiServerCAHash": "sha256:" + strings.Repeat("a", 64)}}}}}
	}
	for _, bad := range []struct {
		name  string
		path  []string
		value any
	}{{"age-low", []string{"kubernetes", "assertionMaxAgeSeconds"}, int64(599)}, {"age-high", []string{"kubernetes", "assertionMaxAgeSeconds"}, int64(3601)}, {"http", []string{"kubernetes", "issuer"}, "http://unsafe.test"}, {"userinfo", []string{"kubernetes", "issuer"}, "https://user@unsafe.test"}, {"query", []string{"kubernetes", "issuer"}, "https://unsafe.test?credential=excluded"}, {"uid", []string{"kubernetes", "clusterAnchor", "kubeSystemNamespaceUID"}, ""}, {"ca", []string{"kubernetes", "clusterAnchor", "apiServerCAHash"}, "sha256:short"}, {"provider", []string{"provider"}, "oidc"}, {"mode", []string{"mode"}, "Adopt"}, {"realm", []string{"realmRef"}, "other/realm"}, {"alias", []string{"keycloakAlias"}, "unsafe/alias"}, {"reader", []string{"dependentReaderRef"}, ""}, {"version", []string{"qualifiedKeycloakVersion"}, "27.0.0"}, {"unqualified-override", []string{"kubernetes", "discoveryURL"}, "https://override.test"}} {
		obj := makeTrust("trust-bad-" + bad.name)
		path := append([]string{"spec"}, bad.path...)
		if err := unstructured.SetNestedField(obj.Object, bad.value, path...); err != nil {
			t.Fatal(err)
		}
		if err := kube.Create(ctx, obj); !apierrors.IsInvalid(err) {
			t.Fatalf("invalid trust %s admitted: %v", bad.name, err)
		}
	}
	obj := makeTrust("trust-qualified")
	if err := kube.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	mode, _, _ := unstructured.NestedString(obj.Object, "spec", "mode")
	age, _, _ := unstructured.NestedInt64(obj.Object, "spec", "kubernetes", "assertionMaxAgeSeconds")
	if mode != "Manage" || age != 600 {
		t.Fatal("trust defaults differ")
	}
	// Real admission must agree with runtime eligibility, including future patches
	// and minors. Version eligibility alone must not admit an older override.
	for index, tc := range []struct {
		version          string
		override, accept bool
	}{
		{"26.7.5", false, true}, {"26.7.6", false, true},
		{"26.8.0", true, true}, {"26.8.1", true, true},
		{"26.8.2", true, true}, {"26.10.0", true, true},
		{"26.7.5", true, false}, {"26.7.10", true, false},
		{"26.7.4", false, false}, {"26.0.0", false, false},
		{"27.0.0", true, false}, {"26.8.2-rc.1", false, false},
		{"26.08.1", false, false}, {"26.8.01", false, false},
		{"26.8", false, false}, {"", false, false},
	} {
		candidate := makeTrust(fmt.Sprintf("trust-version-%d", index))
		_ = unstructured.SetNestedField(candidate.Object, tc.version, "spec", "qualifiedKeycloakVersion")
		if tc.override {
			_ = unstructured.SetNestedField(candidate.Object, "https://override.test", "spec", "kubernetes", "discoveryURL")
		}
		err := kube.Create(ctx, candidate)
		if tc.accept && err != nil || !tc.accept && !apierrors.IsInvalid(err) {
			t.Fatalf("version %q override=%t accept=%t: %v", tc.version, tc.override, tc.accept, err)
		}
	}
	for _, field := range []string{"realmRef", "sourceRef", "keycloakAlias"} {
		copy := obj.DeepCopy()
		_ = unstructured.SetNestedField(copy.Object, "replacement", "spec", field)
		if err := kube.Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Fatalf("retargeting %s admitted", field)
		}
	}
	var typed api.HankoWorkloadTrust
	if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), &typed); err != nil {
		t.Fatal(err)
	}
	before := typed.Spec
	patch := client.MergeFrom(typed.DeepCopy())
	typed.Status.Phase = "Ready"
	typed.Status.ObservedGeneration = typed.Generation
	typed.Status.ProviderID = "native-uuid"
	typed.Status.Capabilities = &api.WorkloadTrustCapabilities{KubernetesWorkloadIdentity: true}
	typed.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Qualified", Message: "configuration only", ObservedGeneration: typed.Generation, LastTransitionTime: metav1.Now()}}
	if err := kube.Status().Patch(ctx, &typed, patch); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Spec != before || typed.Status.ProviderID != "native-uuid" || typed.Status.Capabilities == nil || typed.Status.Capabilities.SecretFallback || typed.Status.Capabilities.IssuerDiscoveryOverride {
		t.Fatal("trust status subresource did not preserve configuration-only evidence")
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"secretFallback", "issuerDiscoveryOverride"} {
		value, found, err := unstructured.NestedBool(obj.Object, "status", "capabilities", field)
		if err != nil || !found || value {
			t.Fatalf("false capability %s was not persisted explicitly", field)
		}
	}
}
