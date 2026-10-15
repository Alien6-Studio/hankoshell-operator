//go:build integration

package v1alpha1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func samePublicJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(x, y)
}

func checkPublicContractCorpus(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	corpus, err := iamconformance.ReadPublicCorpus("public-0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			var spec, expected, status map[string]any
			for _, value := range []struct {
				raw json.RawMessage
				out *map[string]any
			}{{fixture.Spec, &spec}, {fixture.DefaultedSpec, &expected}, {fixture.Status, &status}} {
				if err := json.Unmarshal(value.raw, value.out); err != nil {
					t.Fatal(err)
				}
			}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": fixture.Kind,
				"metadata": map[string]any{"name": "public-" + fixture.Name, "namespace": "auth"}, "spec": spec}}
			if err := kube.Create(ctx, obj, client.FieldOwner("public-corpus")); err != nil {
				t.Fatal(err)
			}
			uid := obj.GetUID()
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if !samePublicJSON(t, obj.Object["spec"], expected) {
				t.Fatalf("stored/defaulted object drift (-golden +actual):\n- %v\n+ %v", expected, obj.Object["spec"])
			}
			patch := client.MergeFrom(obj.DeepCopy())
			obj.SetAnnotations(map[string]string{"fixture.example/independent-owner": "preserve"})
			if err := kube.Patch(ctx, obj, patch); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				apply := &unstructured.Unstructured{Object: map[string]any{"apiVersion": obj.GetAPIVersion(), "kind": obj.GetKind(),
					"metadata": map[string]any{"name": obj.GetName(), "namespace": obj.GetNamespace()}, "spec": expected}}
				if err := kube.Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner("public-corpus")); err != nil {
					t.Fatal(err)
				}
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if obj.GetUID() != uid || obj.GetAnnotations()["fixture.example/independent-owner"] != "preserve" || !samePublicJSON(t, obj.Object["spec"], expected) {
				t.Fatal("idempotent SSA changed identity, foreign metadata or stored meaning")
			}
			obj.Object["status"] = status
			if err := kube.Status().Update(ctx, obj); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if !samePublicJSON(t, obj.Object["status"], status) {
				t.Fatalf("public status round-trip drift: %v != %v", obj.Object["status"], status)
			}
			// An older reader must reject a removed/new unknown stored field,
			// rather than silently pruning it during a supposed rollback.
			unknown := obj.DeepCopy()
			if err := unstructured.SetNestedField(unknown.Object, true, "spec", "removedPublicField"); err != nil {
				t.Fatal(err)
			}
			if err := kube.Update(ctx, unknown, client.DryRunAll, client.FieldValidation("Strict")); !apierrors.IsBadRequest(err) && !apierrors.IsInvalid(err) {
				t.Fatalf("unknown stored field was not explicitly rejected: %v", err)
			}
			// A second field manager cannot silently take a selected scalar.
			conflict := obj.DeepCopy()
			if err := unstructured.SetNestedField(conflict.Object, "Observe", "spec", "mode"); err != nil {
				t.Fatal(err)
			}
			conflict.SetManagedFields(nil)
			conflict.SetResourceVersion("")
			delete(conflict.Object, "status")
			if err := kube.Apply(ctx, client.ApplyConfigurationFromUnstructured(conflict), client.FieldOwner("unapproved-second-manager")); !apierrors.IsConflict(err) {
				t.Fatalf("selected field ownership was taken without an SSA conflict: %v", err)
			}
		})
	}
}
