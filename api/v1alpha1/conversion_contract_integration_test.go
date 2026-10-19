//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Exercise every served version through the real API server and its typed
// reader. This is structural alpha/beta conversion, not public release history.
func checkConversionContract(t *testing.T, ctx context.Context, kube client.Client, crds []*apiextensionsv1.CustomResourceDefinition) {
	specs := conditionAPISpecs()
	for _, crd := range crds {
		t.Run(crd.Spec.Names.Kind, func(t *testing.T) {
			if len(crd.Spec.Versions) > 2 || crd.Spec.Versions[0].Name != "v1alpha1" || !crd.Spec.Versions[0].Storage ||
				(crd.Spec.Conversion != nil && crd.Spec.Conversion.Strategy != apiextensionsv1.NoneConverter) {
				t.Fatal("new conversion/storage contract needs explicit round-trip fixtures")
			}
			for _, version := range crd.Spec.Versions {
				t.Run(version.Name, func(t *testing.T) {
					obj := &unstructured.Unstructured{Object: map[string]any{
						"apiVersion": api.GroupVersion.Group + "/" + version.Name, "kind": crd.Spec.Names.Kind,
						"metadata": map[string]any{"name": "roundtrip-" + strings.ToLower(crd.Spec.Names.Kind) + "-" + version.Name, "namespace": "condition-fixtures",
							"annotations": map[string]any{"fixture.example/owner": "source-uid", "fixture.example/journal": "prepared-checkpoint"},
							"finalizers":  []any{"fixture.example/preserve-ownership"}},
						"spec": runtime.DeepCopyJSONValue(specs[crd.Spec.Names.Kind]),
					}}
					if err := kube.Create(ctx, obj); err != nil {
						t.Fatal(err)
					}
					condition := map[string]any{"type": "Compatibility", "status": "True", "reason": "FixtureCheckpoint", "message": "bounded public checkpoint",
						"observedGeneration": obj.GetGeneration(), "lastTransitionTime": "2026-01-01T00:00:00Z"}
					empty, err := kube.Scheme().New(obj.GroupVersionKind())
					if err != nil {
						t.Fatal(err)
					}
					zero, err := runtime.DefaultUnstructuredConverter.ToUnstructured(empty)
					if err != nil {
						t.Fatal(err)
					}
					status, ok := zero["status"].(map[string]any)
					if !ok {
						status = map[string]any{}
					}
					status["conditions"] = []any{condition}
					obj.Object["status"] = status
					if crd.Spec.Names.Kind == "HankoMeshService" {
						obj.Object["status"].(map[string]any)["receiverNodeUIDs"] = []any{}
					}
					if err := kube.Status().Update(ctx, obj); err != nil {
						t.Fatal(err)
					}
					stored := &unstructured.Unstructured{}
					readVersion := "v1alpha1"
					if version.Name == "v1alpha1" && len(crd.Spec.Versions) == 2 {
						readVersion = "v1beta1"
					}
					stored.SetGroupVersionKind(schema.GroupVersionKind{Group: api.GroupVersion.Group, Version: readVersion, Kind: crd.Spec.Names.Kind})
					if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
						t.Fatal(err)
					}
					typed, err := kube.Scheme().New(stored.GroupVersionKind())
					if err != nil {
						t.Fatal(err)
					}
					if err := runtime.DefaultUnstructuredConverter.FromUnstructured(stored.Object, typed); err != nil {
						t.Fatal(err)
					}
					roundtrip, err := runtime.DefaultUnstructuredConverter.ToUnstructured(typed.DeepCopyObject())
					if err != nil {
						t.Fatal(err)
					}
					// Compare after the API server reapplies declared defaults. Go's
					// omitempty may omit an explicit default false without changing stored
					// meaning; a non-default loss must still produce a different read-back.
					readBack := &unstructured.Unstructured{Object: roundtrip}
					if err := kube.Update(ctx, readBack); err != nil {
						t.Fatal(err)
					}
					if err := kube.Status().Update(ctx, readBack); err != nil {
						t.Fatal(err)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), readBack); err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"spec", "status"} {
						before, _ := json.Marshal(stored.Object[field])
						after, _ := json.Marshal(readBack.Object[field])
						if string(before) != string(after) {
							t.Fatalf("%s lost or changed stored %s through its typed reader", crd.Spec.Names.Kind, field)
						}
					}
					if readBack.GetUID() != stored.GetUID() || readBack.GetGeneration() != stored.GetGeneration() ||
						!reflect.DeepEqual(readBack.GetAnnotations(), stored.GetAnnotations()) || !reflect.DeepEqual(readBack.GetFinalizers(), stored.GetFinalizers()) {
						t.Fatal("typed reader lost ownership/checkpoint/finalizer identity")
					}
					patch := []byte(`{"spec":{"compatibilityUnknownField":"must-not-disappear-silently"}}`)
					if err := kube.Patch(ctx, stored, client.RawPatch(types.MergePatchType, patch), &client.PatchOptions{FieldValidation: "Strict"}); !apierrors.IsBadRequest(err) && !apierrors.IsInvalid(err) {
						t.Fatal("unknown version field was accepted or silently pruned")
					}
				})
			}
			if len(crd.Spec.Versions) == 2 {
				checkCrossVersionApply(t, ctx, kube, crd.Spec.Names.Kind, specs[crd.Spec.Names.Kind])
			}
		})
	}
}

// The two wire versions must share field ownership. A second version cannot
// bypass an SSA conflict, and concurrent independent owners must not lose data.
func checkCrossVersionApply(t *testing.T, ctx context.Context, kube client.Client, kind string, spec map[string]any) {
	name := "ssa-versions-" + strings.ToLower(kind)
	object := func(version string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "hanko.sh/" + version, "kind": kind,
			"metadata": map[string]any{"name": name, "namespace": "condition-fixtures"},
		}}
	}
	alpha := object("v1alpha1")
	alpha.Object["spec"] = runtime.DeepCopyJSONValue(spec)
	if err := kube.Patch(ctx, alpha, client.Apply, client.FieldOwner("alpha-spec-owner")); err != nil {
		t.Fatal(err)
	}
	conflicting := object("v1beta1")
	conflicting.Object["spec"] = map[string]any{"realmRef": "another-realm"}
	if err := kube.Patch(ctx, conflicting, client.Apply, client.FieldOwner("beta-foreign-owner")); !apierrors.IsConflict(err) {
		t.Fatalf("beta bypassed alpha field ownership: %v", err)
	}
	var owners sync.WaitGroup
	errors := make(chan error, 2)
	for _, version := range []string{"v1alpha1", "v1beta1"} {
		owners.Add(1)
		go func() {
			defer owners.Done()
			for range 3 {
				obj := object(version)
				obj.SetAnnotations(map[string]string{"fixture.example/" + version: "preserved"})
				if err := kube.Patch(ctx, obj, client.Apply, client.FieldOwner("annotation-owner-"+version)); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	owners.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	for _, version := range []string{"v1alpha1", "v1beta1"} {
		readBack := object(version)
		if err := kube.Get(ctx, client.ObjectKeyFromObject(readBack), readBack); err != nil {
			t.Fatal(err)
		}
		if readBack.GetUID() != alpha.GetUID() || readBack.GetGeneration() != alpha.GetGeneration() ||
			readBack.GetAnnotations()["fixture.example/v1alpha1"] != "preserved" || readBack.GetAnnotations()["fixture.example/v1beta1"] != "preserved" {
			t.Fatal("concurrent versioned writers changed identity or lost independently owned fields")
		}
		if realm, _, _ := unstructured.NestedString(readBack.Object, "spec", "realmRef"); realm != spec["realmRef"] {
			t.Fatal("refused beta owner changed alpha declaration")
		}
	}
}
