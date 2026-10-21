//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type statusBudgetCase struct {
	Kind, Path, Type, Format string
	Maximum                  int
	Status, Item             map[string]any
}

func statusBudgetValue(c statusBudgetCase, size int) any {
	if c.Type != "array" {
		return inputBudgetValue(inputBudgetCase{Type: c.Type, Format: c.Format}, size)
	}
	values := make([]any, size)
	for i := range values {
		item := runtime.DeepCopyJSONValue(c.Item).(map[string]any)
		if _, exists := item["name"]; exists {
			item["name"] = fmt.Sprintf("entry-%d", i)
		}
		if _, exists := item["type"]; exists {
			item["type"] = fmt.Sprintf("Condition%d", i)
		}
		if _, exists := item["alias"]; exists {
			item["alias"] = fmt.Sprintf("broker-%d", i)
		}
		if _, exists := item["port"]; exists {
			item["port"] = int64(i + 1)
		}
		values[i] = item
	}
	return values
}

// The frozen corpus does not read generated schemas or the generation policy:
// expected maxima and required ancestor fixtures remain independently reviewed.
func checkPublicStatusBudgets(t *testing.T, ctx context.Context, admin client.Client) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "status-budgets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int
		Cases         []statusBudgetCase
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.SchemaVersion != 1 || len(corpus.Cases) != 232 {
		t.Fatal("incomplete independent status-budget corpus", err)
	}
	objects := map[string]*unstructured.Unstructured{}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		key := c.Kind + "/" + c.Path
		if seen[key] || c.Maximum <= 0 || !strings.HasPrefix(c.Path, "status.") {
			t.Fatal("invalid status-budget fixture", key)
		}
		seen[key] = true
		versions := []string{"v1alpha1"}
		for _, version := range versions {
			objectKey := c.Kind + "/" + version
			base := objects[objectKey]
			if base == nil {
				base = &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/" + version, "kind": c.Kind,
					"metadata": map[string]any{"name": "status-budget-" + strings.ToLower(c.Kind) + "-" + version, "namespace": "condition-fixtures"},
					"spec":     conditionAPISpecs()[c.Kind]}}
				if err := admin.Create(ctx, base); err != nil {
					t.Fatal(err)
				}
				objects[objectKey] = base
			}
			for _, size := range []int{c.Maximum, c.Maximum + 1} {
				t.Run(key+"/"+version+fmt.Sprint(size), func(t *testing.T) {
					object := base.DeepCopy()
					status := runtime.DeepCopyJSONValue(c.Status).(map[string]any)
					assignInputBudget(status, inputBudgetPath.FindAllString(c.Path[7:], -1), statusBudgetValue(c, size))
					object.Object["status"] = status
					err := admin.Status().Update(ctx, object, client.DryRunAll)
					if size == c.Maximum {
						if err != nil {
							t.Fatalf("valid status maximum rejected: %v", err)
						}
						return
					}
					if !apierrors.IsInvalid(err) {
						t.Fatalf("oversized public status admitted: %v", err)
					}
					field := strings.ReplaceAll(c.Path, "[]", "[0]")
					for _, cause := range err.(apierrors.APIStatus).Status().Details.Causes {
						if cause.Field == field {
							return
						}
					}
					t.Fatalf("refusal did not identify the oversized status field %s: %v", field, err)
				})
			}
		}
	}
	checkRealmMapperCheckpointOwnership(t, ctx, admin)
}

func checkRealmMapperCheckpointOwnership(t *testing.T, ctx context.Context, admin client.Client) {
	crd := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition"}}
	if err := admin.Get(ctx, client.ObjectKey{Name: "hankorealms.hanko.sh"}, crd); err != nil {
		t.Fatal(err)
	}
	legacy := crd.DeepCopy()
	candidateVersions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	versions, _, _ := unstructured.NestedSlice(legacy.Object, "spec", "versions")
	for _, item := range versions {
		version := item.(map[string]any)
		if err := unstructured.SetNestedStringSlice(version, []string{"name"}, "schema", "openAPIV3Schema", "properties", "status", "properties", "managedIdentityProviders", "items", "properties", "mappers", "x-kubernetes-list-map-keys"); err != nil {
			t.Fatal(err)
		}
	}
	installVersions := func(versions []any) error {
		data, err := json.Marshal(map[string]any{"spec": map[string]any{"versions": versions}})
		if err != nil {
			return err
		}
		return admin.Patch(ctx, crd, client.RawPatch(types.MergePatchType, data))
	}
	if err := installVersions(versions); err != nil {
		t.Fatal("install previous mapper list semantics", err)
	}
	defer func() {
		if err := installVersions(candidateVersions); err != nil {
			t.Error("restore candidate mapper list semantics", err)
		}
	}()
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm",
		"metadata": map[string]any{"name": "retained-mapper-ids", "namespace": "condition-fixtures"}, "spec": map[string]any{}}}
	if err := admin.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	mapper := func(id string) any { return map[string]any{"name": "claim", "keycloakID": id} }
	status := func(mappers ...any) map[string]any {
		return map[string]any{"managedIdentityProviders": []any{map[string]any{"alias": "broker", "mappers": mappers}}}
	}
	waitForSchema := func(legacy bool) {
		t.Helper()
		if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
			probe := object.DeepCopy()
			probe.Object["status"] = status(mapper("old-id"), mapper("new-id"))
			err := admin.Status().Update(ctx, probe, client.DryRunAll)
			if legacy {
				return apierrors.IsInvalid(err), nil
			}
			return err == nil, nil
		}); err != nil {
			t.Fatal("updated mapper list schema did not become available", err)
		}
	}
	waitForSchema(true)
	object.Object["status"] = status(mapper("old-id"))
	apply := object.DeepCopy()
	apply.SetManagedFields(nil)
	if err := admin.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner("checkpoint-writer")); err != nil {
		t.Fatal("store checkpoint with the previous field-manager list keys", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
		t.Fatal(err)
	}
	if len(object.GetManagedFields()) == 0 {
		t.Fatal("legacy field-manager ownership was not exercised")
	}
	if err := installVersions(candidateVersions); err != nil {
		t.Fatal("adopt compound mapper list keys", err)
	}
	waitForSchema(false)
	object.Object["status"] = status(mapper("old-id"), mapper("new-id"))
	apply = object.DeepCopy()
	apply.SetManagedFields(nil)
	if err := admin.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner("checkpoint-writer")); err != nil {
		t.Fatal("replacement checkpoint must retain IDs and remain writable after legacy SSA ownership", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
		t.Fatal(err)
	}
	providers, _, _ := unstructured.NestedSlice(object.Object, "status", "managedIdentityProviders")
	if len(providers) != 1 || len(providers[0].(map[string]any)["mappers"].([]any)) != 2 {
		t.Fatal("read-back lost an accepted mapper before cleanup acknowledgement")
	}
	duplicate := object.DeepCopy()
	duplicate.Object["status"] = status(mapper("old-id"), mapper("old-id"))
	if err := admin.Status().Update(ctx, duplicate); !apierrors.IsInvalid(err) {
		t.Fatal("duplicate mapper checkpoint identity admitted", err)
	}
	object.Object["status"] = status(mapper("new-id"))
	if err := admin.Status().Update(ctx, object); err != nil {
		t.Fatal("cleanup acknowledgement cannot retire the old mapper", err)
	}
}
