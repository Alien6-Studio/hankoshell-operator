//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type inputBudgetCase struct {
	Kind, Path, Type, Format string
	Maximum                  int
	Spec                     map[string]any
}

func inputBudgetValue(c inputBudgetCase, size int) any {
	if c.Type == "object" {
		value := map[string]any{}
		for i := range size {
			value[fmt.Sprintf("example.test/resource-%d", i)] = "1"
		}
		return value
	}
	if c.Type == "array" {
		values := make([]any, size)
		for i := range values {
			switch {
			case strings.HasSuffix(c.Path, ".claims"):
				values[i] = map[string]any{"name": fmt.Sprintf("claim-%d", i), "request": "request"}
			case strings.HasSuffix(c.Path, ".imagePullSecrets"):
				values[i] = map[string]any{"name": fmt.Sprintf("image-%d", i)}
			default:
				values[i] = "value"
			}
		}
		return values
	}
	prefix, suffix, fill := "", "", "a"
	switch c.Format {
	case "uuid":
		return "00000000-0000-0000-0000-000000000000" + strings.Repeat("a", size-36)
	case "datetime":
		prefix, suffix = "2026-10-19T00:00:00.", "Z"
		fill = "0"
	case "unicode":
		fill = "é"
	case "image":
		prefix, suffix = "registry.example/", "@sha256:"+strings.Repeat("a", 64)
	case "url":
		prefix = "https://hub.example/"
	case "jar":
		suffix = ".jar"
	case "digest":
		prefix = "sha256:"
	case "quantity":
		prefix, suffix = "1", "m"
		fill = "0"
	}
	return prefix + strings.Repeat(fill, size-len(prefix)-len(suffix)) + suffix
}

var inputBudgetPath = regexp.MustCompile(`[A-Za-z][A-Za-z0-9]*|\[\]|\{\}`)

func assignInputBudget(value any, path []string, next any) any {
	if len(path) == 0 {
		return next
	}
	if path[0] == "[]" {
		items, _ := value.([]any)
		if len(items) == 0 {
			items = []any{nil}
		}
		items[0] = assignInputBudget(items[0], path[1:], next)
		return items
	}
	object, _ := value.(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	key := path[0]
	if key == "{}" {
		key = "entry"
	}
	object[key] = assignInputBudget(object[key], path[1:], next)
	return object
}

func checkPublicInputBudgets(t *testing.T, ctx context.Context, admin client.Client) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "input-budgets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int
		Cases         []inputBudgetCase
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.SchemaVersion != 1 || len(corpus.Cases) != 95 {
		t.Fatal("incomplete independent input-budget corpus", err)
	}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		key := c.Kind + "/" + c.Path
		if seen[key] || c.Maximum <= 0 || !strings.HasPrefix(c.Path, "spec.") {
			t.Fatal("invalid or duplicate input-budget fixture", key)
		}
		seen[key] = true
		versions := []string{"v1alpha1"}
		for _, version := range versions {
			for _, size := range []int{c.Maximum, c.Maximum + 1} {
				t.Run(key+"/"+version+fmt.Sprint(size), func(t *testing.T) {
					spec := runtime.DeepCopyJSONValue(c.Spec).(map[string]any)
					value := inputBudgetValue(c, size)
					assignInputBudget(spec, inputBudgetPath.FindAllString(c.Path[5:], -1), value)
					object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/" + version, "kind": c.Kind,
						"metadata": map[string]any{"name": "public-input-bound", "namespace": "condition-fixtures"}, "spec": spec}}
					err := admin.Create(ctx, object, client.DryRunAll)
					if size == c.Maximum && err != nil {
						t.Fatalf("valid maximum rejected: %v", err)
					}
					if size > c.Maximum && !apierrors.IsInvalid(err) {
						t.Fatalf("oversized public input admitted: %v", err)
					}
				})
			}
		}
	}
	checkNativeMapKeyBudgets(t, ctx, admin)
}

func checkNativeMapKeyBudgets(t *testing.T, ctx context.Context, admin client.Client) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount", "HankoRole", "HankoRealm"} {
		versions := []string{"v1alpha1"}
		for _, version := range versions {
			for _, size := range []int{0, 255, 256} {
				t.Run(kind+"/"+version+"/native-map-key/"+fmt.Sprint(size), func(t *testing.T) {
					spec := runtime.DeepCopyJSONValue(conditionAPISpecs()[kind]).(map[string]any)
					var value any = "public-value"
					if kind == "HankoRole" {
						value = []any{"public-value"}
					}
					attributes := map[string]any{strings.Repeat("a", size): value}
					if kind == "HankoRealm" {
						spec["identityProviders"] = []any{map[string]any{"alias": "broker", "providerID": "oidc", "config": attributes}}
					} else {
						spec["attributes"] = attributes
					}
					obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/" + version, "kind": kind,
						"metadata": map[string]any{"name": "map-input-bound", "namespace": "condition-fixtures"}, "spec": spec}}
					err := admin.Create(ctx, obj, client.DryRunAll)
					if size == 255 && err != nil || size != 255 && !apierrors.IsInvalid(err) {
						t.Fatalf("native map key budget not enforced: %v", err)
					}
				})
			}
		}
	}
}
