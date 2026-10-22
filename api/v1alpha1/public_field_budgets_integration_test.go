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

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	validationfield "k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type publicFieldBudget struct {
	Kind, Path, Type string
	Object           map[string]any
	Bounds           struct {
		MinLength, MaxLength, MaxItems, MaxProperties *int
		Pattern                                       string
		Enum                                          []string
	}
}

func publicFieldValue(value any, tokens []string) any {
	for _, token := range tokens {
		switch token {
		case "[]":
			value = value.([]any)[0]
		case "{}":
			value = value.(map[string]any)["entry"]
		default:
			value = value.(map[string]any)[token]
		}
	}
	return value
}

// Each bound and representative is frozen independently of generated CRDs. The
// live-schema walk only detects missing/removed paths, never supplies limits.
func checkEveryPublicField(t *testing.T, ctx context.Context, admin client.Client, crds []*apiextensionsv1.CustomResourceDefinition) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "public-field-budgets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int
		Cases         []publicFieldBudget
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.SchemaVersion != 1 || len(corpus.Cases) != 969 {
		t.Fatal("incomplete frozen public-field admission corpus", err)
	}
	expected := map[string]bool{}
	for _, c := range corpus.Cases {
		key := c.Kind + "/" + c.Path
		if expected[key] {
			t.Fatal("duplicate public-field fixture", key)
		}
		expected[key] = true
	}
	observed := map[string]bool{}
	for _, crd := range crds {
		for _, version := range crd.Spec.Versions {
			if version.Name != "v1alpha1" {
				continue
			}
			var walk func(apiextensionsv1.JSONSchemaProps, string)
			walk = func(s apiextensionsv1.JSONSchemaProps, path string) {
				if s.Type == "string" || s.Type == "array" || s.Type == "object" && s.AdditionalProperties != nil && s.AdditionalProperties.Schema != nil {
					key := crd.Spec.Names.Kind + "/" + path
					observed[key] = true
					if !expected[key] {
						t.Error("public field lacks independent admission fixture", key)
					}
				}
				for name, child := range s.Properties {
					walk(child, path+"."+name)
				}
				if s.Items != nil && s.Items.Schema != nil {
					walk(*s.Items.Schema, path+"[]")
				}
				if s.AdditionalProperties != nil && s.AdditionalProperties.Schema != nil {
					walk(*s.AdditionalProperties.Schema, path+"{}")
				}
			}
			for _, group := range []string{"spec", "status"} {
				walk(version.Schema.OpenAPIV3Schema.Properties[group], group)
			}
		}
	}
	for key := range expected {
		if !observed[key] {
			t.Error("frozen public field was removed", key)
		}
	}
	bases := map[string]*unstructured.Unstructured{}
	for _, c := range corpus.Cases {
		versions := []string{"v1alpha1"}
		for _, version := range versions {
			t.Run(c.Kind+"/"+version+"/"+c.Path, func(t *testing.T) {
				object := &unstructured.Unstructured{Object: runtime.DeepCopyJSONValue(c.Object).(map[string]any)}
				object.SetAPIVersion("hanko.sh/" + version)
				object.SetKind(c.Kind)
				object.SetNamespace("condition-fixtures")
				object.SetName("every-public-field")
				status := strings.HasPrefix(c.Path, "status.")
				if status {
					key := c.Kind + "/" + version
					base := bases[key]
					if base == nil {
						base = object.DeepCopy()
						base.SetName("field-status-" + strings.ToLower(c.Kind) + "-" + version)
						delete(base.Object, "status")
						if err := admin.Create(ctx, base); err != nil {
							t.Fatal(err)
						}
						bases[key] = base
					}
					object.SetName(base.GetName())
					object.SetResourceVersion(base.GetResourceVersion())
				}
				submit := func(value *unstructured.Unstructured) error {
					if status {
						return admin.Status().Update(ctx, value, client.DryRunAll)
					}
					return admin.Create(ctx, value, client.DryRunAll)
				}
				if err := submit(object.DeepCopy()); err != nil {
					t.Fatalf("positive representative rejected: %v", err)
				}
				tokens := inputBudgetPath.FindAllString(c.Path, -1)
				value := publicFieldValue(c.Object, tokens)
				negatives := map[string]any{}
				if c.Bounds.MaxLength != nil {
					negatives["maxLength"] = strings.Repeat("a", *c.Bounds.MaxLength+1)
				}
				if c.Bounds.MinLength != nil && *c.Bounds.MinLength > 0 {
					negatives["minLength"] = ""
				}
				if c.Bounds.MaxItems != nil {
					item := value.([]any)[0]
					items := make([]any, *c.Bounds.MaxItems+1)
					for i := range items {
						items[i] = runtime.DeepCopyJSONValue(item)
					}
					negatives["maxItems"] = items
				}
				if c.Bounds.MaxProperties != nil {
					properties := map[string]any{}
					var item any = "public-fixture"
					for _, v := range value.(map[string]any) {
						item = v
						break
					}
					for i := 0; i <= *c.Bounds.MaxProperties; i++ {
						properties[fmt.Sprintf("entry-%d", i)] = runtime.DeepCopyJSONValue(item)
					}
					negatives["maxProperties"] = properties
				}
				if len(c.Bounds.Enum) > 0 {
					negatives["enum"] = "unsupported-field-value"
				}
				if c.Bounds.Pattern != "" {
					pattern, err := regexp.Compile(c.Bounds.Pattern)
					if err != nil {
						t.Fatal(err)
					}
					for _, candidate := range []string{"\x00", "\r", " ", "@", "/", "*"} {
						if !pattern.MatchString(candidate) {
							negatives["pattern"] = candidate
							break
						}
					}
					if _, found := negatives["pattern"]; !found {
						t.Fatal("pattern lacks an adversarial fixture")
					}
				}
				for constraint, invalid := range negatives {
					t.Run(constraint, func(t *testing.T) {
						changed := object.DeepCopy()
						assignInputBudget(changed.Object, tokens, invalid)
						err := submit(changed)
						if !apierrors.IsInvalid(err) {
							t.Fatalf("invalid %s accepted: %v", c.Path, err)
						}
						field := strings.ReplaceAll(strings.ReplaceAll(c.Path, "[]", "[0]"), "{}", "[entry]")
						for _, cause := range err.(apierrors.APIStatus).Status().Details.Causes {
							if cause.Field == field || cause.Field == strings.ReplaceAll(field, "[entry]", ".entry") {
								if constraint == "maxLength" && cause.Type != metav1.CauseType(validationfield.ErrorTypeTooLong) {
									continue
								}
								if (constraint == "maxItems" || constraint == "maxProperties") && cause.Type != metav1.CauseType(validationfield.ErrorTypeTooMany) {
									continue
								}
								return
							}
						}
						t.Fatalf("refusal did not identify %s: %v", field, err)
					})
				}
			})
		}
	}
}
