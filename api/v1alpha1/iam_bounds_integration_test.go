//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkIAMInputBudgets(t *testing.T, ctx context.Context, admin client.Client) {
	type bound struct {
		kind, name, field string
		maximum           int
		value             func(int) any
	}
	text := func(n int) any { return strings.Repeat("a", n) }
	items := func(n int) any {
		values := make([]any, n)
		for i := range values {
			values[i] = fmt.Sprintf("item-%d", i)
		}
		return values
	}
	bounds := []bound{
		{"HankoApplication", "client-id", "clientID", 255, text},
		{"HankoServiceAccount", "client-id", "clientID", 255, text},
		{"HankoRole", "role-name", "name", 255, text},
		{"HankoRole", "description", "description", 1024, text},
		{"HankoOrganization", "name", "name", 255, text},
		{"HankoOrganization", "slug", "slug", 253, text},
		{"HankoOrganization", "parent", "parentRef", 253, text},
		{"HankoOrganization", "broker", "identityProvider", 255, text},
		{"HankoApplication", "theme", "theme", 253, text},
		{"HankoRealm", "display-name", "displayName", 255, text},
		{"HankoRealm", "theme", "loginTheme", 255, text},
		{"HankoRealm", "frontend-url", "frontendURL", 2048, func(n int) any { return "https://example.test/" + strings.Repeat("a", n-21) }},
		{"HankoApplication", "redirect-count", "redirectURIs", 64, items},
		{"HankoApplication", "logout-count", "postLogoutRedirectURIs", 64, items},
		{"HankoApplication", "scope-count", "realmRoleScopes", 64, items},
		{"HankoServiceAccount", "scope-count", "scopes", 64, items},
		{"HankoRole", "composite-count", "composites", 64, items},
		{"HankoOrganization", "domain-count", "domains", 64, items},
	}
	for _, field := range []string{"redirectURIs", "postLogoutRedirectURIs", "realmRoleScopes"} {
		maximum := 255
		if field != "realmRoleScopes" {
			maximum = 2048
		}
		bounds = append(bounds, bound{"HankoApplication", field + "-item", field, maximum, func(n int) any { return []any{strings.Repeat("a", n)} }})
	}
	for _, kind := range []string{"HankoApplication", "HankoRealm"} {
		bounds = append(bounds,
			bound{kind, "role-count", "roles", 64, func(n int) any {
				roles := make([]any, n)
				for i := range roles {
					roles[i] = map[string]any{"name": fmt.Sprintf("role-%d", i)}
				}
				return roles
			}},
			bound{kind, "role-name-item", "roles", 255, func(n int) any { return []any{map[string]any{"name": strings.Repeat("a", n)}} }},
			bound{kind, "role-description-item", "roles", 1024, func(n int) any { return []any{map[string]any{"name": "role", "description": strings.Repeat("a", n)}} }})
	}
	bounds = append(bounds,
		bound{"HankoApplication", "projection-count", "clientSecretProjections", 32, func(n int) any {
			values := make([]any, n)
			for i := range values {
				values[i] = map[string]any{"namespace": fmt.Sprintf("workload-%d", i), "name": "credential"}
			}
			return values
		}},
		bound{"HankoOrganization", "client-role-count", "clientRoles", 64, func(n int) any {
			values := make([]any, n)
			for i := range values {
				values[i] = map[string]any{"client": fmt.Sprintf("client-%d", i), "roles": []any{"reader"}}
			}
			return values
		}},
		bound{"HankoOrganization", "client-role-name", "clientRoles", 255, func(n int) any {
			return []any{map[string]any{"client": strings.Repeat("a", n), "roles": []any{"reader"}}}
		}},
		bound{"HankoOrganization", "nested-role-count", "clientRoles", 64, func(n int) any { return []any{map[string]any{"client": "client", "roles": items(n)}} }},
		bound{"HankoOrganization", "nested-role-length", "clientRoles", 255, func(n int) any {
			return []any{map[string]any{"client": "client", "roles": []any{strings.Repeat("a", n)}}}
		}})
	specs := conditionAPISpecs()
	for _, entry := range bounds {
		versions := []string{"v1alpha1"}
		if entry.kind == "HankoApplication" || entry.kind == "HankoRole" {
			versions = append(versions, "v1beta1")
		}
		for _, version := range versions {
			for _, size := range []int{entry.maximum, entry.maximum + 1} {
				t.Run(entry.kind+"/"+version+"/"+entry.name+fmt.Sprint(size), func(t *testing.T) {
					spec := runtime.DeepCopyJSONValue(specs[entry.kind]).(map[string]any)
					spec[entry.field] = entry.value(size)
					if entry.field == "clientSecretProjections" {
						spec["type"] = "web"
					}
					obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/" + version, "kind": entry.kind,
						"metadata": map[string]any{"name": "iam-boundary", "namespace": "condition-fixtures"}, "spec": spec}}
					err := admin.Create(ctx, obj, client.DryRunAll)
					if size == entry.maximum && err != nil {
						t.Fatalf("valid boundary refused: %v", err)
					}
					if size > entry.maximum && !apierrors.IsInvalid(err) {
						t.Fatalf("over-budget value admitted: %v", err)
					}
				})
			}
		}
	}
	for _, entry := range []struct{ kind, field string }{{"HankoApplication", "clientID"}, {"HankoServiceAccount", "clientID"}, {"HankoRole", "name"}, {"HankoOrganization", "name"}} {
		for _, value := range []string{"", "identifier\n", "identifier\x00", "identifier\x7f"} {
			t.Run(entry.kind+"/invalid-identifier/"+fmt.Sprintf("%x", value), func(t *testing.T) {
				spec := runtime.DeepCopyJSONValue(specs[entry.kind]).(map[string]any)
				spec[entry.field] = value
				obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": entry.kind,
					"metadata": map[string]any{"name": "invalid-identifier", "namespace": "condition-fixtures"}, "spec": spec}}
				if err := admin.Create(ctx, obj, client.DryRunAll); !apierrors.IsInvalid(err) {
					t.Fatalf("unsafe identifier admitted: %v", err)
				}
			})
		}
	}
}
