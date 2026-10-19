//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkCustomResourceRBAC(t *testing.T, ctx context.Context, admin, operator client.Client, chart, version string) {
	// These use cases are intentionally reviewed separately from the chart rule
	// grouping: importing a role is not permission to delete it; reading an
	// issuer or a mesh request is not permission to create or edit its spec.
	type authority struct {
		resource              string
		metadata, create, del bool
	}
	cases := []authority{
		{"hankorealms", true, true, true}, {"hankoiamprofiles", true, true, true},
		{"hankoapplications", true, true, true}, {"hankoserviceaccounts", true, true, true},
		{"hankothemes", true, true, true}, {"hankoroles", true, true, false},
		{"hankoorganizations", true, false, false}, {"hankoworkloadtrusts", true, false, false},
		{"hankoresourceservers", true, false, false}, {"hankotenants", true, false, true},
		{"hankoissuers", false, false, false}, {"hankomeshservices", false, false, false},
		{"hankoemailproviders", false, false, false}, {"hankokeycloakinstances", true, false, false},
		{"hankoimports", false, false, false}, {"hankooperations", false, false, false}, {"hankosnapshots", false, false, false},
	}
	for _, enabled := range []bool{false, true} {
		installCompatibilityChart(t, ctx, admin, chart, version, []string{"--set", fmt.Sprintf("lifecycle.enabled=%t", enabled)})
		for _, entry := range cases {
			lifecycle := entry.resource == "hankooperations" || entry.resource == "hankosnapshots"
			if enabled && (entry.resource == "hankokeycloakinstances" || entry.resource == "hankoimports" || entry.resource == "hankosnapshots") {
				entry.create = true
			}
			if lifecycle {
				entry.metadata = enabled
			}
			for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"} {
				allowed := !lifecycle || enabled
				switch verb {
				case "create":
					allowed = entry.create
				case "update", "patch":
					allowed = entry.metadata
				case "delete":
					allowed = entry.del
				case "deletecollection":
					allowed = false
				}
				t.Run(fmt.Sprintf("lifecycle-%t/%s/%s", enabled, entry.resource, verb), func(t *testing.T) {
					review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: "auth", Group: "hanko.sh", Resource: entry.resource, Verb: verb}}}
					if err := operator.Create(ctx, review); err != nil {
						t.Fatal(err)
					}
					if review.Status.Allowed != allowed || review.Status.EvaluationError != "" {
						t.Fatalf("unexpected live RBAC decision: allowed=%t, expected=%t, evaluation error=%q", review.Status.Allowed, allowed, review.Status.EvaluationError)
					}
				})
			}
		}
	}
	// Restore the ordinary profile before other fixtures exercise its grants.
	installCompatibilityChart(t, ctx, admin, chart, version, nil)
	for _, kind := range []string{"HankoIssuer", "HankoMeshService"} {
		spec := runtime.DeepCopyJSONValue(conditionAPISpecs()[kind])
		obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
			"metadata": map[string]any{"name": "rbac-" + strings.ToLower(kind), "namespace": "auth"}, "spec": spec}}
		if err := operator.Create(ctx, obj, client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatalf("operator can create %s: %v", kind, err)
		}
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
		obj.SetLabels(map[string]string{"fixture": "must-be-refused"})
		if err := operator.Update(ctx, obj, client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatalf("operator can update %s spec/metadata: %v", kind, err)
		}
		if err := operator.Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"labels":{"fixture":"must-be-refused"}}}`)), client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatalf("operator can patch %s: %v", kind, err)
		}
		if err := operator.Delete(ctx, obj, client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatalf("operator can delete %s: %v", kind, err)
		}
		if err := operator.Status().Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(`{"status":{"observedGeneration":1}}`)), client.DryRunAll); err != nil {
			t.Fatalf("operator lost %s status publication: %v", kind, err)
		}
	}
}
