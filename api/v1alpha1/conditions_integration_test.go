//go:build integration

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These declarations contain references, never credentials or provider state.
// Admission and status ownership run on the real API server without controllers.
func conditionAPISpecs() map[string]map[string]any {
	return map[string]map[string]any{
		"HankoApplication":      {"realmRef": "realm", "clientID": "conditions-app"},
		"HankoEmailProvider":    {"type": "office365", "enabled": false, "fromAddress": "fixture@example.test"},
		"HankoIAMProfile":       {"security": map[string]any{}},
		"HankoImport":           {"sourceRef": "source"},
		"HankoIssuer":           {"realmRef": "realm", "host": "issuer.example.test"},
		"HankoKeycloakInstance": {"mode": "external", "adminRef": map[string]any{"name": "admin-reference"}},
		"HankoMeshService": {"identityRef": "identity", "resourceServerRef": "server", "serviceRef": "service", "tenantRef": "tenant",
			"workloadServiceAccountRef": "workload", "ports": []any{map[string]any{"port": int64(443), "protocol": "TCP"}}},
		"HankoOperation":      {"instanceRef": "source", "type": "Clone", "clone": map[string]any{"targetName": "target"}},
		"HankoOrganization":   {"realmRef": "realm", "name": "organization"},
		"HankoRealm":          {},
		"HankoResourceServer": {"realmRef": "realm", "applicationRef": "app", "audience": "urn:conditions"},
		"HankoRole":           {"realmRef": "realm", "name": "conditions-role"},
		"HankoServiceAccount": {"realmRef": "realm", "clientID": "conditions-worker"},
		"HankoSnapshot":       {"instanceRef": "source"},
		"HankoTenant":         {"hubTokenSecretRef": map[string]any{"name": "hub-reference"}},
		"HankoTheme":          {"buildImage": "registry.example/theme@sha256:" + strings.Repeat("a", 64), "keycloakPVC": "theme-volume"},
		"HankoWorkloadTrust": {"realmRef": "realm", "sourceRef": "source", "dependentReaderRef": "reader", "keycloakAlias": "cluster", "provider": "Kubernetes",
			"kubernetes": map[string]any{"issuer": "https://cluster.example.test", "clusterAnchor": map[string]any{
				"apiServerCAHash": "sha256:" + strings.Repeat("b", 64), "kubeSystemNamespaceUID": "fixture-cluster"}}},
	}
}

func checkConditionApply(t *testing.T, ctx context.Context, kube client.Client, crds []*apiextensionsv1.CustomResourceDefinition) {
	specs := conditionAPISpecs()
	if len(specs) != len(crds) {
		t.Fatalf("condition fixtures cover %d of %d CRDs", len(specs), len(crds))
	}
	for _, crd := range crds {
		t.Run(crd.Spec.Names.Kind, func(t *testing.T) {
			spec, found := specs[crd.Spec.Names.Kind]
			if !found {
				t.Fatal("missing condition admission fixture")
			}
			for _, version := range crd.Spec.Versions {
				checkConditionSchema(t, version.Schema.OpenAPIV3Schema, version.Name)
			}
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "hanko.sh/v1alpha1", "kind": crd.Spec.Names.Kind,
				"metadata": map[string]any{"name": "conditions-" + strings.ToLower(crd.Spec.Names.Kind), "namespace": "condition-fixtures"}, "spec": spec,
			}}
			if err := kube.Create(ctx, obj); err != nil {
				t.Fatal(err)
			}
			apply := func(manager, kind, reason string) error {
				patch := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": obj.GetAPIVersion(), "kind": obj.GetKind(),
					"metadata": map[string]any{"name": obj.GetName(), "namespace": obj.GetNamespace()},
					"status": map[string]any{"conditions": []any{map[string]any{
						"type": kind, "status": "True", "reason": reason, "message": "Public fixture decision",
						"lastTransitionTime": "2026-01-01T00:00:00Z", "observedGeneration": obj.GetGeneration(),
					}}},
				}}
				if obj.GetKind() == "HankoMeshService" {
					if err := unstructured.SetNestedSlice(patch.Object, []any{}, "status", "receiverNodeUIDs"); err != nil {
						return err
					}
				}
				return kube.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(patch), client.FieldOwner(manager))
			}
			for _, call := range []struct{ manager, kind, reason string }{
				{"provider-observer", "ProviderObserved", "Observed"},
				{"projection-observer", "ProjectionObserved", "Observed"},
				{"provider-observer", "ProviderObserved", "Reobserved"},
			} {
				if err := apply(call.manager, call.kind, call.reason); err != nil {
					t.Fatalf("independent condition ownership: %v", err)
				}
			}
			if err := apply("projection-observer", "ProviderObserved", "TakenOver"); !apierrors.IsConflict(err) {
				t.Fatalf("another manager changed the same condition without a conflict: %v", err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			conditions, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
			if err != nil || !found || len(conditions) != 2 {
				t.Fatalf("independent conditions did not survive read-back: %v", err)
			}
			reasons := map[string]string{}
			for _, condition := range conditions {
				value := condition.(map[string]any)
				reasons[value["type"].(string)] = value["reason"].(string)
			}
			if reasons["ProviderObserved"] != "Reobserved" || reasons["ProjectionObserved"] != "Observed" {
				t.Fatal("a status writer replaced another condition")
			}
			if err := unstructured.SetNestedSlice(obj.Object, []any{conditions[0], conditions[0]}, "status", "conditions"); err != nil {
				t.Fatal(err)
			}
			if err := kube.Status().Update(ctx, obj); !apierrors.IsInvalid(err) {
				t.Fatalf("duplicate condition types were admitted: %v", err)
			}
		})
	}
}

func checkConditionSchema(t *testing.T, schema *apiextensionsv1.JSONSchemaProps, path string) {
	t.Helper()
	for name, property := range schema.Properties {
		if name == "conditions" {
			if property.XListType == nil || *property.XListType != "map" || len(property.XListMapKeys) != 1 || property.XListMapKeys[0] != "type" {
				t.Fatalf("conditions lack type-keyed ownership at %s", path)
			}
		}
		checkConditionSchema(t, &property, path+"."+name)
	}
	if schema.Items != nil && schema.Items.Schema != nil {
		checkConditionSchema(t, schema.Items.Schema, path+"[]")
	}
}
