//go:build integration

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkAdoptionStatusContract(t *testing.T, ctx context.Context, admin client.Client) {
	t.Helper()
	for _, kind := range []string{"HankoApplication", "HankoRole", "HankoServiceAccount", "HankoResourceServer"} {
		t.Run(kind, func(t *testing.T) {
			spec := map[string]any{"realmRef": "adoption-realm"}
			switch kind {
			case "HankoApplication":
				spec["clientID"] = "app"
				spec["type"] = "spa"
				spec["mode"] = "Observe"
			case "HankoRole":
				spec["name"] = "role"
			case "HankoServiceAccount":
				spec["clientID"] = "service"
			case "HankoResourceServer":
				spec["audience"] = "api"
				spec["applicationRef"] = "app"
				spec["mode"] = "Observe"
			}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": kind, "metadata": map[string]any{"name": "adoption-" + strings.ToLower(kind), "namespace": "auth", "labels": map[string]any{"hanko.sh/imported-by": "inventory"}}, "spec": spec}}
			if err := admin.Create(ctx, obj); err != nil {
				t.Fatal(err)
			}
			if kind == "HankoRole" || kind == "HankoServiceAccount" {
				if mode, _, _ := unstructured.NestedString(obj.Object, "spec", "mode"); mode != "Manage" {
					t.Fatal("omitted mode did not default to Manage")
				}
				bad := obj.DeepCopy()
				_ = unstructured.SetNestedField(bad.Object, "invalid", "spec", "mode")
				if err := admin.Update(ctx, bad); !apierrors.IsInvalid(err) {
					t.Fatal("invalid mode admitted")
				}
				for _, key := range []string{"hanko.sh/role-owner", "hanko.sh/client-owner-kind", "hanko.sh/client-owner-uid", "hanko.sh/application-owner", "hanko.sh/adoption-receipt"} {
					bad = obj.DeepCopy()
					var value any = "forged"
					if kind == "HankoRole" {
						value = []any{"forged"}
					}
					_ = unstructured.SetNestedMap(bad.Object, map[string]any{key: value}, "spec", "attributes")
					if err := admin.Update(ctx, bad); !apierrors.IsInvalid(err) {
						t.Fatalf("reserved provider attribute admitted: %s", key)
					}
				}
			}
			digest := "sha256:" + strings.Repeat("a", 64)
			candidate := map[string]any{"contractVersion": "hanko.sh/adoption-contract/v1alpha1", "target": map[string]any{"kind": kind, "namespace": "auth", "name": obj.GetName(), "uid": string(obj.GetUID()), "generation": obj.GetGeneration()}, "providerIdentity": map[string]any{"instance": map[string]any{"kind": "HankoKeycloakInstance", "namespace": "auth", "name": "reader", "uid": "source-uid"}, "origin": "https://keycloak.example.test", "trust": "public-ca", "realmID": "realm-uuid", "objectIDs": []any{"provider-uuid"}}, "observationHash": digest, "diffHash": digest, "candidateHash": digest, "complete": true, "truncated": false, "approvable": true, "diff": []any{map[string]any{"domain": "application", "identity": "provider-uuid", "object": "app", "field": "owner", "code": "ownership-transition", "classification": "supported-typed-native", "roundTrip": "lossless-represented"}}}
			obj.Object["status"] = map[string]any{"adoptionCandidate": candidate}
			if err := admin.Status().Update(ctx, obj); err != nil {
				t.Fatal(err)
			}
			got := obj.DeepCopy()
			if err := admin.Get(ctx, client.ObjectKeyFromObject(obj), got); err != nil {
				t.Fatal(err)
			}
			if complete, _, _ := unstructured.NestedBool(got.Object, "status", "adoptionCandidate", "complete"); !complete {
				t.Fatal("candidate status did not round-trip")
			}
			if kind != "HankoResourceServer" {
				obj.Object["status"] = map[string]any{"adoptionCandidate": candidate, "adoptionReceipt": map[string]any{"contractVersion": "hanko.sh/adoption-contract/v1alpha1", "candidateHash": digest, "state": "Verified"}}
				if err := admin.Status().Update(ctx, obj); err != nil {
					t.Fatal(err)
				}
				if err := admin.Get(ctx, client.ObjectKeyFromObject(obj), got); err != nil {
					t.Fatal(err)
				}
				if state, _, _ := unstructured.NestedString(got.Object, "status", "adoptionReceipt", "state"); state != "Verified" {
					t.Fatal("receipt status did not round-trip")
				}
			}
			if len(got.GetAnnotations()) != 0 || len(got.GetFinalizers()) != 0 || got.GetLabels()["hanko.sh/imported-by"] != "inventory" {
				t.Fatal("status evidence acquired authority")
			}
			diff := candidate["diff"].([]any)
			for _, bad := range []map[string]any{
				{"contractVersion": "hanko.sh/adoption-contract/unreviewed"},
				{"candidateHash": "not-a-digest"},
				{"diff": append(diff, makeDiffEntries(256)...)},
				{"findings": makeFindings(33)},
				{"providerIdentity": map[string]any{"instance": candidate["providerIdentity"].(map[string]any)["instance"], "origin": "https://keycloak.example.test", "trust": "public-ca", "realmID": "realm", "objectIDs": []any{strings.Repeat("u", 129)}}},
			} {
				copy := obj.DeepCopy()
				newStatus := map[string]any{}
				for k, v := range candidate {
					newStatus[k] = v
				}
				for k, v := range bad {
					newStatus[k] = v
				}
				copy.Object["status"] = map[string]any{"adoptionCandidate": newStatus}
				if err := admin.Status().Update(ctx, copy); !apierrors.IsInvalid(err) {
					t.Fatal("invalid candidate contract or budget admitted")
				}
			}
		})
	}
	saml := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "adoption-qualified-saml", Namespace: "auth", Labels: map[string]string{"hanko.sh/imported-by": "inventory"}}, Spec: api.HankoApplicationSpec{RealmRef: "adoption-realm", ClientID: "https://sp.example.test", Protocol: "saml", Mode: "Observe", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{"https://sp.example.test/acs"}, NameIDFormat: "persistent"}}}
	if err := admin.Create(ctx, saml); err != nil {
		t.Fatal("qualified SAML Observe declaration rejected", err)
	}
	importObject := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "adoption-coverage", Namespace: "auth"}, Spec: api.HankoImportSpec{SourceRef: "reader", DryRun: true}}
	if err := admin.Create(ctx, importObject); err != nil {
		t.Fatal(err)
	}
	importObject.Status.Phase = "Done"
	importObject.Status.Coverage = api.ImportCoverage{Complete: false, Truncated: true, InventoryCount: 1024, CandidateCount: 8, UnsupportedCount: 4, ObservationHash: "sha256:" + strings.Repeat("a", 64)}
	if err := admin.Status().Update(ctx, importObject); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(importObject), importObject); err != nil {
		t.Fatal(err)
	}
	if importObject.Status.Coverage.Complete || importObject.Status.Phase != "Done" {
		t.Fatal("terminal completion was confused with coverage")
	}
	bad := importObject.DeepCopy()
	bad.Name = "adoption-too-many-realms"
	bad.ResourceVersion = ""
	bad.UID = ""
	bad.Spec.Realms = make([]string, 17)
	for i := range bad.Spec.Realms {
		bad.Spec.Realms[i] = "realm"
	}
	if err := admin.Create(ctx, bad); !apierrors.IsInvalid(err) {
		t.Fatal("selected realm budget not enforced")
	}
}
func makeDiffEntries(n int) []any {
	result := []any{}
	for range n {
		result = append(result, map[string]any{"domain": "application", "identity": "provider-id", "object": "app", "field": "name", "code": "equal", "classification": "supported-typed-native", "roundTrip": "lossless-represented"})
	}
	return result
}
func makeFindings(n int) []any {
	result := []any{}
	for range n {
		result = append(result, map[string]any{"code": "bounded", "domain": "application", "message": "bounded", "blocking": true})
	}
	return result
}

func checkInventorySecretsGETOnly(t *testing.T, ctx context.Context, admin client.Client, operator client.WithWatch) {
	for _, name := range []string{"inventory-admin", "inventory-ca"} {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}}
		if err := admin.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := operator.Get(ctx, client.ObjectKeyFromObject(s), &corev1.Secret{}); err != nil {
			t.Fatal("named inventory Secret GET denied")
		}
	}
	if err := operator.List(ctx, &corev1.SecretList{}, client.InNamespace("auth")); !apierrors.IsForbidden(err) {
		t.Fatal("inventory Secret list permitted")
	}
	watch, err := operator.Watch(ctx, &corev1.SecretList{}, client.InNamespace("auth"))
	if watch != nil {
		watch.Stop()
	}
	if !apierrors.IsForbidden(err) {
		t.Fatal("inventory Secret watch permitted")
	}
}
