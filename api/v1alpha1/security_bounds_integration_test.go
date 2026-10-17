//go:build integration

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coordinationclient "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkBoundedReferences(t *testing.T, ctx context.Context, admin client.Client) {
	specs := conditionAPISpecs()
	for _, kind := range []string{"HankoApplication", "HankoRole", "HankoResourceServer", "HankoServiceAccount", "HankoOrganization", "HankoIssuer", "HankoWorkloadTrust"} {
		fields := []string{"realmRef"}
		if kind == "HankoResourceServer" {
			fields = append(fields, "applicationRef")
		}
		for _, field := range fields {
			for _, test := range []struct {
				name, value string
				valid       bool
			}{
				{"short", "a", true}, {"maximum", strings.Repeat("a", 253), true},
				{"empty", "", false}, {"overlong", strings.Repeat("a", 254), false},
				{"path", "realm/foreign", false}, {"uppercase", "Realm", false},
				{"empty-label", "realm..foreign", false}, {"trailing-dot", "realm.", false},
				{"leading-hyphen", "-realm", false}, {"control", "realm\n", false},
			} {
				t.Run(kind+"/"+field+"/"+test.name, func(t *testing.T) {
					spec := runtime.DeepCopyJSONValue(specs[kind]).(map[string]any)
					spec[field] = test.value
					object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": kind, "metadata": map[string]any{"name": "bounded-reference", "namespace": "condition-fixtures"}, "spec": spec}}
					err := admin.Create(ctx, object, client.DryRunAll)
					if test.valid && err != nil {
						t.Fatalf("valid reference refused: %v", err)
					}
					if !test.valid && !apierrors.IsInvalid(err) {
						t.Fatalf("invalid reference admitted: %v", err)
					}
				})
			}
		}
	}
}

func checkLeaderLeaseRBAC(t *testing.T, ctx context.Context, admin, operator client.Client, config *rest.Config) {
	typed, err := coordinationclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	lock := &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Namespace: "auth", Name: "hanko-operator.hanko.sh"}, Client: typed, LockConfig: resourcelock.ResourceLockConfig{Identity: "fixture-leader"}}
	record := resourcelock.LeaderElectionRecord{HolderIdentity: "fixture-leader", LeaseDurationSeconds: 15, AcquireTime: metav1.Now(), RenewTime: metav1.Now()}
	if err := lock.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lock.Get(ctx); err != nil {
		t.Fatal(err)
	}
	record.RenewTime = metav1.Now()
	if err := lock.Update(ctx, record); err != nil {
		t.Fatal(err)
	}
	foreign := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "foreign-lock"}}
	if err := admin.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if err := operator.Get(ctx, client.ObjectKeyFromObject(foreign), new(coordinationv1.Lease)); !apierrors.IsForbidden(err) {
		t.Fatalf("foreign lease readable: %v", err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"update foreign", func() error { return operator.Update(ctx, foreign) }},
		{"patch foreign", func() error {
			return operator.Patch(ctx, foreign, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"labels":{"fixture":"changed"}}}`)))
		}},
		{"delete foreign", func() error { return operator.Delete(ctx, foreign) }},
		{"list", func() error { return operator.List(ctx, new(coordinationv1.LeaseList), client.InNamespace("auth")) }},
		{"delete owned", func() error {
			return operator.Delete(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: lock.LeaseMeta.Name}})
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !apierrors.IsForbidden(err) {
				t.Fatalf("unexpected lease authority: %v", err)
			}
		})
	}
}
