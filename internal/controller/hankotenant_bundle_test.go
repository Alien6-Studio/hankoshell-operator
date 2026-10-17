package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestLegacyBundleObjectBudgetPrecedesKubernetesIO(t *testing.T) {
	requests := 0
	kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			requests++
			return errors.New("unexpected Kubernetes request")
		},
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			requests++
			return errors.New("unexpected Kubernetes request")
		},
	}).Build()
	bundle := &hub.Bundle{Apps: make([]json.RawMessage, fleetplan.MaxObjects), Realms: []json.RawMessage{json.RawMessage(`{}`)}}
	r := &HankoTenantReconciler{Client: kube}
	if _, err := r.applyBundle(context.Background(), &api.HankoTenant{}, bundle); err == nil || bundleApplyReason(err) != "BundleObjectLimit" || requests != 0 {
		t.Fatalf("over-budget bundle reached Kubernetes: %d requests, %v", requests, err)
	}
}

func TestTenantBundleMetadataRefusedBeforeAnyWrite(t *testing.T) {
	for name, tc := range map[string]struct{ raw, reason string }{
		"foreign namespace":   {`{"metadata":{"name":"bad","namespace":"other"}}`, "BundleTenantConflict"},
		"foreign tenant":      {`{"metadata":{"name":"bad","labels":{"hanko.sh/tenant":"other"}}}`, "BundleTenantConflict"},
		"empty tenant":        {`{"metadata":{"name":"bad","labels":{"hanko.sh/tenant":""}}}`, "BundleTenantConflict"},
		"approval":            {`{"metadata":{"name":"bad","annotations":{"hanko.sh/adoption-candidate":"approved"}}}`, "BundleMetadataInvalid"},
		"legacy approval":     {`{"metadata":{"name":"bad","annotations":{"hanko.sh/migrate-keycloak-client-uuid":"id"}}}`, "BundleMetadataInvalid"},
		"import marker":       {`{"metadata":{"name":"bad","labels":{"hanko.sh/imported-by":"import"}}}`, "BundleMetadataInvalid"},
		"owner":               {`{"metadata":{"name":"bad","ownerReferences":[]}}`, "BundleMetadataInvalid"},
		"finalizer":           {`{"metadata":{"name":"bad","finalizers":["hanko.sh/realm-cleanup"]}}`, "BundleMetadataInvalid"},
		"UID":                 {`{"metadata":{"name":"bad","uid":"id"}}`, "BundleMetadataInvalid"},
		"resource version":    {`{"metadata":{"name":"bad","resourceVersion":"42"}}`, "BundleMetadataInvalid"},
		"managed fields":      {`{"metadata":{"name":"bad","managedFields":[]}}`, "BundleMetadataInvalid"},
		"status":              {`{"metadata":{"name":"bad"},"status":{"phase":"Synced"}}`, "BundleObjectInvalid"},
		"missing name":        {`{"metadata":{}}`, "BundleObjectInvalid"},
		"generated name":      {`{"metadata":{"generateName":"bad-"}}`, "BundleObjectInvalid"},
		"invalid name":        {`{"metadata":{"name":"../bad"}}`, "BundleObjectInvalid"},
		"null":                {`null`, "BundleObjectInvalid"},
		"wrong metadata type": {`{"metadata":{"name":"bad","labels":{"team":false}}}`, "BundleObjectInvalid"},
		"duplicate target":    {`{"metadata":{"name":"good"}}`, "BundleObjectInvalid"},
	} {
		t.Run(name, func(t *testing.T) {
			writes := 0
			kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
					writes++
					return nil
				},
				Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
					writes++
					return nil
				},
			}).Build()
			r := &HankoTenantReconciler{Client: kube}
			tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}
			counts, err := r.applyBundle(context.Background(), tenant, &hub.Bundle{Realms: []json.RawMessage{json.RawMessage(`{"metadata":{"name":"good"}}`), json.RawMessage(tc.raw)}})
			if err == nil || bundleApplyReason(err) != tc.reason || writes != 0 || counts["realms"] != 0 {
				t.Fatalf("bundle was not refused before writes: counts=%v writes=%d err=%v", counts, writes, err)
			}
		})
	}
}

func TestTenantBundleUsesCurrentOwnershipForEveryKind(t *testing.T) {
	for _, kind := range []string{"HankoIAMProfile", "HankoRealm", "HankoApplication", "HankoTheme", "HankoServiceAccount"} {
		for _, label := range []string{"other", ""} {
			t.Run(kind+"/"+label, func(t *testing.T) {
				live := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.GroupVersion.String(), "kind": kind,
					"metadata": map[string]any{"name": "target", "namespace": "test", "uid": "live", "labels": map[string]any{"hanko.sh/tenant": label}}}}
				// The cache has no object. Only the uncached reader knows its owner.
				reader := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithObjects(live).Build()
				writes := 0
				kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
					Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
						writes++
						return nil
					},
					Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
						writes++
						return nil
					},
				}).Build()
				raw := []json.RawMessage{json.RawMessage(`{"metadata":{"name":"target"}}`)}
				bundle := &hub.Bundle{}
				switch kind {
				case "HankoIAMProfile":
					bundle.IAMProfiles = raw
				case "HankoRealm":
					bundle.Realms = raw
				case "HankoApplication":
					bundle.Apps = raw
				case "HankoTheme":
					bundle.Themes = raw
				case "HankoServiceAccount":
					bundle.ServiceAccounts = raw
				}
				r := &HankoTenantReconciler{Client: kube, APIReader: reader}
				_, err := r.applyBundle(context.Background(), &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}, bundle)
				if err == nil || bundleApplyReason(err) != "BundleTenantConflict" || writes != 0 {
					t.Fatalf("foreign/unassigned live target was not refused: writes=%d err=%v", writes, err)
				}
			})
		}
	}
}

func TestTenantBundleReadAndWriteFailures(t *testing.T) {
	for _, failure := range []string{"read", "create", "apply", "deleting"} {
		t.Run(failure, func(t *testing.T) {
			want := "BundleApplyFailed"
			writes := 0
			sentinel := errors.New("fixture API unavailable")
			funcs := interceptor.Funcs{}
			var objects []client.Object
			if failure == "apply" || failure == "deleting" {
				obj := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "test", UID: "live", Labels: map[string]string{"hanko.sh/tenant": "tenant"}}}
				if failure == "deleting" {
					now := metav1.Now()
					obj.DeletionTimestamp = &now
					obj.Finalizers = []string{"fixture/retain"}
				}
				objects = append(objects, obj)
				want = "BundleObjectConflict"
			}
			if failure == "read" {
				funcs.Get = func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
					return sentinel
				}
			}
			funcs.Create = func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				writes++
				return sentinel
			}
			funcs.Apply = func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
				writes++
				return apierrors.NewConflict(schema.GroupResource{Group: "hanko.sh", Resource: "hankorealms"}, "target", sentinel)
			}
			kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
			r := &HankoTenantReconciler{Client: kube}
			counts, err := r.applyBundle(context.Background(), &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}, &hub.Bundle{Realms: []json.RawMessage{json.RawMessage(`{"metadata":{"name":"target"}}`)}})
			if err == nil || bundleApplyReason(err) != want || counts["realms"] != 0 || ((failure == "read" || failure == "deleting") && writes != 0) {
				t.Fatalf("failure not surfaced: counts=%v writes=%d err=%v", counts, writes, err)
			}
		})
	}
}

func TestTenantBundleCreatePreservesExplicitValues(t *testing.T) {
	ctx := context.Background()
	var created *unstructured.Unstructured
	kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Apply: func(_ context.Context, _ client.WithWatch, configuration runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			var options client.ApplyOptions
			options.ApplyOptions(opts)
			if options.Force != nil && *options.Force {
				t.Fatal("initial apply forced ownership")
			}
			data, err := json.Marshal(configuration)
			if err != nil {
				return err
			}
			var desired unstructured.Unstructured
			if err := json.Unmarshal(data, &desired); err != nil {
				return err
			}
			if value, found, err := unstructured.NestedBool(desired.Object, "spec", "otpRequired"); err != nil || !found || value {
				t.Fatal("initial apply lost explicit false")
			}
			return nil
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			var ok bool
			created, ok = obj.DeepCopyObject().(*unstructured.Unstructured)
			if !ok {
				t.Fatal("bundle create is not unstructured")
			}
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	r := &HankoTenantReconciler{Client: kube}
	tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}}
	counts, err := r.applyBundle(ctx, tenant, &hub.Bundle{Realms: []json.RawMessage{json.RawMessage(`{"metadata":{"name":"target","annotations":{"example.org/note":"local"}},"spec":{"otpRequired":false,"securityProfile":{"passwordExpiryDays":0}}}`)}})
	if err != nil || counts["realms"] != 1 {
		t.Fatalf("create: counts=%v err=%v", counts, err)
	}
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(api.GroupVersion.WithKind("HankoRealm"))
	if err := kube.Get(ctx, client.ObjectKey{Namespace: "test", Name: "target"}, obj); err != nil {
		t.Fatal(err)
	}
	if obj.GetLabels()["hanko.sh/tenant"] != "tenant" || obj.GetAnnotations()["example.org/note"] != "local" {
		t.Fatal("created object lost permitted metadata")
	}
	if value, found, err := unstructured.NestedBool(created.Object, "spec", "otpRequired"); err != nil || !found || value {
		t.Fatalf("explicit false lost: %v %v %v", value, found, err)
	}
}
