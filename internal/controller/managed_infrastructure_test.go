package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type managedInfrastructureCase struct {
	name   string
	object client.Object
	ensure func(*HankoKeycloakInstanceReconciler, context.Context, *api.HankoKeycloakInstance) error
}

func managedInfrastructureCases() []managedInfrastructureCase {
	return []managedInfrastructureCase{
		{"deployment", &appsv1.Deployment{}, (*HankoKeycloakInstanceReconciler).ensureDeployment},
		{"service", &corev1.Service{}, (*HankoKeycloakInstanceReconciler).ensureService},
		{"networkpolicy", &networkingv1.NetworkPolicy{}, (*HankoKeycloakInstanceReconciler).ensureNetworkPolicy},
		{"pdb-update", &policyv1.PodDisruptionBudget{}, (*HankoKeycloakInstanceReconciler).ensurePDB},
		{"pdb-delete", &policyv1.PodDisruptionBudget{}, (*HankoKeycloakInstanceReconciler).ensurePDB},
	}
}

func managedInfrastructureFixture(t *testing.T, tc managedInfrastructureCase) (*HankoKeycloakInstanceReconciler, *api.HankoKeycloakInstance, client.Object) {
	t.Helper()
	ctx := context.Background()
	instance := managedTestInstance("test", "keycloak")
	backend := controllerTestClient(controllerTestScheme(t), append([]client.Object{instance}, managedTestSecrets(t, instance)...)...)
	r := &HankoKeycloakInstanceReconciler{Client: backend, Scheme: backend.Scheme(), ImageValidator: approvedFixtureValidator(t)}
	if err := tc.ensure(r, ctx, instance); err != nil {
		t.Fatal(err)
	}
	name := instance.Name
	if tc.name == "networkpolicy" {
		name += "-isolation"
	}
	if err := backend.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: name}, tc.object); err != nil {
		t.Fatal(err)
	}
	if tc.name == "pdb-delete" {
		instance.Spec.Managed.Replicas = new(int32(1))
	}
	return r, instance, tc.object
}

func TestManagedInfrastructurePreservesForeignObjects(t *testing.T) {
	for _, tc := range managedInfrastructureCases() {
		for _, authority := range []string{"owned", "unowned", "foreign-uid", "wrong-name", "wrong-kind", "wrong-api", "stale-cache"} {
			t.Run(tc.name+"/"+authority, func(t *testing.T) {
				ctx := context.Background()
				r, instance, object := managedInfrastructureFixture(t, tc)
				backend := r.Client
				cached := object.DeepCopyObject().(client.Object)
				owners := object.GetOwnerReferences()
				switch authority {
				case "unowned":
					owners = nil
				case "foreign-uid", "stale-cache":
					owners[0].UID = "foreign-instance"
				case "wrong-name":
					owners[0].Name = "foreign"
				case "wrong-kind":
					owners[0].Kind = "HankoOperation"
				case "wrong-api":
					owners[0].APIVersion = "foreign.example/v1"
				}
				object.SetOwnerReferences(owners)
				if err := backend.Update(ctx, object); err != nil {
					t.Fatal(err)
				}
				before := object.DeepCopyObject()
				cache := backend
				if authority == "stale-cache" {
					cache = controllerTestClient(backend.Scheme(), append([]client.Object{instance, cached}, managedTestSecrets(t, instance)...)...)
				}
				writes := 0
				r.Client = interceptor.NewClient(cache.(client.WithWatch), interceptor.Funcs{
					Patch: func(ctx context.Context, c client.WithWatch, o client.Object, patch client.Patch, opts ...client.PatchOption) error {
						writes++
						return c.Patch(ctx, o, patch, opts...)
					},
					Delete: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.DeleteOption) error {
						writes++
						return c.Delete(ctx, o, opts...)
					},
				})
				r.APIReader = backend
				err := tc.ensure(r, ctx, instance)
				if authority == "owned" {
					if err != nil || writes != 1 {
						t.Fatalf("owned infrastructure did not reconcile: writes=%d err=%v", writes, err)
					}
					return
				}
				if !errors.Is(err, errManagedInfrastructureOwner) || writes != 0 {
					t.Fatalf("foreign infrastructure was acquired: writes=%d err=%v", writes, err)
				}
				if err := backend.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil || !reflect.DeepEqual(before, object) {
					t.Fatalf("foreign infrastructure changed: %v", err)
				}
			})
		}
	}
}

func TestManagedInfrastructureRejectsConcurrentOwnerChanges(t *testing.T) {
	for _, tc := range managedInfrastructureCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r, instance, object := managedInfrastructureFixture(t, tc)
			backend := r.Client
			switch value := object.(type) {
			case *appsv1.Deployment:
				value.Spec.Replicas = new(int32(1))
			case *corev1.Service:
				value.Spec.Selector = map[string]string{"app": "old"}
			case *networkingv1.NetworkPolicy:
				value.Spec.Ingress = nil
			case *policyv1.PodDisruptionBudget:
				value.Spec.MinAvailable = new(intstr.FromInt32(0))
			}
			if err := backend.Update(ctx, object); err != nil {
				t.Fatal(err)
			}
			var changed client.Object
			changeOwner := func() {
				changed = object.DeepCopyObject().(client.Object)
				if err := backend.Get(ctx, client.ObjectKeyFromObject(object), changed); err != nil {
					t.Fatal(err)
				}
				owners := changed.GetOwnerReferences()
				owners[0].UID = "concurrent-foreign-owner"
				changed.SetOwnerReferences(owners)
				if err := backend.Update(ctx, changed); err != nil {
					t.Fatal(err)
				}
			}
			r.APIReader = backend
			r.Client = interceptor.NewClient(backend.(client.WithWatch), interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, o client.Object, patch client.Patch, opts ...client.PatchOption) error {
					changeOwner()
					return c.Patch(ctx, o, patch, opts...)
				},
				Delete: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.DeleteOption) error {
					changeOwner()
					options := (&client.DeleteOptions{}).ApplyOptions(opts)
					if options.Preconditions == nil || options.Preconditions.UID == nil || options.Preconditions.ResourceVersion == nil {
						t.Error("managed PDB deletion requires UID and resourceVersion preconditions")
					}
					return c.Delete(ctx, o, opts...)
				},
			})
			if err := tc.ensure(r, ctx, instance); !apierrors.IsConflict(err) {
				t.Fatalf("concurrent ownership change did not conflict: %v", err)
			}
			stored := object.DeepCopyObject().(client.Object)
			if err := backend.Get(ctx, client.ObjectKeyFromObject(object), stored); err != nil || !reflect.DeepEqual(changed, stored) {
				t.Fatalf("concurrent foreign object was overwritten or removed: %v", err)
			}
		})
	}
}

func TestManagedInfrastructureRejectsDeletingOrUnknownInstances(t *testing.T) {
	instance := managedTestInstance("test", "keycloak")
	object := readyManagedTestDeployment(instance)
	object.DeletionTimestamp = new(metav1.Now())
	if managedInfrastructureOwned(instance, object) {
		t.Fatal("deleting infrastructure acquired")
	}
	object.DeletionTimestamp = nil
	instance.UID = ""
	object.OwnerReferences[0].UID = ""
	if managedInfrastructureOwned(instance, object) {
		t.Fatal("instance without durable identity acquired infrastructure")
	}
}

func TestDeletingKeycloakInstanceStopsReconciliation(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "stale-cache"}[stale], func(t *testing.T) {
			ctx := context.Background()
			instance := managedTestInstance("test", "keycloak")
			instance.DeletionTimestamp, instance.Finalizers = new(metav1.Now()), []string{"fixture"}
			backend := controllerTestClient(controllerTestScheme(t), instance)
			cache := backend
			if stale {
				active := instance.DeepCopy()
				active.DeletionTimestamp, active.Finalizers = nil, nil
				cache = controllerTestClient(backend.Scheme(), active)
			}
			writes := 0
			wrapped := interceptor.NewClient(cache.(client.WithWatch), interceptor.Funcs{
				SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
					writes++
					return nil
				},
				Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
					writes++
					return nil
				},
			})
			r := &HankoKeycloakInstanceReconciler{Client: wrapped, APIReader: backend, Scheme: backend.Scheme()}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)}); err != nil || writes != 0 {
				t.Fatalf("deleting instance reconciled: writes=%d err=%v", writes, err)
			}
		})
	}
}
