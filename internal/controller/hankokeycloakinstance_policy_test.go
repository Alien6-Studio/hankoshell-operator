package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

type policyFailureClient struct {
	client.Client
	resource  string
	operation string
}

func (c policyFailureClient) fails(object client.Object, operation string) bool {
	if operation != c.operation {
		return false
	}
	switch object.(type) {
	case *networkingv1.NetworkPolicy:
		return c.resource == "networkpolicies"
	case *policyv1.PodDisruptionBudget:
		return c.resource == "poddisruptionbudgets"
	}
	return false
}

func (c policyFailureClient) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	if c.fails(object, "create") {
		return apierrors.NewForbidden(schema.GroupResource{Resource: c.resource}, object.GetName(), errors.New("policy write denied"))
	}
	return c.Client.Create(ctx, object, opts...)
}

func (c policyFailureClient) Patch(ctx context.Context, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if c.fails(object, "patch") {
		return errors.New("policy update unavailable")
	}
	return c.Client.Patch(ctx, object, patch, opts...)
}

func TestManagedInstanceRefusesRolloutWhenInfrastructurePoliciesFail(t *testing.T) {
	for _, resource := range []string{"networkpolicies", "poddisruptionbudgets"} {
		for _, operation := range []string{"create", "patch"} {
			t.Run(resource+"/"+operation, func(t *testing.T) {
				ctx := context.Background()
				scheme := controllerTestScheme(t)
				instance := managedTestInstance("test", "keycloak")
				kube := controllerTestClient(scheme, append([]client.Object{instance}, managedTestSecrets(t, instance)...)...)
				reconciler := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
				var original appsv1.Deployment
				if operation == "patch" {
					if err := reconciler.ensureManagedInstancePolicies(ctx, instance); err != nil {
						t.Fatal(err)
					}
					if err := reconciler.ensureDeployment(ctx, instance); err != nil {
						t.Fatal(err)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(instance), &original); err != nil {
						t.Fatal(err)
					}
					instance.Spec.Managed.ThemePVC = "updated-theme"
				}
				reconciler.Client = policyFailureClient{Client: kube, resource: resource, operation: operation}
				result, handled, err := reconciler.reconcileManagedInstance(ctx, instance, client.MergeFrom(instance.DeepCopy()))
				if err != nil || !handled || result.RequeueAfter <= 0 {
					t.Fatalf("policy failure must block and retry: result=%v handled=%v err=%v", result, handled, err)
				}
				var deployment appsv1.Deployment
				deploymentErr := kube.Get(ctx, client.ObjectKeyFromObject(instance), &deployment)
				if operation == "create" && !apierrors.IsNotFound(deploymentErr) {
					t.Fatalf("an unprotected Deployment must not be created: %v", deploymentErr)
				}
				if operation == "patch" && (deploymentErr != nil || !reflect.DeepEqual(original.Spec, deployment.Spec)) {
					t.Fatalf("a policy failure must not update existing pods: %v", deploymentErr)
				}
				var actual hankoshv1alpha1.HankoKeycloakInstance
				if err := kube.Get(ctx, client.ObjectKeyFromObject(instance), &actual); err != nil {
					t.Fatal(err)
				}
				if actual.Status.Phase != "Degraded" || conditionReason(actual.Status.Conditions, "InfrastructureProtected") != "PolicyError" {
					t.Fatalf("policy failure must remain visible: %#v", actual.Status)
				}
			})
		}
	}
}

func TestManagedInstanceScaleDownRemovesStaleDisruptionBudget(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	kube := controllerTestClient(scheme, append([]client.Object{instance}, managedTestSecrets(t, instance)...)...)
	reconciler := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
	if _, handled, err := reconciler.reconcileManagedInstance(ctx, instance, client.MergeFrom(instance.DeepCopy())); err != nil || handled {
		t.Fatalf("initial multi-replica instance: handled=%v err=%v", handled, err)
	}
	*instance.Spec.Managed.Replicas = 1
	if _, handled, err := reconciler.reconcileManagedInstance(ctx, instance, client.MergeFrom(instance.DeepCopy())); err != nil || handled {
		t.Fatalf("scale down must not block drains with a stale PDB: handled=%v err=%v", handled, err)
	}
	var pdb policyv1.PodDisruptionBudget
	if err := kube.Get(ctx, client.ObjectKeyFromObject(instance), &pdb); !apierrors.IsNotFound(err) {
		t.Fatalf("single-replica instance must not retain a drain-blocking PDB: %v", err)
	}
	var deployment appsv1.Deployment
	if err := kube.Get(ctx, client.ObjectKeyFromObject(instance), &deployment); err != nil {
		t.Fatal(err)
	}
	if *deployment.Spec.Replicas != 1 {
		t.Fatalf("Deployment was not scaled down: %#v", deployment.Spec.Replicas)
	}
}
