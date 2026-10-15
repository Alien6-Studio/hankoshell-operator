package controller

import (
	"context"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func operationChildTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	backend := controllerTestClient(controllerTestScheme(t), objects...)
	return interceptor.NewClient(backend.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			obj.SetUID(uuid.NewUUID())
			obj.SetGeneration(1)
			return c.Create(ctx, obj, opts...)
		},
	})
}

func operationRecoveryFixture() (*api.HankoOperation, *api.HankoKeycloakInstance) {
	instance := managedTestInstance("test", "source")
	instance.UID, instance.Generation = "source-uid", 1
	snapshot := false
	op := &api.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "work", Namespace: "test", UID: "operation-uid", Generation: 1}, Spec: api.HankoOperationSpec{
		Type: api.OperationDBSwitch, InstanceRef: instance.Name, SnapshotBefore: &snapshot,
		DBSwitch: &api.DBSwitchSpec{NewDatabaseSecretRef: "database-v2"},
	}}
	return op, instance
}

func TestOperationCheckpointRejectsChangedAuthority(t *testing.T) {
	op, instance := operationRecoveryFixture()
	op.Status = api.HankoOperationStatus{StartedGeneration: op.Generation, IntentHash: operationIntentHash(op), InstanceUID: string(instance.UID), Steps: initSteps(op.Spec.Type)}
	if reason := validateOperationCheckpoint(op, instance); reason != "" {
		t.Fatal(reason)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*api.HankoOperation, *api.HankoKeycloakInstance)
	}{
		{"spec", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) {
			o.Spec.DBSwitch.NewDatabaseSecretRef = "another"
		}},
		{"generation", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) { o.Generation++ }},
		{"tenant", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) {
			o.Labels = map[string]string{"hanko.sh/tenant": "other"}
		}},
		{"source recreation", func(_ *api.HankoOperation, i *api.HankoKeycloakInstance) { i.UID = "replacement" }},
		{"legacy checkpoint", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) { o.Status.IntentHash = "" }},
		{"unknown step", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) { o.Status.Steps[0].Name = "FutureStep" }},
		{"skipped inventory", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) { o.Status.Steps = o.Status.Steps[1:] }},
		{"out of order", func(o *api.HankoOperation, _ *api.HankoKeycloakInstance) { o.Status.Steps[3].Status = "Done" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, i := op.DeepCopy(), instance.DeepCopy()
			tc.mutate(o, i)
			if validateOperationCheckpoint(o, i) == "" {
				t.Fatal("changed checkpoint accepted")
			}
		})
	}
}

func TestOperationStatusFailuresRemainRetryable(t *testing.T) {
	for _, boundary := range []string{"initial", "dry run", "failure", "after mutation", "after status acknowledgement"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			op, instance := operationRecoveryFixture()
			if boundary == "dry run" {
				op.Spec.DryRun = true
			}
			if boundary == "failure" {
				op.Spec.DBSwitch = nil
			}
			if boundary == "after mutation" || boundary == "after status acknowledgement" {
				op.Status = api.HankoOperationStatus{StartedGeneration: op.Generation, IntentHash: operationIntentHash(op), InstanceUID: string(instance.UID), Steps: initSteps(op.Spec.Type)}
			}
			backend := controllerTestClient(controllerTestScheme(t), op, instance)
			failure := errors.New("injected status failure")
			patches := 0
			failStatus := true
			kube := interceptor.NewClient(backend.(client.WithWatch), interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, o client.Object, patch client.Patch, opts ...client.PatchOption) error {
					patches++
					return c.Patch(ctx, o, patch, opts...)
				},
				SubResourcePatch: func(ctx context.Context, c client.Client, name string, o client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					if !failStatus {
						return c.SubResource(name).Patch(ctx, o, patch, opts...)
					}
					if boundary == "after status acknowledgement" {
						if err := c.SubResource(name).Patch(ctx, o, patch, opts...); err != nil {
							return err
						}
					}
					return failure
				},
			})
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}
			if _, err := (&HankoOperationReconciler{Client: kube}).Reconcile(ctx, request); !errors.Is(err, failure) {
				t.Fatalf("status error lost: %v", err)
			}
			if boundary == "after mutation" || boundary == "after status acknowledgement" {
				if patches != 1 {
					t.Fatalf("instance patches = %d", patches)
				}
				failStatus = false
				if _, err := (&HankoOperationReconciler{Client: kube}).Reconcile(ctx, request); err == nil {
					t.Fatal("missing Deployment must keep rollout unqualified")
				}
				if patches != 1 {
					t.Fatal("restart repeated database mutation")
				}
			} else if patches != 0 {
				t.Fatal("mutation before initial checkpoint")
			}
		})
	}
}

func TestOperationRolloutRequiresOwnedCurrentRevision(t *testing.T) {
	op, instance := operationRecoveryFixture()
	instance.Spec.Managed.Database.Name = op.Spec.DBSwitch.NewDatabaseSecretRef
	two, control := int32(2), true
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace, Generation: 3, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoKeycloakInstance", Name: instance.Name, UID: instance.UID, Controller: &control}}},
		Spec:       appsv1.DeploymentSpec{Replicas: &two, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "keycloak", Image: instance.Spec.Managed.Image, EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: instance.Spec.Managed.Database}}}}}}}},
		Status:     appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2},
	}
	if !operationRolloutCurrent(instance, deployment, two) {
		t.Fatal("current rollout refused")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*appsv1.Deployment)
	}{
		{"old generation", func(d *appsv1.Deployment) { d.Status.ObservedGeneration-- }},
		{"old pods", func(d *appsv1.Deployment) { d.Status.UpdatedReplicas-- }},
		{"unavailable pods", func(d *appsv1.Deployment) { d.Status.AvailableReplicas-- }},
		{"surge pods", func(d *appsv1.Deployment) { d.Status.Replicas++ }},
		{"foreign owner", func(d *appsv1.Deployment) { d.OwnerReferences[0].UID = "foreign" }},
		{"old image", func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "old" }},
		{"old database", func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].EnvFrom = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := deployment.DeepCopy()
			tc.mutate(d)
			if operationRolloutCurrent(instance, d, two) {
				t.Fatal("stale rollout accepted")
			}
		})
	}
	if operationRolloutCurrent(instance, deployment, 0) {
		t.Fatal("zero replica rollout accepted")
	}
}

func TestOperationCompletionNeedsCurrentProviderObservation(t *testing.T) {
	ctx := context.Background()
	op, instance := operationRecoveryFixture()
	instance.Spec.Managed.Database.Name = op.Spec.DBSwitch.NewDatabaseSecretRef
	instance.Generation = 4
	instance.Status.Phase = "Ready"
	iamCondition(&instance.Status.Conditions, 3, "AdminAPIReachable", metav1.ConditionTrue, "ProbeSucceeded", "previous generation")
	deployment := readyManagedTestDeployment(instance)
	backend := controllerTestClient(controllerTestScheme(t), instance, deployment)
	opReconciler := &HankoOperationReconciler{Client: backend}
	step := &api.OperationStep{Name: "Validate", Status: "Pending"}
	now := metav1.Now()
	if _, _, err := opReconciler.advanceValidationStep(ctx, op, instance, step, &now); err != nil || step.Status != "Running" {
		t.Fatal("old provider observation completed the operation")
	}
	instanceReconciler := &HankoKeycloakInstanceReconciler{Client: backend}
	observation, err := managedDeploymentObservation(ctx, backend, instance)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := instanceReconciler.completeKeycloakInstance(ctx, instance, keycloak.New("https://provider.invalid", "", ""), client.MergeFrom(instance.DeepCopy()), "26.8.0", 1, observation); err != nil {
		t.Fatal(err)
	}
	if err := backend.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
		t.Fatal(err)
	}
	if _, _, err := opReconciler.advanceValidationStep(ctx, op, instance, step, &now); err != nil || step.Status != "Done" {
		t.Fatal("current provider observation was not persisted or consumed")
	}
}
