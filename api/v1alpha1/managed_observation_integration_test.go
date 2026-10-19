//go:build integration

package v1alpha1_test

import (
	"context"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Real API storage/generation semantics, with kubelet/provider observations
// explicitly supplied by the fixture. This does not qualify installed rollouts.
func checkManagedOperationObservation(t *testing.T, ctx context.Context, kube client.Client) {
	for _, kind := range []api.HankoOperationType{api.OperationUpgrade, api.OperationDBSwitch} {
		for _, boundary := range []string{"legacy", "rollout", "replacement"} {
			t.Run(string(kind)+"/"+boundary, func(t *testing.T) {
				name := "upgrade-" + boundary
				if kind == api.OperationDBSwitch {
					name = "dbswitch-" + boundary
				}
				op, source := operationAPIFixture(t, ctx, kube, "managed-"+name, false)
				op.Spec.SnapshotBefore = new(bool)
				if kind == api.OperationDBSwitch {
					op.Spec.Type, op.Spec.Upgrade = kind, nil
					op.Spec.DBSwitch = &api.DBSwitchSpec{NewDatabaseSecretRef: "new-database"}
				}
				if err := kube.Update(ctx, op); err != nil {
					t.Fatal(err)
				}
				for range 3 {
					if err := reconcileOperationAPI(ctx, kube, op); err != nil && !apierrors.IsNotFound(err) {
						t.Fatal(err)
					}
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(source), source); err != nil {
					t.Fatal(err)
				}
				control, replicas := true, int32(1)
				labels := map[string]string{"app": source.Name}
				deployment := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: source.Name, Namespace: source.Namespace,
						OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoKeycloakInstance", Name: source.Name, UID: source.UID, Controller: &control}}},
					Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: labels},
						Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "keycloak", Image: source.Spec.Managed.Image,
							EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: source.Spec.Managed.Database}}}}}}}},
				}
				if err := kube.Create(ctx, deployment); err != nil {
					t.Fatal(err)
				}
				setManagedAPIRolloutReady(t, ctx, kube, deployment)
				source.Status.Phase = "Ready"
				source.Status.Conditions = []metav1.Condition{{Type: "AdminAPIReachable", Status: metav1.ConditionTrue, Reason: "ProbeSucceeded", ObservedGeneration: source.Generation, LastTransitionTime: metav1.Now()}}
				if boundary != "legacy" {
					source.Status.ManagedObservation = &api.ManagedDeploymentObservation{DeploymentUID: string(deployment.UID), DeploymentGeneration: deployment.Generation}
				}
				if err := kube.Status().Update(ctx, source); err != nil {
					t.Fatal(err)
				}
				// Persist WaitRollout=Done before the next reconciliation consumes
				// provider evidence. A later rollout cannot inherit this checkpoint.
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
					t.Fatal(err)
				}
				if op.Status.Steps[2].Status != "Done" || op.Status.Phase == "Done" {
					t.Fatal("rollout step did not persist independently of provider validation")
				}
				if boundary == "rollout" {
					deployment.Spec.Template.Annotations = map[string]string{"qualification": "next-generation"}
					if err := kube.Update(ctx, deployment); err != nil {
						t.Fatal(err)
					}
					setManagedAPIRolloutReady(t, ctx, kube, deployment)
				}
				if boundary == "replacement" {
					if err := kube.Delete(ctx, deployment); err != nil {
						t.Fatal(err)
					}
					deployment.ResourceVersion, deployment.UID = "", ""
					if err := kube.Create(ctx, deployment); err != nil {
						t.Fatal(err)
					}
					setManagedAPIRolloutReady(t, ctx, kube, deployment)
				}
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
					t.Fatal(err)
				}
				if op.Status.Phase == "Done" || op.Status.Steps[3].Status != "Running" {
					t.Fatal("legacy or stale provider evidence completed a managed operation")
				}
				source.Status.ManagedObservation = &api.ManagedDeploymentObservation{DeploymentUID: string(deployment.UID), DeploymentGeneration: deployment.Generation}
				if err := kube.Status().Update(ctx, source); err != nil {
					t.Fatal(err)
				}
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil || op.Status.Phase != "Done" {
					t.Fatalf("fresh bound observation did not allow completion: phase=%s err=%v", op.Status.Phase, err)
				}
			})
		}
	}
}

func setManagedAPIRolloutReady(t *testing.T, ctx context.Context, kube client.Client, deployment *appsv1.Deployment) {
	t.Helper()
	deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: deployment.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
	if err := kube.Status().Update(ctx, deployment); err != nil {
		t.Fatal(err)
	}
}
