package controller

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestOperationPendingAndSkippedTransitions(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	now := metav1.Now()

	t.Run("snapshot disabled", func(t *testing.T) {
		disabled := false
		operation := &hankoshv1alpha1.HankoOperation{Spec: hankoshv1alpha1.HankoOperationSpec{SnapshotBefore: &disabled}}
		step := &hankoshv1alpha1.OperationStep{Name: "Snapshot", Status: "Pending"}
		reconciler := &HankoOperationReconciler{Client: controllerTestClient(scheme), Scheme: scheme}
		_, next, err := reconciler.advanceSnapshotStep(ctx, operation, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("disabled snapshot transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("snapshot created then running", func(t *testing.T) {
		operation := &hankoshv1alpha1.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "test"}, Spec: hankoshv1alpha1.HankoOperationSpec{InstanceRef: "source"}}
		k8sClient := controllerTestClient(scheme)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		step := &hankoshv1alpha1.OperationStep{Name: "Snapshot", Status: "Pending"}
		_, next, err := reconciler.advanceSnapshotStep(ctx, operation, step, &now)
		if err != nil || next || step.Status != "Running" || operation.Status.Phase != "Snapshotting" {
			t.Fatalf("create snapshot transition: next=%t step=%#v err=%v", next, step, err)
		}
		step = &hankoshv1alpha1.OperationStep{Name: "Snapshot", Status: "Pending"}
		_, next, err = reconciler.advanceSnapshotStep(ctx, operation, step, &now)
		if err != nil || next || step.Message != "snapshot in progress" {
			t.Fatalf("running snapshot transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("image transitions", func(t *testing.T) {
		instance := managedTestInstance("test", "source")
		k8sClient := controllerTestClient(scheme, instance)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		step := &hankoshv1alpha1.OperationStep{Name: "UpdateImage"}
		_, next, err := reconciler.advanceImageStep(ctx, &hankoshv1alpha1.HankoOperation{}, instance, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("missing image spec: next=%t step=%#v err=%v", next, step, err)
		}
		operation := &hankoshv1alpha1.HankoOperation{Spec: hankoshv1alpha1.HankoOperationSpec{Upgrade: &hankoshv1alpha1.UpgradeSpec{ToImage: "quay.io/keycloak/keycloak:26.1"}}}
		unmanaged := instance.DeepCopy()
		unmanaged.Spec.Managed = nil
		step = &hankoshv1alpha1.OperationStep{Name: "UpdateImage"}
		_, next, err = reconciler.advanceImageStep(ctx, operation, unmanaged, step, &now)
		if err != nil || next || step.Status != "Failed" {
			t.Fatalf("unmanaged image update: next=%t step=%#v err=%v", next, step, err)
		}
		step = &hankoshv1alpha1.OperationStep{Name: "UpdateImage"}
		_, next, err = reconciler.advanceImageStep(ctx, operation, instance, step, &now)
		if err != nil || next || step.Status != "Running" || operation.Status.Phase != "Running" {
			t.Fatalf("image patch transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("database transitions", func(t *testing.T) {
		instance := managedTestInstance("test", "database")
		k8sClient := controllerTestClient(scheme, instance)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		step := &hankoshv1alpha1.OperationStep{Name: "UpdateDatabase"}
		_, next, err := reconciler.advanceDatabaseStep(ctx, &hankoshv1alpha1.HankoOperation{}, instance, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("missing database spec: next=%t step=%#v err=%v", next, step, err)
		}
		operation := &hankoshv1alpha1.HankoOperation{Spec: hankoshv1alpha1.HankoOperationSpec{DBSwitch: &hankoshv1alpha1.DBSwitchSpec{NewDatabaseSecretRef: "database-v2"}}}
		unmanaged := instance.DeepCopy()
		unmanaged.Spec.Managed = nil
		step = &hankoshv1alpha1.OperationStep{Name: "UpdateDatabase"}
		_, next, err = reconciler.advanceDatabaseStep(ctx, operation, unmanaged, step, &now)
		if err != nil || next || step.Status != "Failed" {
			t.Fatalf("unmanaged database update: next=%t step=%#v err=%v", next, step, err)
		}
		step = &hankoshv1alpha1.OperationStep{Name: "UpdateDatabase"}
		_, next, err = reconciler.advanceDatabaseStep(ctx, operation, instance, step, &now)
		if err != nil || next || step.Status != "Done" {
			t.Fatalf("database patch transition: next=%t step=%#v err=%v", next, step, err)
		}
	})
}

func TestOperationCloneRolloutAndValidationTransitions(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	now := metav1.Now()
	instance := managedTestInstance("test", "source")

	t.Run("clone target", func(t *testing.T) {
		k8sClient := controllerTestClient(scheme, instance)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		step := &hankoshv1alpha1.OperationStep{Name: "CreateTarget"}
		_, next, err := reconciler.advanceCreateTargetStep(ctx, &hankoshv1alpha1.HankoOperation{}, instance, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("missing clone spec: next=%t step=%#v err=%v", next, step, err)
		}
		operation := &hankoshv1alpha1.HankoOperation{
			ObjectMeta: metav1.ObjectMeta{Name: "clone", Namespace: "test"},
			Spec:       hankoshv1alpha1.HankoOperationSpec{Clone: &hankoshv1alpha1.CloneSpec{TargetName: "target", TargetNamespace: "target-ns"}},
		}
		step = &hankoshv1alpha1.OperationStep{Name: "CreateTarget"}
		_, next, err = reconciler.advanceCreateTargetStep(ctx, operation, instance, step, &now)
		if err != nil || next || step.Status != "Done" {
			t.Fatalf("create target transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("import created then running", func(t *testing.T) {
		k8sClient := controllerTestClient(scheme)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		step := &hankoshv1alpha1.OperationStep{Name: "ImportConfig"}
		_, next, err := reconciler.advanceImportStep(ctx, &hankoshv1alpha1.HankoOperation{}, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("missing clone import: next=%t step=%#v err=%v", next, step, err)
		}
		operation := &hankoshv1alpha1.HankoOperation{
			ObjectMeta: metav1.ObjectMeta{Name: "clone", Namespace: "test"},
			Spec: hankoshv1alpha1.HankoOperationSpec{
				InstanceRef: "source", Clone: &hankoshv1alpha1.CloneSpec{TargetName: "target"},
			},
		}
		step = &hankoshv1alpha1.OperationStep{Name: "ImportConfig"}
		_, next, err = reconciler.advanceImportStep(ctx, operation, step, &now)
		if err != nil || next || step.Status != "Running" {
			t.Fatalf("create import transition: next=%t step=%#v err=%v", next, step, err)
		}
		step = &hankoshv1alpha1.OperationStep{Name: "ImportConfig"}
		_, next, err = reconciler.advanceImportStep(ctx, operation, step, &now)
		if err != nil || next || step.Message != "import in progress" {
			t.Fatalf("running import transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("rollout waits and unmanaged skips", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: 1},
		}
		k8sClient := controllerTestClient(scheme, deployment)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		operation := &hankoshv1alpha1.HankoOperation{}
		step := &hankoshv1alpha1.OperationStep{Name: "WaitRollout"}
		_, next, err := reconciler.advanceRolloutStep(ctx, operation, instance, step, &now)
		if err != nil || next || step.Status != "Running" || !strings.Contains(step.Message, "1/2") {
			t.Fatalf("partial rollout transition: next=%t step=%#v err=%v", next, step, err)
		}
		unmanaged := instance.DeepCopy()
		unmanaged.Spec.Managed = nil
		step = &hankoshv1alpha1.OperationStep{Name: "WaitRollout"}
		_, next, err = reconciler.advanceRolloutStep(ctx, operation, unmanaged, step, &now)
		if err != nil || !next || step.Status != "Skipped" {
			t.Fatalf("unmanaged rollout transition: next=%t step=%#v err=%v", next, step, err)
		}
	})

	t.Run("validation and unknown step", func(t *testing.T) {
		operation := &hankoshv1alpha1.HankoOperation{}
		step := &hankoshv1alpha1.OperationStep{Name: "Validate"}
		_, next, err := advanceValidationStep(operation, instance, step, &now)
		if err != nil || next || step.Status != "Running" || operation.Status.Phase != "Validating" {
			t.Fatalf("validation wait: next=%t step=%#v err=%v", next, step, err)
		}
		reconciler := &HankoOperationReconciler{Client: controllerTestClient(scheme), Scheme: scheme}
		unknown := &hankoshv1alpha1.OperationStep{Name: "FutureStep"}
		_, next, err = reconciler.advanceStep(ctx, operation, instance, unknown, &now)
		if err != nil || next || unknown.Status != "Skipped" {
			t.Fatalf("unknown step transition: next=%t step=%#v err=%v", next, unknown, err)
		}
	})
}

func TestOperationAdvanceAndFailureBookkeeping(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	now := metav1.Now()
	instance := managedTestInstance("test", "source")
	reconciler := &HankoOperationReconciler{Client: controllerTestClient(scheme), Scheme: scheme}
	operation := &hankoshv1alpha1.HankoOperation{
		Status: hankoshv1alpha1.HankoOperationStatus{Steps: []hankoshv1alpha1.OperationStep{
			{Name: "Snapshot", Status: "Done"}, {Name: "Validate", Status: "Skipped"}, {Name: "FutureStep", Status: "Pending"},
		}},
	}
	if _, err := reconciler.advanceSteps(ctx, operation, instance, &now); err != nil {
		t.Fatalf("advance mixed steps: %v", err)
	}
	if operation.Status.Steps[2].Status != "Skipped" {
		t.Fatalf("unknown step was not checkpointed: %#v", operation.Status.Steps)
	}

	stored := &hankoshv1alpha1.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "test"}}
	k8sClient := controllerTestClient(scheme, stored)
	reconciler.Client = k8sClient
	_, err := reconciler.failOp(ctx, stored, client.MergeFrom(stored.DeepCopy()), &now, "TestFailure", "expected failure")
	if err == nil || !strings.Contains(err.Error(), "TestFailure") || stored.Status.Phase != "Failed" {
		t.Fatalf("failure bookkeeping: status=%#v err=%v", stored.Status, err)
	}
}
