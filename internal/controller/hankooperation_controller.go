package controller

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// HankoOperationReconciler reconciles HankoOperation objects (one-shot step machine).
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankooperations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankooperations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankooperations/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankosnapshots,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoimports,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch
type HankoOperationReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIReader client.Reader
}

func (r *HankoOperationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var op hankoshv1alpha1.HankoOperation
	if err := r.operationReader().Get(ctx, req.NamespacedName, &op); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if op.Status.Phase == "Done" || op.Status.Phase == "Failed" {
		return ctrl.Result{}, nil
	}
	if !op.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFromWithOptions(op.DeepCopy(), client.MergeFromWithOptimisticLock{})
	now := metav1.Now()

	if (len(op.Status.Steps) > 0) != (op.Status.IntentHash != "") {
		return r.failOp(ctx, &op, patch, &now, "CheckpointRejected", "operation checkpoint is incomplete or predates identity binding")
	}
	if op.Status.IntentHash != "" && (op.Status.IntentHash != operationIntentHash(&op) || op.Status.StartedGeneration != op.Generation) {
		return r.failOp(ctx, &op, patch, &now, "CheckpointRejected", "operation intent changed after execution began")
	}
	// DryRun: skip all steps immediately.
	if op.Spec.DryRun {
		op.Status.Phase = "Done"
		op.Status.CompletedAt = &now
		op.Status.Steps = skipAllSteps(initSteps(op.Spec.Type), &now)
		iamCondition(&op.Status.Conditions, op.Generation, "Completed", metav1.ConditionTrue, "DryRun", "dry-run: no changes applied")
		return ctrl.Result{}, r.Status().Patch(ctx, &op, patch)
	}

	// Get the referenced HankoKeycloakInstance.
	var instance hankoshv1alpha1.HankoKeycloakInstance
	if err := r.operationReader().Get(ctx, types.NamespacedName{Name: op.Spec.InstanceRef, Namespace: op.Namespace}, &instance); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if reason := validateOperationSource(&op, &instance); reason != "" {
		return r.failOp(ctx, &op, patch, &now, "InvalidOperation", reason)
	}
	// Persist authority before creating children or changing the instance.
	if len(op.Status.Steps) == 0 {
		op.Status.Steps = initSteps(op.Spec.Type)
		op.Status.Phase = "Pending"
		op.Status.StartedAt = &now
		op.Status.StartedGeneration = op.Generation
		op.Status.IntentHash = operationIntentHash(&op)
		op.Status.InstanceUID = string(instance.UID)
		return ctrl.Result{RequeueAfter: requeueImmediately}, r.Status().Patch(ctx, &op, patch)
	}
	if reason := validateOperationCheckpoint(&op, &instance); reason != "" {
		return r.failOp(ctx, &op, patch, &now, "CheckpointRejected", reason)
	}

	// Advance the step machine.
	result, err := r.advanceSteps(ctx, &op, &instance, &now)

	// Check terminal states.
	allDone := true
	for _, s := range op.Status.Steps {
		if s.Status == "Failed" {
			return r.failOp(ctx, &op, patch, &now, "StepFailed", fmt.Sprintf("step %q failed: %s", s.Name, s.Message))
		}
		if s.Status != "Done" && s.Status != "Skipped" {
			allDone = false
		}
	}
	if allDone && err == nil {
		op.Status.Phase = "Done"
		op.Status.CompletedAt = &now
		iamCondition(&op.Status.Conditions, op.Generation, "Completed", metav1.ConditionTrue, "AllStepsDone", "all steps completed successfully")
		log.Info("HankoOperation complete", "type", op.Spec.Type)
	}

	op.Status.LastReconciled = &now
	return result, errors.Join(err, r.Status().Patch(ctx, &op, patch))
}

func (r *HankoOperationReconciler) advanceSteps(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, now *metav1.Time) (ctrl.Result, error) {
	for i := range operation.Status.Steps {
		step := &operation.Status.Steps[i]
		if step.Status == "Failed" {
			return ctrl.Result{}, nil
		}
		if step.Status == "Done" || step.Status == "Skipped" {
			continue
		}
		result, processNext, err := r.advanceStep(ctx, operation, instance, step, now)
		if err != nil || !processNext {
			return result, err
		}
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, nil
}

func (r *HankoOperationReconciler) advanceStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	switch step.Name {
	case "Snapshot":
		return r.advanceSnapshotStep(ctx, operation, step, now)
	case "UpdateImage":
		return r.advanceImageStep(ctx, operation, instance, step, now)
	case "UpdateDatabase":
		return r.advanceDatabaseStep(ctx, operation, instance, step, now)
	case "CreateTarget":
		return r.advanceCreateTargetStep(ctx, operation, instance, step, now)
	case "ImportConfig":
		return r.advanceImportStep(ctx, operation, step, now)
	case "WaitRollout":
		return r.advanceRolloutStep(ctx, operation, instance, step, now)
	case "Validate":
		return r.advanceValidationStep(ctx, operation, instance, step, now)
	default:
		setStepStatus(step, "Failed", "unknown operation step", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
}

func (r *HankoOperationReconciler) advanceSnapshotStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.SnapshotBefore != nil && !*operation.Spec.SnapshotBefore {
		setStepStatus(step, "Skipped", "snapshotBefore=false", now)
		return ctrl.Result{}, true, nil
	}
	name := "op-" + operation.Name + "-snap"
	snapshot := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operation.Namespace},
		Spec:       hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: operation.Spec.InstanceRef},
	}
	ready, err := r.operationChild(ctx, operation, step, snapshot)
	if errors.Is(err, errOperationChild) {
		return r.markStepFailed(step, errOperationChild.Error(), now), false, nil
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if snapshot.Status.Phase == "Failed" {
		return r.markStepFailed(step, "snapshot child failed", now), false, nil
	}
	if !ready || snapshot.Status.Phase != "Done" {
		setStepStatus(step, "Running", "snapshot in progress", now)
		operation.Status.Phase = "Snapshotting"
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	operation.Status.SnapshotRef = name
	setStepStatus(step, "Done", "snapshot ready", now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceImageStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.Upgrade == nil {
		setStepStatus(step, "Skipped", "no upgrade spec", now)
		return ctrl.Result{}, true, nil
	}
	if instance.Spec.Managed == nil {
		return r.markStepFailed(step, "instance is not in managed mode", now), false, nil
	}
	target := operation.Spec.Upgrade.ToImage
	if instance.Spec.Managed.Image == target {
		setStepStatus(step, "Done", "image already at target version", now)
		return ctrl.Result{}, true, nil
	}
	patch := client.MergeFromWithOptions(instance.DeepCopy(), client.MergeFromWithOptimisticLock{})
	instance.Spec.Managed.Image = target
	if err := checkLifecycleAuthority(ctx); err != nil {
		return ctrl.Result{}, false, err
	}
	if err := r.Patch(ctx, instance, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("patch instance image: %w", err)
	}
	setStepStatus(step, "Running", fmt.Sprintf("image patched to %s, waiting rollout", target), now)
	operation.Status.Phase = "Running"
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceDatabaseStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.DBSwitch == nil {
		setStepStatus(step, "Skipped", "no dbSwitch spec", now)
		return ctrl.Result{}, true, nil
	}
	if instance.Spec.Managed == nil {
		return r.markStepFailed(step, "instance is not in managed mode", now), false, nil
	}
	if instance.Spec.Managed.Database.Name == operation.Spec.DBSwitch.NewDatabaseSecretRef {
		setStepStatus(step, "Done", "database reference already at target", now)
		return ctrl.Result{}, true, nil
	}
	patch := client.MergeFromWithOptions(instance.DeepCopy(), client.MergeFromWithOptimisticLock{})
	instance.Spec.Managed.Database.Name = operation.Spec.DBSwitch.NewDatabaseSecretRef
	if err := checkLifecycleAuthority(ctx); err != nil {
		return ctrl.Result{}, false, err
	}
	if err := r.Patch(ctx, instance, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("patch instance database: %w", err)
	}
	setStepStatus(step, "Done", "database secret updated", now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceCreateTargetStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.Clone == nil {
		setStepStatus(step, "Skipped", "no clone spec", now)
		return ctrl.Result{}, true, nil
	}
	target := operationCloneTarget(operation, instance)
	ready, err := r.operationChild(ctx, operation, step, target)
	if errors.Is(err, errOperationChild) {
		return r.markStepFailed(step, errOperationChild.Error(), now), false, nil
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if ready {
		setStepStatus(step, "Done", "target instance created", now)
	} else {
		setStepStatus(step, "Running", "target identity checkpointed", now)
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func operationCloneTarget(operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance) *hankoshv1alpha1.HankoKeycloakInstance {
	return &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: operation.Spec.Clone.TargetName, Namespace: operation.Namespace},
		Spec:       hankoshv1alpha1.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: instance.Spec.AdminRef, TLSCARef: instance.Spec.TLSCARef},
	}
}

func (r *HankoOperationReconciler) advanceImportStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.Clone == nil {
		return r.markStepFailed(step, "missing clone specification", now), false, nil
	}
	include := true
	importOperation := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "op-" + operation.Name + "-import", Namespace: operation.Namespace},
		Spec:       hankoshv1alpha1.HankoImportSpec{SourceRef: operation.Spec.InstanceRef, IncludeClients: &include, IncludeServiceAccounts: &include, IncludeIdentityProviders: &include},
	}
	ready, err := r.operationChild(ctx, operation, step, importOperation)
	if errors.Is(err, errOperationChild) {
		return r.markStepFailed(step, errOperationChild.Error(), now), false, nil
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if importOperation.Status.Phase == "Failed" {
		return r.markStepFailed(step, "import child failed", now), false, nil
	}
	if !ready || importOperation.Status.Phase != "Done" {
		setStepStatus(step, "Running", "import in progress", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	condition := meta.FindStatusCondition(importOperation.Status.Conditions, "ImportReady")
	if !importOperation.Status.Coverage.Complete || importOperation.Status.Coverage.Truncated || condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "Completed" {
		return r.markStepFailed(step, "import completed with incomplete coverage or partial failure", now), false, nil
	}
	setStepStatus(step, "Done", "config imported", now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceRolloutStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if !operationTargetCurrent(operation, instance) {
		return r.markStepFailed(step, "instance no longer matches the operation target", now), false, nil
	}
	if instance.Spec.Managed == nil {
		setStepStatus(step, "Skipped", "no managed deployment", now)
		return ctrl.Result{}, true, nil
	}
	var deployment appsv1.Deployment
	if err := r.operationReader().Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, &deployment); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("get deployment: %w", err)
	}
	desired := int32(1)
	if instance.Spec.Managed.Replicas != nil {
		desired = *instance.Spec.Managed.Replicas
	}
	if !operationRolloutCurrent(instance, &deployment, desired) {
		setStepStatus(step, "Running", fmt.Sprintf("waiting: %d/%d ready", deployment.Status.ReadyReplicas, desired), now)
		operation.Status.Phase = "Running"
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	setStepStatus(step, "Done", fmt.Sprintf("all %d replicas ready", desired), now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceValidationStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if !operationTargetCurrent(operation, instance) {
		return r.markStepFailed(step, "instance no longer matches the operation target", now), false, nil
	}
	if operation.Spec.Type == hankoshv1alpha1.OperationClone {
		target := operationCloneTarget(operation, instance)
		var creation *hankoshv1alpha1.OperationStep
		for i := range operation.Status.Steps {
			if operation.Status.Steps[i].Name == "CreateTarget" {
				creation = &operation.Status.Steps[i]
			}
		}
		if creation == nil || creation.ChildUID == "" {
			return r.markStepFailed(step, "missing target identity checkpoint", now), false, nil
		}
		ready, err := r.operationChild(ctx, operation, creation, target)
		if errors.Is(err, errOperationChild) {
			return r.markStepFailed(step, errOperationChild.Error(), now), false, nil
		}
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, false, err
		}
		if !ready {
			return r.markStepFailed(step, "target identity is not current", now), false, nil
		}
		instance = target
	}
	condition := meta.FindStatusCondition(instance.Status.Conditions, "AdminAPIReachable")
	if instance.Status.Phase == "Ready" && condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == instance.Generation && instance.Generation > 0 {
		if instance.Spec.Mode == "managed" {
			current, err := managedDeploymentObservation(ctx, r.operationReader(), instance)
			if err != nil && !errors.Is(err, errManagedRolloutPending) {
				return ctrl.Result{RequeueAfter: requeueOnError}, false, err
			}
			if current == nil || instance.Status.ManagedObservation == nil || *instance.Status.ManagedObservation != *current {
				setStepStatus(step, "Running", "waiting for a provider observation bound to the current managed rollout", now)
				operation.Status.Phase = "Validating"
				return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
			}
		}
		setStepStatus(step, "Done", "instance is Ready", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	setStepStatus(step, "Running", fmt.Sprintf("waiting: instance phase=%s", instance.Status.Phase), now)
	operation.Status.Phase = "Validating"
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) failOp(ctx context.Context, op *hankoshv1alpha1.HankoOperation, patch client.Patch, now *metav1.Time, reason, msg string) (ctrl.Result, error) {
	op.Status.Phase = "Failed"
	op.Status.CompletedAt = now
	iamCondition(&op.Status.Conditions, op.Generation, "Completed", metav1.ConditionFalse, reason, msg)
	return ctrl.Result{}, errors.Join(fmt.Errorf("%s: %s", reason, msg), r.Status().Patch(ctx, op, patch))
}

func (r *HankoOperationReconciler) markStepFailed(step *hankoshv1alpha1.OperationStep, msg string, now *metav1.Time) ctrl.Result {
	setStepStatus(step, "Failed", msg, now)
	return ctrl.Result{RequeueAfter: requeueOnError}
}

func initSteps(opType hankoshv1alpha1.HankoOperationType) []hankoshv1alpha1.OperationStep {
	var names []string
	switch opType {
	case hankoshv1alpha1.OperationUpgrade:
		names = []string{"Snapshot", "UpdateImage", "WaitRollout", "Validate"}
	case hankoshv1alpha1.OperationClone:
		names = []string{"Snapshot", "CreateTarget", "ImportConfig", "Validate"}
	case hankoshv1alpha1.OperationDBSwitch:
		names = []string{"Snapshot", "UpdateDatabase", "WaitRollout", "Validate"}
	default:
		names = []string{"Snapshot", "Validate"}
	}
	steps := make([]hankoshv1alpha1.OperationStep, len(names))
	for i, n := range names {
		steps[i] = hankoshv1alpha1.OperationStep{Name: n, Status: "Pending"}
	}
	return steps
}

func skipAllSteps(steps []hankoshv1alpha1.OperationStep, now *metav1.Time) []hankoshv1alpha1.OperationStep {
	for i := range steps {
		steps[i].Status = "Skipped"
		steps[i].CompletedAt = now
	}
	return steps
}

func setStepStatus(step *hankoshv1alpha1.OperationStep, status, message string, now *metav1.Time) {
	if step.Status == "Pending" && status == "Running" {
		step.StartedAt = now
	}
	if status == "Done" || status == "Failed" || status == "Skipped" {
		step.CompletedAt = now
	}
	step.Status = status
	step.Message = message
}

func (r *HankoOperationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoOperation{}, builder.WithPredicates(generationOrReconcileRequestChanged())).
		Owns(&hankoshv1alpha1.HankoSnapshot{}).
		Owns(&hankoshv1alpha1.HankoImport{}).
		Owns(&hankoshv1alpha1.HankoKeycloakInstance{}).
		Complete(&lifecycleApprovalGuard{Client: r.Client, reader: r.APIReader, inner: r, snapshot: false})
}

func (r *HankoOperationReconciler) operationReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}
