package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
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
	Scheme *runtime.Scheme
}

func (r *HankoOperationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var op hankoshv1alpha1.HankoOperation
	if err := r.Get(ctx, req.NamespacedName, &op); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if op.Status.Phase == "Done" || op.Status.Phase == "Failed" {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFrom(op.DeepCopy())
	now := metav1.Now()

	// DryRun: skip all steps immediately.
	if op.Spec.DryRun {
		op.Status.Phase = "Done"
		op.Status.CompletedAt = &now
		op.Status.Steps = skipAllSteps(initSteps(op.Spec.Type), &now)
		setCondition(&op.Status.Conditions, "Completed", metav1.ConditionTrue, "DryRun", "dry-run: no changes applied")
		_ = r.Status().Patch(ctx, &op, patch)
		return ctrl.Result{}, nil
	}

	// Initialize steps on first reconcile.
	if len(op.Status.Steps) == 0 {
		op.Status.Steps = initSteps(op.Spec.Type)
		op.Status.Phase = "Pending"
		op.Status.StartedAt = &now
		if err := r.Status().Patch(ctx, &op, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}

	// Get the referenced HankoKeycloakInstance.
	var instance hankoshv1alpha1.HankoKeycloakInstance
	if err := r.Get(ctx, types.NamespacedName{Name: op.Spec.InstanceRef, Namespace: op.Namespace}, &instance); err != nil {
		return r.failOp(ctx, &op, patch, &now, "InstanceNotFound",
			fmt.Sprintf("HankoKeycloakInstance %q not found: %v", op.Spec.InstanceRef, err))
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
	if allDone {
		op.Status.Phase = "Done"
		op.Status.CompletedAt = &now
		setCondition(&op.Status.Conditions, "Completed", metav1.ConditionTrue, "AllStepsDone", "all steps completed successfully")
		log.Info("HankoOperation complete", "type", op.Spec.Type)
	}

	op.Status.LastReconciled = &now
	_ = r.Status().Patch(ctx, &op, patch)
	return result, err
}

func (r *HankoOperationReconciler) advanceSteps(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, now *metav1.Time) (ctrl.Result, error) {
	for i := range operation.Status.Steps {
		step := &operation.Status.Steps[i]
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
		return advanceValidationStep(operation, instance, step, now)
	default:
		log.FromContext(ctx).Info("unknown step, skipping", "step", step.Name)
		setStepStatus(step, "Skipped", "unknown step", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
}

func (r *HankoOperationReconciler) advanceSnapshotStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.SnapshotBefore != nil && !*operation.Spec.SnapshotBefore {
		setStepStatus(step, "Skipped", "snapshotBefore=false", now)
		return ctrl.Result{}, true, nil
	}
	name := "op-" + operation.Name + "-snap"
	var snapshot hankoshv1alpha1.HankoSnapshot
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: operation.Namespace}, &snapshot)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if err != nil {
		snapshot = hankoshv1alpha1.HankoSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operation.Namespace},
			Spec:       hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: operation.Spec.InstanceRef, IncludeData: false},
		}
		if err := r.Create(ctx, &snapshot); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("create snapshot: %w", err)
		}
		setStepStatus(step, "Running", "waiting for snapshot", now)
		operation.Status.Phase = "Snapshotting"
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	if snapshot.Status.Phase != "Done" {
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
	patch := client.MergeFrom(instance.DeepCopy())
	instance.Spec.Managed.Image = target
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
	patch := client.MergeFrom(instance.DeepCopy())
	instance.Spec.Managed.Database.Name = operation.Spec.DBSwitch.NewDatabaseSecretRef
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
	namespace := operation.Spec.Clone.TargetNamespace
	if namespace == "" {
		namespace = operation.Namespace
	}
	name := operation.Spec.Clone.TargetName
	var target hankoshv1alpha1.HankoKeycloakInstance
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &target)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if err != nil {
		target = hankoshv1alpha1.HankoKeycloakInstance{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec:       hankoshv1alpha1.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: instance.Spec.AdminRef},
		}
		if err := r.Create(ctx, &target); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("create target instance: %w", err)
		}
	}
	setStepStatus(step, "Done", "target instance created", now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceImportStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if operation.Spec.Clone == nil {
		setStepStatus(step, "Skipped", "no clone spec", now)
		return ctrl.Result{}, true, nil
	}
	name := "op-" + operation.Name + "-import"
	var importOperation hankoshv1alpha1.HankoImport
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: operation.Namespace}, &importOperation)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, err
	}
	if err != nil {
		importOperation = hankoshv1alpha1.HankoImport{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operation.Namespace},
			Spec:       hankoshv1alpha1.HankoImportSpec{SourceRef: operation.Spec.InstanceRef},
		}
		if err := r.Create(ctx, &importOperation); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("create import: %w", err)
		}
		setStepStatus(step, "Running", "waiting for import", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	if importOperation.Status.Phase != "Done" {
		setStepStatus(step, "Running", "import in progress", now)
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	setStepStatus(step, "Done", "config imported", now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func (r *HankoOperationReconciler) advanceRolloutStep(ctx context.Context, operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if instance.Spec.Managed == nil {
		setStepStatus(step, "Skipped", "no managed deployment", now)
		return ctrl.Result{}, true, nil
	}
	var deployment appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, &deployment); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, false, fmt.Errorf("get deployment: %w", err)
	}
	desired := int32(1)
	if instance.Spec.Managed.Replicas != nil {
		desired = *instance.Spec.Managed.Replicas
	}
	if deployment.Status.ReadyReplicas < desired {
		setStepStatus(step, "Running", fmt.Sprintf("waiting: %d/%d ready", deployment.Status.ReadyReplicas, desired), now)
		operation.Status.Phase = "Running"
		return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
	}
	setStepStatus(step, "Done", fmt.Sprintf("all %d replicas ready", desired), now)
	return ctrl.Result{RequeueAfter: requeueOnError}, false, nil
}

func advanceValidationStep(operation *hankoshv1alpha1.HankoOperation, instance *hankoshv1alpha1.HankoKeycloakInstance, step *hankoshv1alpha1.OperationStep, now *metav1.Time) (ctrl.Result, bool, error) {
	if instance.Status.Phase == "Ready" {
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
	setCondition(&op.Status.Conditions, "Completed", metav1.ConditionFalse, reason, msg)
	_ = r.Status().Patch(ctx, op, patch)
	return ctrl.Result{}, fmt.Errorf("%s: %s", reason, msg)
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoOperation{}).
		Complete(r)
}
