package controller

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const operationIntentAnnotation = "hanko.sh/operation-intent"

func operationIntentHash(op *api.HankoOperation) string {
	data, _ := json.Marshal(struct {
		Spec   api.HankoOperationSpec
		Tenant string
	}{op.Spec, op.Labels["hanko.sh/tenant"]})
	return string(iamcontract.Hash(iamcontract.Version, "operation", "intent", data))
}

func validateOperationSource(op *api.HankoOperation, instance *api.HankoKeycloakInstance) string {
	if op.UID == "" || instance.UID == "" || !instance.DeletionTimestamp.IsZero() || op.Labels["hanko.sh/tenant"] != instance.Labels["hanko.sh/tenant"] {
		return "operation requires a current instance in the same tenant"
	}
	switch op.Spec.Type {
	case api.OperationUpgrade:
		if op.Spec.Upgrade == nil || op.Spec.Upgrade.ToImage == "" || op.Spec.Clone != nil || op.Spec.DBSwitch != nil {
			return "Upgrade requires only a nonempty upgrade specification"
		}
	case api.OperationDBSwitch:
		if op.Spec.DBSwitch == nil || op.Spec.DBSwitch.NewDatabaseSecretRef == "" || op.Spec.Clone != nil || op.Spec.Upgrade != nil {
			return "DBSwitch requires only a nonempty database specification"
		}
	case api.OperationClone:
		if op.Spec.Clone == nil || op.Spec.Clone.TargetName == "" || op.Spec.Clone.TargetName == instance.Name || op.Spec.Upgrade != nil || op.Spec.DBSwitch != nil {
			return "Clone requires only a distinct target specification"
		}
		if op.Spec.Clone.IncludeData || (op.Spec.Clone.TargetNamespace != "" && op.Spec.Clone.TargetNamespace != op.Namespace) {
			return "Clone supports only same-namespace configuration aliases without data copying"
		}
		return ""
	default:
		return "unsupported operation type"
	}
	if instance.Spec.Mode != "managed" || instance.Spec.Managed == nil {
		return "Upgrade and DBSwitch require a managed instance"
	}
	return ""
}

func validateOperationCheckpoint(op *api.HankoOperation, instance *api.HankoKeycloakInstance) string {
	if op.Status.IntentHash != operationIntentHash(op) || op.Status.StartedGeneration != op.Generation || op.Status.InstanceUID != string(instance.UID) {
		return "operation intent or source identity changed, or the checkpoint predates identity binding"
	}
	expected := initSteps(op.Spec.Type)
	if len(op.Status.Steps) != len(expected) {
		return "operation step inventory differs from its checkpoint"
	}
	pending := false
	for i, step := range op.Status.Steps {
		if step.Name != expected[i].Name || !slices.Contains([]string{"Pending", "Running", "Done", "Skipped", "Failed"}, step.Status) {
			return "operation step inventory differs from its checkpoint"
		}
		if pending && step.Status != "Pending" {
			return "operation steps are out of order"
		}
		pending = pending || (step.Status != "Done" && step.Status != "Skipped")
	}
	return ""
}

// Child creation can succeed even when its acknowledgement or parent checkpoint
// is lost. Recovery accepts only our exact immutable intent and UID provenance.
// Once a UID is checkpointed, a missing/replaced child is never recreated.
func (r *HankoOperationReconciler) operationChild(ctx context.Context, op *api.HankoOperation, step *api.OperationStep, child client.Object) (bool, error) {
	if op.UID == "" || op.Status.IntentHash == "" {
		return false, errors.New("operation child requires a durable identity checkpoint")
	}
	wanted := operationChildSpec(child)
	err := r.operationReader().Get(ctx, client.ObjectKeyFromObject(child), child)
	if client.IgnoreNotFound(err) != nil {
		return false, err
	}
	if err != nil {
		if step.ChildUID != "" {
			return false, errOperationChild
		}
		controller := true
		child.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoOperation", Name: op.Name, UID: op.UID, Controller: &controller}})
		child.SetAnnotations(map[string]string{operationIntentAnnotation: op.Status.IntentHash})
		child.SetLabels(map[string]string{"hanko.sh/tenant": op.Labels["hanko.sh/tenant"]})
		if err := r.Create(ctx, child); err != nil {
			return false, err
		}
	}
	if !operationChildMatches(op, step, child, wanted) {
		return false, errOperationChild
	}
	if step.ChildUID == "" {
		step.ChildUID = string(child.GetUID())
		step.ChildGeneration = child.GetGeneration()
		return false, nil // Persist the accepted identity before using its status.
	}
	return true, nil
}

var errOperationChild = errors.New("operation child ownership, identity or specification differs from the checkpoint")

func operationChildMatches(op *api.HankoOperation, step *api.OperationStep, child client.Object, wanted string) bool {
	owner := metav1.GetControllerOf(child)
	if owner == nil || owner.UID != op.UID || owner.Name != op.Name || owner.Kind != "HankoOperation" || owner.APIVersion != api.GroupVersion.String() {
		return false
	}
	if child.GetUID() == "" || !child.GetDeletionTimestamp().IsZero() || child.GetNamespace() != op.Namespace || child.GetLabels()["hanko.sh/tenant"] != op.Labels["hanko.sh/tenant"] || child.GetAnnotations()[operationIntentAnnotation] != op.Status.IntentHash {
		return false
	}
	if step.ChildUID == "" {
		if child.GetGeneration() != 1 {
			return false
		}
	} else if step.ChildUID != string(child.GetUID()) || step.ChildGeneration != child.GetGeneration() {
		return false
	}
	return operationChildSpec(child) == wanted
}

func operationChildSpec(child client.Object) string {
	var spec any
	switch value := child.(type) {
	case *api.HankoSnapshot:
		spec = value.Spec
	case *api.HankoImport:
		spec = value.Spec
	case *api.HankoKeycloakInstance:
		spec = value.Spec
	default:
		panic("unsupported operation child type")
	}
	data, _ := json.Marshal(spec)
	return string(data)
}

func operationRolloutCurrent(instance *api.HankoKeycloakInstance, deployment *appsv1.Deployment, desired int32) bool {
	owner := metav1.GetControllerOf(deployment)
	if owner == nil || owner.UID != instance.UID || owner.Kind != "HankoKeycloakInstance" || owner.APIVersion != api.GroupVersion.String() || !deployment.DeletionTimestamp.IsZero() {
		return false
	}
	if desired < 1 || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != desired || deployment.Generation < 1 || deployment.Status.ObservedGeneration != deployment.Generation {
		return false
	}
	status := deployment.Status
	if status.UpdatedReplicas != desired || status.ReadyReplicas != desired || status.AvailableReplicas != desired || status.Replicas != desired || status.UnavailableReplicas != 0 {
		return false
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "keycloak" || container.Image != instance.Spec.Managed.Image {
			continue
		}
		for _, env := range container.EnvFrom {
			if env.SecretRef != nil && env.SecretRef.Name == instance.Spec.Managed.Database.Name {
				return true
			}
		}
	}
	return false
}

func operationTargetCurrent(op *api.HankoOperation, instance *api.HankoKeycloakInstance) bool {
	switch op.Spec.Type {
	case api.OperationUpgrade:
		return instance.Spec.Managed != nil && op.Spec.Upgrade != nil && instance.Spec.Managed.Image == op.Spec.Upgrade.ToImage
	case api.OperationDBSwitch:
		return instance.Spec.Managed != nil && op.Spec.DBSwitch != nil && instance.Spec.Managed.Database.Name == op.Spec.DBSwitch.NewDatabaseSecretRef
	default:
		return true
	}
}
