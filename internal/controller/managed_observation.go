package controller

import (
	"context"
	"errors"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errManagedRolloutPending = errors.New("managed deployment is not a current ready rollout")

func managedDeploymentObservation(ctx context.Context, reader client.Reader, instance *api.HankoKeycloakInstance) (*api.ManagedDeploymentObservation, error) {
	if instance.Spec.Mode != "managed" {
		return nil, nil
	}
	if instance.Spec.Managed == nil {
		return nil, errManagedRolloutPending
	}
	var deployment appsv1.Deployment
	if err := reader.Get(ctx, client.ObjectKeyFromObject(instance), &deployment); err != nil {
		return nil, err
	}
	desired := int32(1)
	if instance.Spec.Managed.Replicas != nil {
		desired = *instance.Spec.Managed.Replicas
	}
	if deployment.UID == "" || !operationRolloutCurrent(instance, &deployment, desired) {
		return nil, errManagedRolloutPending
	}
	return &api.ManagedDeploymentObservation{DeploymentUID: string(deployment.UID), DeploymentGeneration: deployment.Generation}, nil
}

func (r *HankoKeycloakInstanceReconciler) instanceReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *HankoKeycloakInstanceReconciler) deferManagedObservation(ctx context.Context, instance *api.HankoKeycloakInstance, patch client.Patch, cause error) (ctrl.Result, error) {
	instance.Status.Phase = "Probing"
	instance.Status.ManagedObservation = nil
	iamCondition(&instance.Status.Conditions, instance.Generation, "AdminAPIReachable", metav1.ConditionFalse,
		"ManagedRolloutPending", "a stable current managed rollout is required before accepting the Admin API observation")
	if errors.Is(cause, errManagedRolloutPending) {
		cause = nil
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, errors.Join(cause, r.Status().Patch(ctx, instance, patch))
}
