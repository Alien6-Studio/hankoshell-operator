package controller

import (
	"context"
	"errors"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errManagedInfrastructureOwner = errors.New("managed infrastructure is not owned by the current instance; inspect it without forcing acquisition")

func (r *HankoKeycloakInstanceReconciler) readManagedInfrastructure(ctx context.Context, instance *api.HankoKeycloakInstance, name string, object client.Object) error {
	if err := r.instanceReader().Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: name}, object); err != nil {
		return err
	}
	if !managedInfrastructureOwned(instance, object) {
		return errManagedInfrastructureOwner
	}
	return nil
}

func managedInfrastructureOwned(instance *api.HankoKeycloakInstance, object client.Object) bool {
	owner := metav1.GetControllerOf(object)
	return instance.UID != "" && owner != nil && owner.UID == instance.UID && owner.Name == instance.Name &&
		owner.Kind == "HankoKeycloakInstance" && owner.APIVersion == api.GroupVersion.String() &&
		object.GetNamespace() == instance.Namespace && object.GetDeletionTimestamp().IsZero()
}

func managedInfrastructurePatch(before client.Object) client.Patch {
	return client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})
}
