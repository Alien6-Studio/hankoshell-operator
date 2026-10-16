package controller

import (
	"context"
	"fmt"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func tenantScopeLabels(object client.Object) map[string]string {
	if tenant, present := object.GetLabels()["hanko.sh/tenant"]; present {
		return map[string]string{"hanko.sh/tenant": tenant}
	}
	return nil
}

func sameTenantScope(first, second client.Object) bool {
	tenant, present := first.GetLabels()["hanko.sh/tenant"]
	other, otherPresent := second.GetLabels()["hanko.sh/tenant"]
	return present == otherPresent && tenant == other
}

// Tenant-labelled resources must wait for explicit routing even in Observe and
// deletion paths. In particular, retain finalizers until the right provider can
// be reached instead of treating an unavailable tenant as an absent remote object.
func reconcileTenantClient(ctx context.Context, kube client.Client, obj client.Object, kc *keycloak.Client) (bool, ctrl.Result, error) {
	if _, selected := obj.GetLabels()[providerConnectionLabel]; selected {
		result, err := rejectExperimentalResource(ctx, kube, obj)
		return true, result, err
	}
	if _, labelled := obj.GetLabels()["hanko.sh/tenant"]; !labelled || kc != nil {
		return false, ctrl.Result{}, nil
	}
	before, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return true, ctrl.Result{}, fmt.Errorf("cannot copy tenant client guard object %T", obj)
	}
	patch := client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})
	var phase *string
	var observed *int64
	var conditions *[]metav1.Condition
	tracksObservation := false
	switch value := obj.(type) {
	case *api.HankoRealm:
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoApplication:
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.ObservationComplete = false
		value.Status.OIDCEndpoints, value.Status.SAMLEndpoints = nil, nil
		markRuntimePending(value, "TenantClientUnavailable")
		iamCondition(conditions, obj.GetGeneration(), "Operational", metav1.ConditionFalse, "TenantClientUnavailable", "tenant Keycloak client is not registered")
	case *api.HankoServiceAccount:
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoOrganization:
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoRole:
		tracksObservation = true
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.ObservationComplete = false
	case *api.HankoResourceServer:
		tracksObservation = true
		phase, observed, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.ObservationComplete = false
		historicalExplanation(value, "Stale", metav1.ConditionFalse)
	default:
		return true, ctrl.Result{}, fmt.Errorf("unsupported tenant client guard object %T", obj)
	}
	*phase, *observed = "Error", obj.GetGeneration()
	iamCondition(conditions, obj.GetGeneration(), "Synced", metav1.ConditionFalse, "TenantClientUnavailable", "tenant Keycloak client is not registered; waiting for HankoTenant reconciliation")
	if tracksObservation {
		iamCondition(conditions, obj.GetGeneration(), "ObservationSucceeded", metav1.ConditionUnknown, "TenantClientUnavailable", "provider state has not been observed with a registered tenant client")
	}
	if err := kube.Status().Patch(ctx, obj, patch); err != nil {
		return true, ctrl.Result{}, err
	}
	return true, ctrl.Result{RequeueAfter: requeueOnError}, nil
}
