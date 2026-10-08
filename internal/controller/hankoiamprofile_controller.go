package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// HankoIAMProfileReconciler validates reusable IAM profiles before realms consume them.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoiamprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoiamprofiles/status,verbs=get;update;patch
type HankoIAMProfileReconciler struct {
	client.Client
}

func (r *HankoIAMProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var profile hankoshv1alpha1.HankoIAMProfile
	if err := r.Get(ctx, req.NamespacedName, &profile); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(profile.DeepCopy())
	profile.Status.ObservedGeneration = profile.Generation

	if err := validateIAMSecurityProfile(&profile.Spec.Security); err != nil {
		profile.Status.Phase = "Error"
		profile.Status.PolicyHash = ""
		profile.Status.LastValidated = nil
		setCondition(&profile.Status.Conditions, "Valid", metav1.ConditionFalse, "InvalidPolicy", err.Error())
		if patchErr := r.Status().Patch(ctx, &profile, patch); patchErr != nil {
			return ctrl.Result{}, fmt.Errorf("patch invalid IAM profile status: %w", patchErr)
		}
		return ctrl.Result{}, nil
	}

	now := metav1.Now()
	profile.Status.Phase = "Ready"
	profile.Status.PolicyHash = hashIAMSecurityProfile(&profile.Spec.Security)
	profile.Status.LastValidated = &now
	setCondition(&profile.Status.Conditions, "Valid", metav1.ConditionTrue, "PolicyValidated", "IAM policy is valid and ready for realm consumption")
	if err := r.Status().Patch(ctx, &profile, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch ready IAM profile status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *HankoIAMProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoIAMProfile{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
