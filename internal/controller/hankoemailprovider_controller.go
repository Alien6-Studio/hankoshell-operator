package controller

import (
	"context"
	"fmt"
	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HankoEmailProviderReconciler invalidates legacy status without resolving
// credentials or sending messages. The CRD is retained for upgrade compatibility.
// Provider configuration and explicit tests belong to the platform API.
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoemailproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoemailproviders/status,verbs=get;update;patch
type HankoEmailProviderReconciler struct{ client.Client }

func (r *HankoEmailProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var provider hankoshv1alpha1.HankoEmailProvider
	if err := r.Get(ctx, req.NamespacedName, &provider); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	phase := "Deprecated"
	if !provider.Spec.Enabled {
		phase = "Disabled"
	}
	condition := meta.FindStatusCondition(provider.Status.Conditions, "DeliveryReady")
	if provider.Status.Phase == phase && provider.Status.ObservedGeneration == provider.Generation &&
		provider.Status.LastPreflight == nil && provider.Status.CredentialVersion == "" &&
		condition != nil && condition.Status == metav1.ConditionFalse &&
		condition.Reason == "DelegatedToAPI" && condition.ObservedGeneration == provider.Generation {
		return ctrl.Result{}, nil
	}
	patch := client.MergeFrom(provider.DeepCopy())
	provider.Status.Phase = phase
	provider.Status.ObservedGeneration = provider.Generation
	provider.Status.LastPreflight = nil
	provider.Status.CredentialVersion = ""
	setCondition(&provider.Status.Conditions, "DeliveryReady", metav1.ConditionFalse,
		"DelegatedToAPI", "Messaging configuration and explicit tests are owned by the hankoShell API; this resource is deprecated")
	condition = meta.FindStatusCondition(provider.Status.Conditions, "DeliveryReady")
	condition.ObservedGeneration = provider.Generation
	if err := r.Status().Patch(ctx, &provider, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("retire legacy email provider status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *HankoEmailProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&hankoshv1alpha1.HankoEmailProvider{}).Complete(r)
}
