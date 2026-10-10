package controller

import (
	"context"
	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func explicitLeafManage(o client.Object) bool {
	if isImported(o.GetLabels()) {
		return false
	}
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Spec.Mode == ModeManage
	case *api.HankoRole:
		return t.Spec.Mode == ModeManage
	case *api.HankoServiceAccount:
		return t.Spec.Mode == ModeManage
	}
	return false
}

func (s *acquisitionSnapshot) manageQualified(o client.Object) bool {
	values := s.attributes()[adoption.ReceiptKey]
	if len(values) != 1 {
		return false
	}
	proof, err := adoption.ParseReceipt(values[0])
	if err != nil || proof.TargetKind != adoptionTargetKind(o) || proof.TargetUID != string(o.GetUID()) || !s.owned(o) {
		return false
	}
	if s.role != nil {
		return s.role.QualifiedLeaf() && keycloak.QualifiedRoleAttributes(s.role.Role.Attributes)
	}
	return s.client.PreservationQualified()
}

func adoptedCleanupConflict(ctx context.Context, kube client.Client, o client.Object) (ctrl.Result, error) {
	base, ok := o.DeepCopyObject().(client.Object)
	if !ok {
		return ctrl.Result{}, errAdoptionIdentity
	}
	condition := metav1.Condition{Type: "Synced", Status: metav1.ConditionFalse, ObservedGeneration: o.GetGeneration(), Reason: "CleanupConflict", Message: "the current provider dependency boundary does not authorize destructive cleanup"}
	switch target := o.(type) {
	case *api.HankoApplication:
		target.Status.Phase = "Error"
		meta.SetStatusCondition(&target.Status.Conditions, condition)
	case *api.HankoRole:
		target.Status.Phase = "Error"
		meta.SetStatusCondition(&target.Status.Conditions, condition)
	case *api.HankoServiceAccount:
		target.Status.Phase = "Error"
		meta.SetStatusCondition(&target.Status.Conditions, condition)
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, kube.Status().Patch(ctx, o, client.MergeFrom(base))
}
