package controller

import (
	"context"
	"fmt"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// applyInventoryTarget creates Observe inventory only. No owner attribute,
// adoption approval, credential projection or runtime binding is generated.
func (r *HankoImportReconciler) applyInventoryTarget(ctx context.Context, operation *api.HankoImport, item *adoptionInventoryItem) error {
	target, _ := r.currentInventoryTarget(ctx, operation, item)
	if target.UID != "" {
		switch item.kind {
		case "application":
			operation.Status.Skipped.Applications++
		case "service-account":
			operation.Status.Skipped.ServiceAccounts++
		case "role":
			operation.Status.Skipped.Roles++
		}
		return nil
	}
	meta := metav1.ObjectMeta{Namespace: operation.Namespace, Name: importResourceName(item.realm, item.name), Labels: map[string]string{importedByLabel: operation.Name}}
	var object client.Object
	switch {
	case item.app != nil:
		object = &api.HankoApplication{ObjectMeta: meta, Spec: *item.app}
	case item.account != nil:
		if isStaticallyProtectedServiceAccountClient(item.name) || isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, item.realm, item.name) {
			operation.Status.Skipped.ServiceAccounts++
			return nil
		}
		object = &api.HankoServiceAccount{ObjectMeta: meta, Spec: *item.account}
	case item.role != nil:
		object = &api.HankoRole{ObjectMeta: meta, Spec: *item.role}
	default:
		if item.kind == "application" {
			operation.Status.Skipped.Applications++
			return fmt.Errorf("application protocol or semantics cannot be represented safely")
		}
		return nil
	}
	// A generated Kubernetes-name collision is not provider-identity adoption.
	existing, ok := object.DeepCopyObject().(client.Object)
	if !ok {
		return nil
	}
	err := r.importReader().Get(ctx, types.NamespacedName{Namespace: meta.Namespace, Name: meta.Name}, existing)
	if err == nil {
		item.failed("generated_target_name_collision")
		return nil
	}
	if !errors.IsNotFound(err) {
		return err
	}
	if err := r.Create(ctx, object); err != nil {
		return err
	}
	switch item.kind {
	case "application":
		operation.Status.Applied.Applications++
	case "service-account":
		operation.Status.Applied.ServiceAccounts++
	case "role":
		operation.Status.Applied.Roles++
	}
	return nil
}
