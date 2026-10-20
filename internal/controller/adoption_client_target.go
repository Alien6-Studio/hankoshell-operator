package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A target-local review already names an exact declaration UID. Passive Observe
// aliases do not choose another owner. Any competing manager, deleting alias or
// pending/malformed approval still holds acquisition. Whole-import discovery
// retains its ambiguous-target refusal and never picks an alias automatically.
func (r *HankoImportReconciler) explicitClientInventoryTarget(ctx context.Context, namespace string, item *adoptionInventoryItem, expected client.Object) client.Object {
	if expected == nil || expected.GetUID() == "" || expected.GetNamespace() != namespace || !inventoryClientMatches(expected, item) {
		return nil
	}
	var apps api.HankoApplicationList
	var accounts api.HankoServiceAccountList
	if r.importReader().List(ctx, &apps, client.InNamespace(namespace)) != nil || r.importReader().List(ctx, &accounts, client.InNamespace(namespace)) != nil {
		return nil
	}
	candidates := make([]client.Object, 0, len(apps.Items)+len(accounts.Items))
	for i := range apps.Items {
		candidates = append(candidates, &apps.Items[i])
	}
	for i := range accounts.Items {
		candidates = append(candidates, &accounts.Items[i])
	}
	var selected client.Object
	for _, peer := range candidates {
		if !inventoryClientMatches(peer, item) {
			continue
		}
		if peer.GetUID() == expected.GetUID() && peer.GetName() == expected.GetName() && adoptionTargetKind(peer) == adoptionTargetKind(expected) {
			selected = peer
			continue
		}
		approval, err := adoption.ParseApproval(peer.GetAnnotations())
		if peer.GetUID() == "" || targetAdoptionMode(peer) != ModeObserve || !peer.GetDeletionTimestamp().IsZero() || err != nil || approval.Requested {
			return nil
		}
	}
	return selected
}

func inventoryClientMatches(object client.Object, item *adoptionInventoryItem) bool {
	switch object := object.(type) {
	case *api.HankoApplication:
		return object.Spec.RealmRef == item.realm && object.Spec.ClientID == item.name
	case *api.HankoServiceAccount:
		return object.Spec.RealmRef == item.realm && object.Spec.ClientID == item.name
	}
	return false
}
