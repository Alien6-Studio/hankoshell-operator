package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *HankoServiceAccountReconciler) validateServiceAccountExecution(ctx context.Context, sa *api.HankoServiceAccount, kc *keycloak.Client, provider bool) error {
	reader := r.OwnershipReader
	if reader == nil {
		reader = r.APIReader
	}
	if reader == nil {
		reader = r.Client
	}
	if sa.UID == "" || effectiveServiceAccountMode(sa) != ModeManage || !acquisitionTargetUnchanged(ctx, reader, sa) {
		return keycloak.ErrApplicationPrecondition
	}
	if err := r.serviceAccountAcquisitionGuard(ctx, sa, kc); err != nil {
		return err
	}
	for key := range sa.Spec.Attributes {
		if adoption.ReservedAttribute(key) {
			return keycloak.ErrApplicationPrecondition
		}
	}
	if provider {
		return kc.CheckServiceAccountOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID))
	}
	return nil
}

// Used for deletion separately: deleting an Observe resource is not consent.
func acquiredProviderReceipt(ctx context.Context, kc *keycloak.Client, o client.Object) (bool, error) {
	s, err := readAcquisitionSnapshot(ctx, kc, o)
	if err != nil {
		if keycloak.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return s.receiptPresent(), nil
}
