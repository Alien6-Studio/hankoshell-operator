package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func (r *HankoResourceServerReconciler) protectedBackingApplication(obj *api.HankoResourceServer, app *api.HankoApplication, kc *keycloak.Client) bool {
	id := strings.TrimSpace(app.Spec.ClientID)
	return keycloakInternalClients[id] || isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, obj.Spec.RealmRef, id) ||
		(kc != nil && id == strings.TrimSpace(kc.CredentialClientID()))
}

func (r *HankoResourceServerReconciler) validateBackingApplication(ctx context.Context, obj *api.HankoResourceServer, app *api.HankoApplication) error {
	if app.UID == "" || !app.DeletionTimestamp.IsZero() || effectiveMode(app) != ModeManage {
		return fmt.Errorf("%w: backing application must be managed", keycloak.ErrAuthorizationOwnershipConflict)
	}
	if app.Status.Phase != "Ready" || app.Status.ObservedGeneration != app.Generation ||
		app.Status.AppliedGeneration != app.Generation || !meta.IsStatusConditionTrue(app.Status.Conditions, "Synced") {
		return iamcontract.ErrStale
	}
	var kc *keycloak.Client
	if r.Pool != nil {
		kc = kcForObject(r.Pool, obj.Namespace, obj.Labels)
	}
	if r.protectedBackingApplication(obj, app, kc) {
		return fmt.Errorf("%w: protected backing application", keycloak.ErrAuthorizationOwnershipConflict)
	}
	// Provider adapters independently enforce this binding at each mutation.
	if kc != nil {
		native, err := kc.GetApplication(ctx, obj.Spec.RealmRef, app.Spec.ClientID)
		if err != nil {
			return err
		}
		if !keycloak.ApplicationOwned(native, string(app.UID)) {
			return keycloak.ErrAuthorizationOwnershipConflict
		}
	}
	return nil
}
