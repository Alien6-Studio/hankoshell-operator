package controller

import (
	"context"
	"errors"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errAcquisitionAuthority = errors.New("ownership acquisition authority guard refused")

func (r *HankoApplicationReconciler) applicationAcquisitionGuard(ctx context.Context, o client.Object, kc *keycloak.Client) error {
	app, ok := o.(*api.HankoApplication)
	if !ok || validateApplicationProtocol(app) != nil || validateApplicationAuthorityRoles(app, r.ProtectedRealm) != nil {
		return errAcquisitionAuthority
	}
	if isProtectedControlPlaneApplication(r.ProtectedRealm, r.ProtectedClientIDs, app) || app.Spec.ClientID == kc.CredentialClientID() || keycloakInternalClients[app.Spec.ClientID] {
		return errAcquisitionAuthority
	}
	if err := validateApplicationEffectiveAuthorityRoles(ctx, app, r.ProtectedRealm, r.ProtectedClientIDs, kc); err != nil {
		return err
	}
	_, conflict, err := r.applicationOwnershipConflict(ctx, app, kc)
	if err != nil || conflict != "" {
		return errAcquisitionAuthority
	}
	return nil
}
func (r *HankoRoleReconciler) roleAcquisitionGuard(ctx context.Context, o client.Object, kc *keycloak.Client) error {
	role, ok := o.(*api.HankoRole)
	if !ok || validateStandaloneAuthorityRole(role, r.ProtectedRealm) != nil {
		return errAcquisitionAuthority
	}
	return r.validateRoleAuthority(ctx, role, roles.NewKeycloakDriver(kc))
}
func (r *HankoServiceAccountReconciler) serviceAccountAcquisitionGuard(ctx context.Context, o client.Object, kc *keycloak.Client) error {
	sa, ok := o.(*api.HankoServiceAccount)
	if !ok {
		return errAcquisitionAuthority
	}
	conflict, err := r.serviceAccountOwnershipConflict(ctx, sa, kc)
	if err != nil || conflict != "" {
		return errAcquisitionAuthority
	}
	return nil
}
