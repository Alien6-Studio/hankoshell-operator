package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/version"
)

func fleetNativeSupport(p keycloak.FleetPermissions) fleetplan.Support {
	apps := applications.KeycloakEvidence().Supported
	qualified := p.Version == "26.7.5" || p.Version == "26.8.0" || p.Version == "26.8.1"
	return fleetplan.Support{Capabilities: map[string]bool{"iam.policy": qualified, "realm.manage": qualified, "realm.identity-providers": qualified, "application.oidc": qualified && apps.OIDC, "application.saml": qualified && apps.SAML && apps.SAMLAssertionSigning, "application.client-roles": qualified && apps.ClientRoles, "application.token-claims": qualified && apps.ProtocolMappers, "service-account.manage": qualified}, Permissions: map[string]bool{"iam.policy": p.ManageRealm && p.ManageEvents, "realm.manage": p.ManageRealm && p.ManageEvents, "realm.identity-providers": p.ManageIdentityProviders, "application.oidc": p.ManageClients, "application.saml": p.ManageClients, "application.client-roles": p.ManageClients, "application.token-claims": p.ManageClients, "service-account.manage": p.ManageClients}}
}

func (r *HankoTenantReconciler) evaluateFleetRollout(ctx context.Context, tenant *api.HankoTenant, verified fleetplan.Verified, localPolicy []byte) (fleetplan.Rollout, time.Time, error) {
	p := verified.Plan()
	if err := fleetplan.CheckOperatorVersion(p, version.Agent); err != nil {
		return fleetplan.Rollout{Objects: fleetplan.Objects(p)}, time.Time{}, err
	}
	objects := fleetplan.Objects(p)
	support := make([]fleetplan.Support, len(objects))
	cache := map[string]fleetplan.Support{}
	var validUntil time.Time
	kc := r.Pool.Get(tenant.Namespace + "/" + tenant.Name)
	approvedVersion := ""
	if kc != nil {
		var err error
		approvedVersion, err = fleetplan.ProviderVersion(localPolicy, p.Target, kc.BaseURL())
		if err != nil {
			return fleetplan.Rollout{Objects: objects}, time.Time{}, err
		}
	}
	for i, o := range objects {
		if o.Kind == "HankoTheme" {
			support[i] = r.themeArtifactSupport(ctx, tenant.Namespace, o)
			continue
		}
		realm := o.RealmRef
		if o.Kind == "HankoIAMProfile" {
			realm = tenant.Spec.RealmRef
		}
		if realm == "" || ((tenant.Spec.IsolationMode == "" || tenant.Spec.IsolationMode == "realm") && realm != tenant.Spec.RealmRef) {
			return fleetplan.Rollout{Objects: objects}, time.Time{}, fleetplan.Refusal("FleetProviderScopeUnknown")
		}
		if cached, ok := cache[realm]; ok {
			support[i] = cached
			continue
		}
		permissions, err := kc.FleetPermissions(ctx, realm)
		if err != nil {
			support[i] = fleetplan.Support{Unavailable: true}
		} else {
			if approvedVersion != "" && permissions.Version != "" && approvedVersion != permissions.Version {
				return fleetplan.Rollout{Objects: objects}, time.Time{}, fleetplan.Refusal("FleetProviderVersionMismatch")
			}
			if permissions.Version == "" {
				permissions.Version = approvedVersion
			}
			support[i] = fleetNativeSupport(permissions)
			if validUntil.IsZero() || permissions.ExpiresAt.Before(validUntil) {
				validUntil = permissions.ExpiresAt
			}
		}
		cache[realm] = support[i]
	}
	rollout, err := fleetplan.Evaluate(verified, version.Agent, support)
	return rollout, validUntil, err
}

func fleetRolloutStatus(tenant *api.HankoTenant, verified fleetplan.Verified, rollout fleetplan.Rollout) *api.FleetRolloutStatus {
	p := verified.Plan()
	bits, _ := json.Marshal(struct {
		Identity string
		Selected []bool
	}{verified.Identity(), rollout.Selected})
	s := &api.FleetRolloutStatus{Identity: verified.Identity(), Sequence: p.Sequence, SelectionHash: string(iamcontract.Hash(iamcontract.Version, "fleet", "selection", bits)), ObservedGeneration: tenant.Generation, State: "Pending", Refused: boundedFleetCount(rollout.Refused), Pending: boundedFleetCount(len(rollout.Objects) - rollout.Refused), Omitted: boundedFleetCount(rollout.Omitted)}
	for _, f := range rollout.Findings {
		s.Findings = append(s.Findings, api.FleetRolloutFinding{Index: boundedFleetCount(f.Index), Reason: f.Reason})
	}
	return s
}

func (r *HankoTenantReconciler) persistFleetDecision(ctx context.Context, tenant *api.HankoTenant, status *api.FleetRolloutStatus) error {
	patch := fleetStatusPatch(tenant)
	tenant.Status.FleetRollout = status
	if err := r.Status().Patch(ctx, tenant, patch); err != nil {
		return fmt.Errorf("%w: %w", errFleetCheckpointWrite, err)
	}
	return nil
}

func fleetRolloutRefusal(tenant *api.HankoTenant, reason string) {
	if reason != "FleetRolloutPaused" && reason != "FleetRolloutRefused" && reason != "FleetRolloutPolicyInvalid" {
		return
	}
	if tenant.Status.FleetRollout == nil {
		tenant.Status.FleetRollout = &api.FleetRolloutStatus{ObservedGeneration: tenant.Generation}
	}
	tenant.Status.FleetRollout.State = "Refused"
	if reason == "FleetRolloutPaused" {
		tenant.Status.FleetRollout.State = "Paused"
	}
}

func fleetRolloutEvidence(tenant *api.HankoTenant) *hub.FleetRolloutEvidence {
	s := tenant.Status.FleetRollout
	if s == nil {
		return nil
	}
	e := &hub.FleetRolloutEvidence{Identity: s.Identity, Sequence: s.Sequence, SelectionHash: s.SelectionHash, ObservedGeneration: s.ObservedGeneration, State: s.State, Applied: s.Applied, Refused: s.Refused, Pending: s.Pending, Omitted: s.Omitted}
	for _, f := range s.Findings {
		e.Findings = append(e.Findings, hub.FleetRolloutFinding{Index: f.Index, Reason: f.Reason})
	}
	return e
}

// Invalid counts must fail API validation instead of silently truncating evidence.
func boundedFleetCount(value int) int32 {
	if value < 0 || value > fleetplan.MaxObjects {
		return -1
	}
	return int32(value)
}
