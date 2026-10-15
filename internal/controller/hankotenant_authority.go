package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func fleetTenantTarget(tenant *api.HankoTenant) fleetplan.Target {
	return fleetplan.Target{Scope: fleetplan.Scope{TenantID: tenant.Status.TenantID, ClusterID: tenant.Status.ClusterID, Namespace: tenant.Namespace, TenantName: tenant.Name}, TenantUID: string(tenant.UID)}
}

// Check before any credential rotation, fetch or heartbeat to a changed URL.
func (r *HankoTenantReconciler) fleetHubAuthority(ctx context.Context, tenant *api.HankoTenant) error {
	if tenant.Status.FleetPlan == nil && (tenant.Status.TenantID == "" || tenant.Status.ClusterID == "") {
		return nil
	}
	if r.FleetTrustConfigMapName == "" {
		return fleetplan.Refusal("FleetLegacyDowngrade")
	}
	cm := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKey{Namespace: tenant.Namespace, Name: r.FleetTrustConfigMapName}, cm); err != nil || !cm.DeletionTimestamp.IsZero() {
		return fleetplan.Refusal("FleetTrustUnavailable")
	}
	accepted := ""
	if tenant.Status.FleetPlan != nil {
		accepted = tenant.Status.FleetPlan.HubEndpointHash
	}
	return fleetplan.ApproveHub([]byte(cm.Data["rollout.json"]), fleetTenantTarget(tenant), tenant.Spec.HubEndpoint, accepted)
}

func (r *HankoTenantReconciler) fleetDecommissionAuthority(ctx context.Context, tenant *api.HankoTenant, command *hub.DecommissionCommand) error {
	if err := r.fleetProviderAuthority(ctx, tenant); err != nil {
		return err
	}
	cm := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKey{Namespace: tenant.Namespace, Name: r.FleetTrustConfigMapName}, cm); err != nil || !cm.DeletionTimestamp.IsZero() {
		return fleetplan.Refusal("FleetTrustUnavailable")
	}
	target := fleetTenantTarget(tenant)
	return fleetplan.ApproveDecommission([]byte(cm.Data["rollout.json"]), target, fleetplan.DecommissionIdentity(target, command.RequestedAt, command.Deadline))
}
