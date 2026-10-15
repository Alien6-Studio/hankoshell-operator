package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	strictjson "sigs.k8s.io/json"
)

var errFleetCheckpointWrite = errors.New("fleet checkpoint write not acknowledged")

func fleetStatusPatch(tenant *api.HankoTenant) client.Patch {
	return client.MergeFromWithOptions(tenant.DeepCopy(), client.MergeFromWithOptimisticLock{})
}

func fleetCheckpoint(tenant *api.HankoTenant) (fleetplan.Checkpoint, error) {
	if tenant.Status.FleetPlan == nil {
		return fleetplan.Checkpoint{}, nil
	}
	s := tenant.Status.FleetPlan
	if s.TenantUID != string(tenant.UID) {
		return fleetplan.Checkpoint{}, fleetplan.Refusal("FleetCheckpointInvalid")
	}
	return fleetplan.Checkpoint{Sequence: s.Sequence, Identity: s.Identity, Applied: s.AppliedIdentity == s.Identity}, nil
}

// applyFleetPlan never uses legacy HMAC after signed mode was locally enabled or
// checkpointed. Content is validated in full before persisting acceptance.
func (r *HankoTenantReconciler) applyFleetPlan(ctx context.Context, tenant *api.HankoTenant, hubClient *hub.Client, tenantID, clusterID string) (string, map[string]int, string, error) {
	if r.FleetTrustConfigMapName == "" {
		return "", nil, "", fleetplan.Refusal("FleetLegacyDowngrade")
	}
	if clusterID == "" || tenant.UID == "" {
		return "", nil, "", fleetplan.Refusal("FleetTargetMismatch")
	}
	trust := &corev1.ConfigMap{}
	trustKey := client.ObjectKey{Namespace: tenant.Namespace, Name: r.FleetTrustConfigMapName}
	if err := r.tenantReader().Get(ctx, trustKey, trust); err != nil {
		return "", nil, "", fleetplan.Refusal("FleetTrustUnavailable")
	}
	if trust.UID == "" || trust.ResourceVersion == "" || !trust.DeletionTimestamp.IsZero() || len(trust.Data["trust.json"]) > fleetplan.MaxTrust {
		return "", nil, "", fleetplan.Refusal("FleetTrustInvalid")
	}
	envelope, err := hubClient.FetchFleetPlan(ctx)
	if err != nil {
		return "", nil, "", fleetplan.Refusal("FleetPlanFetchFailed")
	}
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: tenantID, ClusterID: clusterID, Namespace: tenant.Namespace, TenantName: tenant.Name}, TenantUID: string(tenant.UID)}
	checkpoint, err := fleetCheckpoint(tenant)
	if err != nil {
		return "", nil, "", err
	}
	verified, err := fleetplan.Verify(envelope, []byte(trust.Data["trust.json"]), target, time.Now(), checkpoint)
	if err != nil {
		return "", nil, "", err
	}
	plan := verified.Plan()
	content := plan.Content
	bundle := &hub.Bundle{Version: strconv.FormatInt(plan.Sequence, 10), TenantID: tenantID, IAMProfiles: content.IAMProfiles, Realms: content.Realms, Apps: content.Apps, Themes: content.Themes, ServiceAccounts: content.ServiceAccounts}
	if err := r.preflightFleetContent(ctx, tenant, bundle); err != nil {
		return "", nil, "", err
	}
	// Fence source intent/trust after the network/preflight reads. An unchanged
	// applied plan is still verified against current key authority and time.
	original := tenant.DeepCopy()
	guard := func() error {
		return r.fleetAuthorityCurrent(ctx, original, trust, envelope, target, verified.Identity())
	}
	if err := guard(); err != nil {
		return "", nil, "", err
	}
	if verified.Current() {
		return bundle.Version, fleetContentCounts(content), "FleetPlanCurrent", nil
	}
	if checkpoint.Sequence != plan.Sequence || checkpoint.Identity != verified.Identity() {
		patch := fleetStatusPatch(tenant)
		previous, applied := "", ""
		if tenant.Status.FleetPlan != nil {
			previous = tenant.Status.FleetPlan.Identity
			applied = tenant.Status.FleetPlan.AppliedIdentity
		}
		tenant.Status.FleetPlan = &api.FleetPlanStatus{Sequence: plan.Sequence, Identity: verified.Identity(), PreviousIdentity: previous, AppliedIdentity: applied,
			KeyID: plan.KeyID, TenantUID: string(tenant.UID), ExpiresAt: metav1.NewTime(plan.ExpiresAt)}
		if err := r.Status().Patch(ctx, tenant, patch); err != nil {
			return "", nil, "", fmt.Errorf("%w: %w", errFleetCheckpointWrite, err)
		}
	}
	// Refresh the expected accepted checkpoint; every create/SSA and metadata
	// transition rechecks its exact current authority, expiry and local trust.
	original = tenant.DeepCopy()
	counts, err := r.applyBundleGuarded(ctx, tenant, bundle, guard)
	if err != nil {
		var refusal fleetplan.Refusal
		if errors.As(err, &refusal) {
			return "", counts, "", refusal
		}
		return "", counts, "", fleetplan.Refusal(bundleApplyReason(err))
	}
	if err := guard(); err != nil {
		return "", counts, "", err
	}
	patch := fleetStatusPatch(tenant)
	tenant.Status.FleetPlan.AppliedIdentity = verified.Identity()
	if err := r.Status().Patch(ctx, tenant, patch); err != nil {
		return "", counts, "", fmt.Errorf("%w: %w", errFleetCheckpointWrite, err)
	}
	return bundle.Version, counts, "FleetPlanApplied", nil
}

func fleetContentCounts(content fleetplan.Content) map[string]int {
	return map[string]int{"iamProfiles": len(content.IAMProfiles), "realms": len(content.Realms), "apps": len(content.Apps), "themes": len(content.Themes), "serviceAccounts": len(content.ServiceAccounts)}
}

func (r *HankoTenantReconciler) fleetAuthorityCurrent(ctx context.Context, expected *api.HankoTenant, trust *corev1.ConfigMap, envelope []byte, target fleetplan.Target, identity string) error {
	live := &api.HankoTenant{}
	if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(expected), live); err != nil {
		return fleetplan.Refusal("FleetAuthorityChanged")
	}
	if live.UID != expected.UID || live.Generation != expected.Generation || !live.DeletionTimestamp.IsZero() ||
		!reflect.DeepEqual(live.Spec, expected.Spec) || !reflect.DeepEqual(live.Status.FleetPlan, expected.Status.FleetPlan) {
		return fleetplan.Refusal("FleetAuthorityChanged")
	}
	current := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(trust), current); err != nil || current.UID != trust.UID ||
		current.ResourceVersion != trust.ResourceVersion || !current.DeletionTimestamp.IsZero() {
		return fleetplan.Refusal("FleetTrustChanged")
	}
	checkpoint, err := fleetCheckpoint(live)
	if err != nil {
		return err
	}
	verified, err := fleetplan.Verify(envelope, []byte(current.Data["trust.json"]), target, time.Now(), checkpoint)
	if err != nil {
		return err
	}
	if verified.Identity() != identity {
		return fleetplan.Refusal("FleetAuthorityChanged")
	}
	return nil
}

func (r *HankoTenantReconciler) preflightFleetContent(ctx context.Context, tenant *api.HankoTenant, bundle *hub.Bundle) error {
	objects, err := r.prepareBundle(ctx, tenant, bundle)
	if err != nil {
		return fleetplan.Refusal(bundleApplyReason(err))
	}
	for _, item := range objects {
		typed, err := r.Client.Scheme().New(item.desired.GroupVersionKind())
		if err != nil {
			return fleetplan.Refusal("FleetContentInvalid")
		}
		raw, err := json.Marshal(item.desired.Object)
		if err != nil {
			return fleetplan.Refusal("FleetContentInvalid")
		}
		failures, err := strictjson.UnmarshalStrict(raw, typed)
		if err != nil || len(failures) != 0 {
			return fleetplan.Refusal("FleetContentInvalid")
		}
		candidate := item.desired.DeepCopy()
		if !item.exists {
			err = r.Create(ctx, candidate, client.DryRunAll, client.FieldValidation("Strict"))
		} else {
			candidate = item.current.DeepCopy()
			candidate.Object["spec"] = item.desired.Object["spec"]
			err = r.Update(ctx, candidate, client.DryRunAll, client.FieldValidation("Strict"))
		}
		if err != nil {
			return fleetplan.Refusal("FleetContentInvalid")
		}
	}
	return nil
}

func fleetEvidence(tenant *api.HankoTenant) *hub.FleetPlanEvidence {
	if s := tenant.Status.FleetPlan; s != nil {
		return &hub.FleetPlanEvidence{Sequence: s.Sequence, Identity: s.Identity, AppliedIdentity: s.AppliedIdentity}
	}
	return nil
}
