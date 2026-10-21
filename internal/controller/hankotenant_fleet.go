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
	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
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
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: tenantID, ClusterID: clusterID, Namespace: tenant.Namespace, TenantName: tenant.Name}, TenantUID: string(tenant.UID)}
	trust := &corev1.ConfigMap{}
	trustKey := client.ObjectKey{Namespace: tenant.Namespace, Name: r.FleetTrustConfigMapName}
	if err := r.tenantReader().Get(ctx, trustKey, trust); err != nil {
		return "", nil, "", fleetplan.Refusal("FleetTrustUnavailable")
	}
	if trust.UID == "" || trust.ResourceVersion == "" || !trust.DeletionTimestamp.IsZero() || len(trust.Data["trust.json"]) > fleetplan.MaxTrust {
		return "", nil, "", fleetplan.Refusal("FleetTrustInvalid")
	}
	if err := fleetplan.LocalOverride([]byte(trust.Data["rollout.json"]), target); err != nil {
		return "", nil, "", err
	}
	envelope, disconnected, err := r.fleetEnvelope(ctx, tenant, hubClient)
	if err != nil {
		return "", nil, "", err
	}
	checkpoint, err := fleetCheckpoint(tenant)
	if err != nil {
		return "", nil, "", err
	}
	verified, err := fleetplan.Verify(envelope, []byte(trust.Data["trust.json"]), target, time.Now(), checkpoint)
	observability.Default.Verification("fleet", err)
	if err != nil {
		return "", nil, "", err
	}
	if disconnected && (tenant.Status.FleetPlan.Cache.Identity != verified.Identity() || tenant.Status.FleetPlan.Identity != verified.Identity() || tenant.Status.FleetPlan.Cache.Sequence != verified.Plan().Sequence) {
		return "", nil, "", fleetplan.Refusal("FleetCacheInvalid")
	}
	if err := fleetRecoveryTime(tenant, verified.Identity()); err != nil {
		return "", nil, "", err
	}
	rollbackRef, err := r.fleetRollbackReference(ctx, tenant, verified, []byte(trust.Data["trust.json"]))
	if err != nil {
		return "", nil, "", err
	}
	plan := verified.Plan()
	content := plan.Content
	bundle := &hub.Bundle{Version: strconv.FormatInt(plan.Sequence, 10), TenantID: tenantID, IAMProfiles: content.IAMProfiles, Realms: content.Realms, Apps: content.Apps, Themes: content.Themes, ServiceAccounts: content.ServiceAccounts}
	if err := r.preflightFleetContent(ctx, tenant, bundle); err != nil {
		return "", nil, "", err
	}
	rollout, permissionExpiry, evaluationErr := r.evaluateFleetRollout(ctx, tenant, verified, []byte(trust.Data["rollout.json"]))
	decision := fleetRolloutStatus(tenant, verified, rollout)
	original := tenant.DeepCopy()
	guard := func() error {
		if !permissionExpiry.IsZero() && !time.Now().Before(permissionExpiry) {
			return fleetplan.Refusal("FleetPermissionEvidenceExpired")
		}
		return r.fleetAuthorityCurrent(ctx, original, trust, envelope, target, verified.Identity())
	}
	if err := guard(); err != nil {
		return "", nil, "", err
	}
	if evaluationErr != nil {
		decision.State = "Refused"
		if rollout.Selected == nil {
			decision.Refused = boundedFleetCount(len(rollout.Objects))
			decision.Pending = 0
		}
		if err := r.persistFleetDecision(ctx, tenant, decision); err != nil {
			return "", nil, "", err
		}
		return "", nil, "", evaluationErr
	}
	cacheRef, err := r.retainFleetPlan(ctx, tenant, verified, envelope, []byte(trust.Data["trust.json"]))
	if err != nil {
		return "", nil, "", err
	}
	if err := guard(); err != nil {
		return "", nil, "", err
	}
	selected := rollout.Content()
	bundle = &hub.Bundle{Version: bundle.Version, TenantID: tenantID, IAMProfiles: selected.IAMProfiles, Realms: selected.Realms, Apps: selected.Apps, Themes: selected.Themes, ServiceAccounts: selected.ServiceAccounts}
	previousDecision := tenant.Status.FleetRollout
	delivered := verified.Current() || (checkpoint.Sequence == plan.Sequence && checkpoint.Identity == verified.Identity() && previousDecision != nil && previousDecision.Identity == decision.Identity && previousDecision.SelectionHash == decision.SelectionHash && previousDecision.Pending == 0 && (previousDecision.State == "Applied" || previousDecision.State == "Partial"))
	if !delivered || tenant.Status.FleetPlan.Cache == nil {
		patch := fleetStatusPatch(tenant)
		if checkpoint.Sequence != plan.Sequence || checkpoint.Identity != verified.Identity() {
			previous, applied := "", ""
			if tenant.Status.FleetPlan != nil {
				previous = tenant.Status.FleetPlan.Identity
				applied = tenant.Status.FleetPlan.AppliedIdentity
			}
			var previousCache *api.FleetPlanReference
			var journal []api.FleetPlanTransition
			if tenant.Status.FleetPlan != nil {
				previousCache = tenant.Status.FleetPlan.Cache.DeepCopy()
				journal = append(journal, tenant.Status.FleetPlan.Journal...)
			}
			journal = append(journal, api.FleetPlanTransition{Sequence: plan.Sequence, Identity: verified.Identity(), RollbackOf: plan.RollbackOf, AcceptedAt: cacheRef.AcceptedAt})
			if len(journal) > 16 {
				journal = journal[len(journal)-16:]
			}
			tenant.Status.FleetPlan = &api.FleetPlanStatus{Sequence: plan.Sequence, Identity: verified.Identity(), PreviousIdentity: previous, AppliedIdentity: applied, KeyID: plan.KeyID, TenantUID: string(tenant.UID), ExpiresAt: metav1.NewTime(plan.ExpiresAt), Cache: cacheRef, PreviousCache: previousCache, RollbackReference: rollbackRef, Journal: journal}
		}
		tenant.Status.FleetPlan.Cache = cacheRef
		tenant.Status.FleetPlan.HubEndpointHash = fleetplan.EndpointIdentity(tenant.Spec.HubEndpoint)
		verifiedAt := metav1.Now()
		tenant.Status.FleetPlan.VerifiedAt = &verifiedAt
		tenant.Status.FleetRollout = decision
		if err := r.Status().Patch(ctx, tenant, patch); err != nil {
			return "", nil, "", fmt.Errorf("%w: %w", errFleetCheckpointWrite, err)
		}
		original = tenant.DeepCopy()
		if counts, err := r.applyBundleGuarded(ctx, tenant, bundle, guard); err != nil {
			if fleetplan.Reason(err) != "FleetAuthorityChanged" {
				acknowledged := 0
				for _, count := range counts {
					acknowledged += count
				}
				decision.Applied = boundedFleetCount(acknowledged)
				decision.Pending = boundedFleetCount(len(rollout.Objects) - rollout.Refused - acknowledged)
				if statusErr := r.persistFleetDecision(ctx, tenant, decision); statusErr != nil {
					return "", nil, "", statusErr
				}
			}
			var refusal fleetplan.Refusal
			if errors.As(err, &refusal) {
				return "", nil, "", refusal
			}
			return "", nil, "", fleetplan.Refusal(bundleApplyReason(err))
		}
	}
	if err := guard(); err != nil {
		return "", nil, "", err
	}
	patch := fleetStatusPatch(tenant)
	decision.Applied, decision.Pending = boundedFleetCount(len(rollout.Objects)-rollout.Refused), 0
	decision.State = "Applied"
	reason := "FleetPlanApplied"
	if delivered {
		reason = "FleetPlanCurrent"
	}
	if decision.Refused > 0 {
		decision.State, reason = "Partial", "FleetPlanPartial"
	} else {
		tenant.Status.FleetPlan.AppliedIdentity = verified.Identity()
	}
	verifiedAt := metav1.Now()
	tenant.Status.FleetPlan.VerifiedAt = &verifiedAt
	tenant.Status.FleetPlan.HubEndpointHash = fleetplan.EndpointIdentity(tenant.Spec.HubEndpoint)
	tenant.Status.FleetRollout = decision
	if err := r.Status().Patch(ctx, tenant, patch); err != nil {
		return "", nil, "", fmt.Errorf("%w: %w", errFleetCheckpointWrite, err)
	}
	if disconnected {
		reason = "FleetPlanDisconnected"
	}
	r.pruneFleetCaches(ctx, tenant)
	return bundle.Version, fleetContentCounts(selected), reason, nil
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
	if err := fleetRecoveryTime(live, identity); err != nil {
		return err
	}
	current := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(trust), current); err != nil || current.UID != trust.UID || !current.DeletionTimestamp.IsZero() {
		return fleetplan.Refusal("FleetTrustChanged")
	}
	if err := fleetplan.LocalOverride([]byte(current.Data["rollout.json"]), target); err != nil {
		return err
	}
	if current.ResourceVersion != trust.ResourceVersion {
		return fleetplan.Refusal("FleetTrustChanged")
	}
	checkpoint, err := fleetCheckpoint(live)
	if err != nil {
		return err
	}
	verified, err := fleetplan.Verify(envelope, []byte(current.Data["trust.json"]), target, time.Now(), checkpoint)
	observability.Default.Verification("fleet", err)
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
