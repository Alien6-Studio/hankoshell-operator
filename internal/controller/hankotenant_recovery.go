package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const fleetCacheLabel = "hanko.sh/fleet-cache"
const fleetEnvelopeKey = "envelope.json"
const maxFleetCacheBytes = 900 << 10

func (r *HankoTenantReconciler) fleetEnvelope(ctx context.Context, tenant *api.HankoTenant, hubClient *hub.Client) ([]byte, bool, error) {
	var envelope []byte
	err := hub.ErrFleetUnavailable
	if hubClient != nil {
		envelope, err = hubClient.FetchFleetPlan(ctx)
	}
	if err == nil {
		return envelope, false, nil
	}
	if !errors.Is(err, hub.ErrFleetUnavailable) {
		return nil, false, fleetplan.Refusal("FleetPlanFetchFailed")
	}
	if tenant.Status.FleetPlan == nil || tenant.Status.FleetPlan.Cache == nil {
		return nil, false, fleetplan.Refusal("FleetPlanFetchFailed")
	}
	envelope, err = r.readFleetCache(ctx, tenant, tenant.Status.FleetPlan.Cache)
	return envelope, true, err
}

func fleetCacheOwned(cm *corev1.ConfigMap, tenant *api.HankoTenant) bool {
	owner := metav1.GetControllerOf(cm)
	return owner != nil && owner.APIVersion == "hanko.sh/v1alpha1" && owner.Kind == "HankoTenant" &&
		owner.Name == tenant.Name && owner.UID == tenant.UID && cm.Labels[fleetCacheLabel] == string(tenant.UID) &&
		cm.Labels["hanko.sh/tenant"] == tenant.Name && cm.Immutable != nil && *cm.Immutable &&
		cm.UID != "" && cm.DeletionTimestamp.IsZero() && len(cm.BinaryData) == 0 && len(cm.Data) == 1 &&
		len(cm.Data[fleetEnvelopeKey]) > 0 && len(cm.Data[fleetEnvelopeKey]) <= maxFleetCacheBytes
}

func (r *HankoTenantReconciler) readFleetCache(ctx context.Context, tenant *api.HankoTenant, ref *api.FleetPlanReference) ([]byte, error) {
	if ref == nil || ref.Name == "" || ref.UID == "" || ref.Sequence < 1 || ref.AcceptedAt.IsZero() {
		return nil, fleetplan.Refusal("FleetCacheInvalid")
	}
	cm := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKey{Namespace: tenant.Namespace, Name: ref.Name}, cm); err != nil ||
		string(cm.UID) != ref.UID || !fleetCacheOwned(cm, tenant) {
		return nil, fleetplan.Refusal("FleetCacheInvalid")
	}
	return []byte(cm.Data[fleetEnvelopeKey]), nil
}

// Persist immutable signed bytes before acknowledging a new high-water mark.
// A name collision or lost acknowledgement never authorizes overwriting a cache.
func (r *HankoTenantReconciler) retainFleetPlan(ctx context.Context, tenant *api.HankoTenant, verified fleetplan.Verified, envelope, trust []byte) (*api.FleetPlanReference, error) {
	p := verified.Plan()
	if len(envelope) > maxFleetCacheBytes {
		return nil, fleetplan.Refusal("FleetCacheTooLarge")
	}
	if s := tenant.Status.FleetPlan; s != nil && s.Identity == verified.Identity() && s.Cache != nil {
		raw, err := r.readFleetCache(ctx, tenant, s.Cache)
		if err != nil {
			return nil, err
		}
		cached, err := fleetplan.Verify(raw, trust, p.Target, time.Now(), fleetplan.Checkpoint{Sequence: p.Sequence, Identity: verified.Identity()})
		if err != nil || cached.Identity() != verified.Identity() {
			return nil, fleetplan.Refusal("FleetCacheInvalid")
		}
		return s.Cache.DeepCopy(), nil
	}
	digest := sha256.Sum256([]byte(string(tenant.UID) + "\x00" + verified.Identity()))
	immutable := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "hanko-fleet-" + hex.EncodeToString(digest[:])[:48], Namespace: tenant.Namespace,
		Labels:          map[string]string{fleetCacheLabel: string(tenant.UID), "hanko.sh/tenant": tenant.Name},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(tenant, api.GroupVersion.WithKind("HankoTenant"))}},
		Immutable: &immutable, Data: map[string]string{fleetEnvelopeKey: string(envelope)}}
	if err := r.Create(ctx, cm); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fleetplan.Refusal("FleetCacheWriteFailed")
		}
		if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
			return nil, fleetplan.Refusal("FleetCacheWriteFailed")
		}
	}
	if !fleetCacheOwned(cm, tenant) {
		return nil, fleetplan.Refusal("FleetCacheInvalid")
	}
	cached, err := fleetplan.Verify([]byte(cm.Data[fleetEnvelopeKey]), trust, p.Target, time.Now(), fleetplan.Checkpoint{Sequence: p.Sequence, Identity: verified.Identity()})
	if err != nil || cached.Identity() != verified.Identity() {
		return nil, fleetplan.Refusal("FleetCacheInvalid")
	}
	return &api.FleetPlanReference{Name: cm.Name, UID: string(cm.UID), Sequence: p.Sequence, Identity: verified.Identity(), AcceptedAt: metav1.Now()}, nil
}

func (r *HankoTenantReconciler) fleetRollbackReference(ctx context.Context, tenant *api.HankoTenant, verified fleetplan.Verified, trust []byte) (*api.FleetPlanReference, error) {
	if verified.Plan().RollbackOf == "" {
		return nil, nil
	}
	s := tenant.Status.FleetPlan
	if s == nil {
		return nil, fleetplan.Refusal("FleetRollbackReferenceInvalid")
	}
	for _, ref := range []*api.FleetPlanReference{s.PreviousCache, s.RollbackReference} {
		if ref == nil || ref.Identity != verified.Plan().RollbackOf {
			continue
		}
		raw, err := r.readFleetCache(ctx, tenant, ref)
		if err != nil {
			return nil, err
		}
		reference, err := fleetplan.VerifyReference(raw, trust, verified.Plan().Target, time.Now(), ref.AcceptedAt.Time, fleetplan.Checkpoint{Sequence: ref.Sequence, Identity: ref.Identity})
		if err != nil {
			return nil, err
		}
		if err := fleetplan.VerifyRollback(verified, reference); err != nil {
			return nil, err
		}
		return ref.DeepCopy(), nil
	}
	return nil, fleetplan.Refusal("FleetRollbackReferenceInvalid")
}

func fleetRecoveryTime(tenant *api.HankoTenant, identity string) error {
	s := tenant.Status.FleetPlan
	if s == nil || s.Identity != identity {
		return nil
	}
	var verifiedAt time.Time
	if s.VerifiedAt != nil {
		verifiedAt = s.VerifiedAt.Time
	}
	return fleetplan.RecoveryTime(time.Now(), verifiedAt, s.Expired)
}

// Every native administrative mutation rechecks durable authority, including
// old in-flight clients and clients reconstructed before the first Hub request.
func (r *HankoTenantReconciler) fleetProviderAuthority(ctx context.Context, registered *api.HankoTenant) error {
	live := &api.HankoTenant{}
	if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(registered), live); err != nil || live.UID != registered.UID ||
		!live.DeletionTimestamp.IsZero() || !reflect.DeepEqual(live.Spec, registered.Spec) {
		return fleetplan.Refusal("FleetAuthorityChanged")
	}
	s := live.Status.FleetPlan
	if s == nil || s.Cache == nil || s.Cache.Identity != s.Identity || s.Cache.Sequence != s.Sequence {
		return fleetplan.Refusal("FleetCacheInvalid")
	}
	if err := fleetRecoveryTime(live, s.Identity); err != nil {
		return err
	}
	if r.FleetTrustConfigMapName == "" {
		return fleetplan.Refusal("FleetLegacyDowngrade")
	}
	trust := &corev1.ConfigMap{}
	if err := r.tenantReader().Get(ctx, client.ObjectKey{Namespace: live.Namespace, Name: r.FleetTrustConfigMapName}, trust); err != nil ||
		trust.UID == "" || !trust.DeletionTimestamp.IsZero() {
		return fleetplan.Refusal("FleetTrustUnavailable")
	}
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: live.Status.TenantID, ClusterID: live.Status.ClusterID, Namespace: live.Namespace, TenantName: live.Name}, TenantUID: string(live.UID)}
	if err := fleetplan.LocalOverride([]byte(trust.Data["rollout.json"]), target); err != nil {
		return err
	}
	raw, err := r.readFleetCache(ctx, live, s.Cache)
	if err != nil {
		return err
	}
	checkpoint, err := fleetCheckpoint(live)
	if err != nil {
		return err
	}
	verified, err := fleetplan.Verify(raw, []byte(trust.Data["trust.json"]), target, time.Now(), checkpoint)
	if err != nil {
		if fleetplan.Reason(err) == "FleetPlanExpired" && fleetAcceptedExpired(live) && !s.Expired {
			patch := fleetStatusPatch(live)
			s.Expired = true
			if r.Status().Patch(ctx, live, patch) != nil {
				return fleetplan.Refusal("FleetExpiryCheckpointFailed")
			}
		}
		return err
	}
	if verified.Identity() != s.Identity {
		return fleetplan.Refusal("FleetCacheInvalid")
	}
	_, err = r.fleetRollbackReference(ctx, live, verified, []byte(trust.Data["trust.json"]))
	return err
}

func (r *HankoTenantReconciler) reconcileFleetDisconnected(ctx context.Context, tenant *api.HankoTenant) (ctrl.Result, error) {
	_, _, _, err := r.applyFleetPlan(ctx, tenant, nil, tenant.Status.TenantID, tenant.Status.ClusterID)
	if errors.Is(err, errFleetCheckpointWrite) || fleetplan.Reason(err) == "FleetAuthorityChanged" {
		return ctrl.Result{}, err
	}
	return r.fleetDisconnectedStatus(ctx, tenant, err)
}

func (r *HankoTenantReconciler) fleetDisconnectedStatus(ctx context.Context, tenant *api.HankoTenant, err error) (ctrl.Result, error) {
	patch := fleetStatusPatch(tenant)
	reason := "FleetPlanDisconnected"
	if err != nil {
		reason = fleetplan.Reason(err)
	}
	if reason == "FleetPlanExpired" && fleetAcceptedExpired(tenant) {
		tenant.Status.FleetPlan.Expired = true
	}
	// No heartbeat, mesh policy, self-update or decommission call while offline.
	return r.setError(ctx, nil, tenant, patch, reason, fleetplan.Refusal(reason))
}

func fleetAcceptedExpired(tenant *api.HankoTenant) bool {
	return tenant.Status.FleetPlan != nil && !time.Now().Before(tenant.Status.FleetPlan.ExpiresAt.Time)
}

// Only obsolete operator-owned envelope caches are collected, after the durable
// transition. No provider or desired-state object is ever deleted by rollback.
func (r *HankoTenantReconciler) pruneFleetCaches(ctx context.Context, tenant *api.HankoTenant) {
	s := tenant.Status.FleetPlan
	keep := map[string]bool{}
	for _, ref := range []*api.FleetPlanReference{s.Cache, s.PreviousCache, s.RollbackReference} {
		if ref != nil {
			keep[ref.UID] = true
		}
	}
	discard := map[string]bool{}
	for _, entry := range s.Journal {
		digest := sha256.Sum256([]byte(string(tenant.UID) + "\x00" + entry.Identity))
		discard["hanko-fleet-"+hex.EncodeToString(digest[:])[:48]] = true
	}
	var caches corev1.ConfigMapList
	if r.tenantReader().List(ctx, &caches, client.InNamespace(tenant.Namespace), client.MatchingLabels{fleetCacheLabel: string(tenant.UID)}) != nil {
		return
	}
	for i := range caches.Items {
		cm := &caches.Items[i]
		if keep[string(cm.UID)] || !discard[cm.Name] || !fleetCacheOwned(cm, tenant) {
			continue
		}
		// Best effort; later successful reconciles retry a transient failure.
		_ = r.Delete(ctx, cm, client.Preconditions{UID: &cm.UID, ResourceVersion: &cm.ResourceVersion})
	}
}
