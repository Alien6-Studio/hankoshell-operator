package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *fleetUnitFixture) reload(t *testing.T) {
	t.Helper()
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
		t.Fatal(err)
	}
}

func (f *fleetUnitFixture) reason(t *testing.T, expected string) {
	t.Helper()
	f.reload(t)
	if len(f.tenant.Status.Conditions) != 1 || f.tenant.Status.Conditions[0].Reason != expected {
		t.Fatalf("want %s, got %+v", expected, f.tenant.Status.Conditions)
	}
}

func TestFleetDisconnectedRestartAndReconnect(t *testing.T) {
	f := newFleetUnitFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanApplied")
	accepted := f.tenant.Status.FleetPlan.DeepCopy()
	if accepted.Cache == nil || accepted.VerifiedAt == nil || len(accepted.Journal) != 1 {
		t.Fatal("no durable envelope/checkpoint journal")
	}
	f.hubStatus = http.StatusServiceUnavailable
	// Reconstruct controller and pool; no in-memory plan or tenant registration.
	f.r = &HankoTenantReconciler{Client: f.client, APIReader: f.client.Client, Pool: keycloak.NewPool(f.r.Pool.Get("")), HubHTTPClient: f.r.HubHTTPClient, FleetTrustConfigMapName: f.r.FleetTrustConfigMapName}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanDisconnected")
	if f.tenant.Status.FleetPlan.Identity != accepted.Identity || f.client.writes != 1 {
		t.Fatal("offline recovery lost/duplicated content")
	}
	kc := f.r.Pool.Get("auth/tenant")
	if kc == nil {
		t.Fatal("tenant not registered offline")
	}
	if err := kc.UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{}); err != nil {
		t.Fatal(err)
	}
	if f.nativeWrites.Load() != 1 {
		t.Fatal("valid offline authority did not reach provider")
	}
	// A local pause fences even a client obtained before the pause.
	cm := &corev1.ConfigMap{}
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: "fleet-trust"}, cm); err != nil {
		t.Fatal(err)
	}
	policy, _ := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "overrides": []any{map[string]any{"target": f.plan.Target, "action": "pause"}}})
	cm.Data["rollout.json"] = string(policy)
	if err := f.client.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	if fleetplan.Reason(kc.UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{})) != "FleetRolloutPaused" || f.nativeWrites.Load() != 1 {
		t.Fatal("offline local pause bypassed")
	}
	delete(cm.Data, "rollout.json")
	if err := f.client.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	f.hubStatus = 0
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanCurrent")
	f.plan.Sequence = 2
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanApplied")
	if f.tenant.Status.FleetPlan.PreviousCache.Identity != accepted.Identity || len(f.tenant.Status.FleetPlan.Journal) != 2 {
		t.Fatal("new sequence lost history")
	}
	for _, boundary := range []string{"older", "conflict", "wrong-tenant", "tampered"} {
		t.Run(boundary, func(t *testing.T) {
			plan := f.plan
			switch boundary {
			case "older":
				f.plan.Sequence = 1
			case "conflict":
				f.plan.Source.Revision = strings.Repeat("c", 40)
			case "wrong-tenant":
				f.plan.Target.TenantID = "foreign"
			}
			f.sign(t)
			if boundary == "tampered" {
				f.envelope = []byte(`{}`)
			}
			if err := f.reconcile(t); err != nil {
				t.Fatal(err)
			}
			f.reload(t)
			if f.tenant.Status.FleetPlan.Sequence != 2 || f.tenant.Status.FleetPlan.Identity == "" || f.tenant.Status.Phase != "Error" {
				t.Fatal("reconnect replaced checkpoint")
			}
			f.plan = plan
		})
	}
}

func TestFleetProviderAuthorityFailsClosed(t *testing.T) {
	for _, boundary := range []string{"no-plan", "cache-uid", "cache-content", "owner", "trust", "pause", "clock", "expired", "identity", "tenant-changed", "tenant-deleted", "credentials-missing"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFleetUnitFixture(t)
			if boundary != "no-plan" {
				if err := f.reconcile(t); err != nil {
					t.Fatal(err)
				}
				f.reload(t)
			} else {
				if _, err := f.r.registerTenantKeycloak(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
			}
			kc := f.r.Pool.Get("auth/tenant")
			if kc == nil {
				t.Fatal("missing explicit routing")
			}
			s := f.tenant.Status.FleetPlan
			switch boundary {
			case "cache-uid":
				s.Cache.UID = "replacement"
			case "cache-content", "owner":
				cm := &corev1.ConfigMap{}
				if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: s.Cache.Name}, cm); err != nil {
					t.Fatal(err)
				}
				if boundary == "cache-content" {
					cm.Data[fleetEnvelopeKey] = `{}`
				} else {
					cm.OwnerReferences = nil
				}
				// Fake API permits immutable data changes: emulate disk corruption.
				if err := f.client.Update(context.Background(), cm); err != nil {
					t.Fatal(err)
				}
			case "trust", "pause":
				cm := &corev1.ConfigMap{}
				if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: "fleet-trust"}, cm); err != nil {
					t.Fatal(err)
				}
				if boundary == "trust" {
					cm.Data["trust.json"] = `{}`
				} else {
					cm.Data["rollout.json"] = `{}`
				}
				if err := f.client.Update(context.Background(), cm); err != nil {
					t.Fatal(err)
				}
			case "clock":
				at := metav1.NewTime(time.Now().Add(time.Minute))
				s.VerifiedAt = &at
			case "expired":
				s.Expired = true
			case "identity":
				s.Identity = "sha256:" + strings.Repeat("c", 64)
			case "tenant-changed":
				f.tenant.Spec.RealmRef = "foreign"
				if err := f.client.Update(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
			case "tenant-deleted":
				if err := f.client.Delete(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
			case "credentials-missing":
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "hub"}}
				if err := f.client.Delete(context.Background(), secret); err != nil {
					t.Fatal(err)
				}
				if err := f.reconcile(t); err != nil {
					t.Fatal(err)
				}
				f.reason(t, "FleetPlanDisconnected")
			}
			if boundary != "no-plan" && boundary != "tenant-deleted" && boundary != "credentials-missing" {
				if err := f.client.Status().Update(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
			}
			err := kc.UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{})
			if boundary == "credentials-missing" {
				if err != nil || f.nativeWrites.Load() != 1 {
					t.Fatalf("Hub credential loss destroyed valid offline authority: %v", err)
				}
				return
			}
			if err == nil || f.nativeWrites.Load() != 0 {
				t.Fatal("invalid durable authority reached provider")
			}
		})
	}
}

func TestFleetRollbackUsesRetainedVerifiedContent(t *testing.T) {
	f := newFleetUnitFixture(t)
	original := f.plan
	original.Content.Realms = append([]json.RawMessage(nil), f.plan.Content.Realms...)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	first := f.tenant.Status.FleetPlan.Identity
	f.plan.Sequence = 2
	f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), "true", "false", 1))
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	second := f.tenant.Status.FleetPlan.Identity
	f.plan = original
	f.plan.Sequence = 3
	f.plan.RollbackOf = "sha256:" + strings.Repeat("c", 64)
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetRollbackReferenceInvalid")
	if f.tenant.Status.FleetPlan.Identity != second {
		t.Fatal("unverified rollback checkpointed")
	}
	f.plan.RollbackOf = first
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanApplied")
	s := f.tenant.Status.FleetPlan
	if s.Sequence != 3 || s.PreviousIdentity != second || s.RollbackReference == nil || s.RollbackReference.Identity != first || len(s.Journal) != 3 || s.Journal[2].RollbackOf != first {
		t.Fatal("rollback lost monotonic journal/reference")
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanCurrent")
	if len(f.tenant.Status.FleetPlan.Journal) != 3 {
		t.Fatal("replay duplicated journal")
	}
	f.hubStatus = http.StatusServiceUnavailable
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanDisconnected")
}

func TestFleetExpiryBetweenProviderWrites(t *testing.T) {
	f := newFleetUnitFixture(t)
	f.plan.ExpiresAt = time.Now().Add(1500 * time.Millisecond)
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	kc := f.r.Pool.Get("auth/tenant")
	if err := kc.UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(f.plan.ExpiresAt) + 10*time.Millisecond)
	if fleetplan.Reason(kc.UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{})) != "FleetPlanExpired" || f.nativeWrites.Load() != 1 {
		t.Fatal("expiry between writes bypassed")
	}
	f.hubStatus = http.StatusServiceUnavailable
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanExpired")
	if !f.tenant.Status.FleetPlan.Expired {
		t.Fatal("expiry not durable")
	}
}

func TestFleetCacheAcknowledgementAndBoundedRetention(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			f := newFleetUnitFixture(t)
			f.client.cacheFailure = stage
			if err := f.reconcile(t); err != nil {
				t.Fatal(err)
			}
			f.reason(t, "FleetCacheWriteFailed")
			if f.tenant.Status.FleetPlan != nil || f.client.writes != 0 {
				t.Fatal("unacknowledged envelope granted authority")
			}
			if err := f.reconcile(t); err != nil {
				t.Fatal(err)
			}
			f.reason(t, "FleetPlanApplied")
		})
	}
	f := newFleetUnitFixture(t)
	for seq := int64(1); seq <= 19; seq++ {
		f.plan.Sequence = seq
		f.plan.Source.Revision = fmt.Sprintf("%040x", seq)
		f.sign(t)
		if err := f.reconcile(t); err != nil {
			t.Fatal(err)
		}
		f.reload(t)
	}
	s := f.tenant.Status.FleetPlan
	if len(s.Journal) != 16 || s.Journal[0].Sequence != 4 || s.Journal[15].Sequence != 19 {
		t.Fatal("journal did not retain bounded latest transitions")
	}
	var caches corev1.ConfigMapList
	if err := f.client.List(context.Background(), &caches, client.InNamespace("auth"), client.MatchingLabels{fleetCacheLabel: string(f.tenant.UID)}); err != nil {
		t.Fatal(err)
	}
	if len(caches.Items) != 2 {
		t.Fatalf("obsolete accepted caches retained: %d", len(caches.Items))
	}
}

func TestFleetOfflineCacheCannotIntroduceNewSequence(t *testing.T) {
	f := newFleetUnitFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	accepted := f.tenant.Status.FleetPlan.Identity
	cm := &corev1.ConfigMap{}
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: f.tenant.Status.FleetPlan.Cache.Name}, cm); err != nil {
		t.Fatal(err)
	}
	f.plan.Sequence = 2
	f.sign(t)
	cm.Data[fleetEnvelopeKey] = string(f.envelope)
	if err := f.client.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	f.hubStatus = http.StatusServiceUnavailable
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetCacheInvalid")
	if f.tenant.Status.FleetPlan.Identity != accepted || f.tenant.Status.FleetPlan.Sequence != 1 {
		t.Fatal("cache granted a never-accepted plan")
	}
}

func TestFleetExpiredReconnectCannotExpireAcceptedPlan(t *testing.T) {
	f := newFleetUnitFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	accepted := f.tenant.Status.FleetPlan.Identity
	f.plan.Sequence = 2
	f.plan.ExpiresAt = time.Now().Add(-time.Minute)
	f.plan.IssuedAt = f.plan.ExpiresAt.Add(-time.Minute)
	f.plan.NotBefore = f.plan.IssuedAt
	f.sign(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetPlanExpired")
	if f.tenant.Status.FleetPlan.Identity != accepted || f.tenant.Status.FleetPlan.Expired {
		t.Fatal("refused remote expiry poisoned valid local authority")
	}
	if err := f.r.Pool.Get("auth/tenant").UpdateRealm(context.Background(), "fleet-realm", keycloak.RealmSpec{}); err != nil {
		t.Fatal(err)
	}
}
