//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkFleetDisconnectedRecovery(t *testing.T, ctx context.Context, kube client.Client) {
	t.Run("restart-local-pause-and-cache-integrity", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "offline-restart")
		f.expect(t, ctx, "FleetPlanApplied")
		s := f.tenant.Status.FleetPlan.DeepCopy()
		cache := &corev1.ConfigMap{}
		if err := kube.Get(ctx, client.ObjectKey{Namespace: f.tenant.Namespace, Name: s.Cache.Name}, cache); err != nil {
			t.Fatal(err)
		}
		if cache.Immutable == nil || !*cache.Immutable || string(cache.UID) != s.Cache.UID {
			t.Fatal("cache not durable/immutable")
		}
		cache.Data["envelope.json"] = `{}`
		if err := kube.Update(ctx, cache); !apierrors.IsInvalid(err) {
			t.Fatalf("API admitted immutable cache edit: %v", err)
		}
		f.hubStatus.Store(http.StatusServiceUnavailable)
		f.r = &controller.HankoTenantReconciler{Client: f.writer, APIReader: kube, Pool: keycloak.NewPool(f.r.Pool.Get("")), HubHTTPClient: f.r.HubHTTPClient, FleetTrustConfigMapName: f.r.FleetTrustConfigMapName}
		if err := f.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
			t.Fatal(err)
		}
		if f.tenant.Status.Phase != "Error" || f.tenant.Status.Conditions[0].Reason != "FleetPlanDisconnected" || f.tenant.Status.FleetPlan.Identity != s.Identity {
			t.Fatal("restart did not recover exact accepted plan")
		}
		kc := f.r.Pool.Get(f.tenant.Namespace + "/" + f.tenant.Name)
		if kc == nil {
			t.Fatal("restart did not register tenant client")
		}
		if err := kc.UpdateRealm(ctx, f.tenant.Name, keycloak.RealmSpec{}); err != nil {
			t.Fatal(err)
		}
		f.override(t, ctx, "pause")
		if fleetplan.Reason(kc.UpdateRealm(ctx, f.tenant.Name, keycloak.RealmSpec{})) != "FleetRolloutPaused" || f.nativeWrites.Load() != 1 {
			t.Fatal("offline local pause bypassed")
		}
		f.override(t, ctx, "allow")
		// Replacing an immutable ConfigMap with valid-looking metadata loses UID.
		if err := kube.Get(ctx, client.ObjectKeyFromObject(cache), cache); err != nil {
			t.Fatal(err)
		}
		if err := kube.Delete(ctx, cache); err != nil {
			t.Fatal(err)
		}
		cache.ResourceVersion = ""
		cache.UID = ""
		cache.CreationTimestamp = metav1.Time{}
		cache.ManagedFields = nil
		if err := kube.Create(ctx, cache); err != nil {
			t.Fatal(err)
		}
		if fleetplan.Reason(kc.UpdateRealm(ctx, f.tenant.Name, keycloak.RealmSpec{})) != "FleetCacheInvalid" || f.nativeWrites.Load() != 1 {
			t.Fatal("replaced cache reached provider")
		}
	})
	t.Run("versioned-rollback-preserves-foreign-and-omitted-objects", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "offline-rollback")
		original := f.plan
		original.Content.Realms = append([]json.RawMessage(nil), f.plan.Content.Realms...)
		f.expect(t, ctx, "FleetPlanApplied")
		first := f.tenant.Status.FleetPlan.Identity
		foreign := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "rollback-foreign", Namespace: f.tenant.Namespace, Labels: map[string]string{"hanko.sh/tenant": "foreign"}}, Spec: api.HankoApplicationSpec{RealmRef: f.tenant.Name, ClientID: "foreign"}}
		if err := kube.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		f.plan.Sequence = 2
		f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), "true", "false", 1))
		f.addApplication()
		f.sign(t)
		f.expect(t, ctx, "FleetPlanApplied")
		second := f.tenant.Status.FleetPlan.Identity
		f.plan = original
		f.plan.Sequence = 3
		f.plan.RollbackOf = "sha256:" + strings.Repeat("c", 64)
		f.sign(t)
		f.expect(t, ctx, "FleetRollbackReferenceInvalid")
		if f.tenant.Status.FleetPlan.Identity != second {
			t.Fatal("unknown rollback reference checkpointed")
		}
		f.plan.RollbackOf = first
		f.sign(t)
		f.expect(t, ctx, "FleetPlanApplied")
		realm := &api.HankoRealm{}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), realm); err != nil || !realm.Spec.OTPRequired {
			t.Fatalf("rollback did not restore desired state: %v", err)
		}
		for _, name := range []string{foreign.Name, f.tenant.Name + "-app"} {
			if err := kube.Get(ctx, client.ObjectKey{Namespace: f.tenant.Namespace, Name: name}, &api.HankoApplication{}); err != nil {
				t.Fatalf("rollback pruned provider configuration %s: %v", name, err)
			}
		}
		s := f.tenant.Status.FleetPlan
		if s.Sequence != 3 || len(s.Journal) != 3 || s.Journal[2].RollbackOf != first || s.RollbackReference == nil {
			t.Fatal("rollback journal not durable")
		}
		f.expect(t, ctx, "FleetPlanCurrent")
	})
	t.Run("expiry-between-checkpoint-and-child-write", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "offline-mid-expiry")
		f.plan.ExpiresAt = time.Now().UTC().Add(1500 * time.Millisecond)
		f.sign(t)
		f.writer.afterCheckpoint = func() { time.Sleep(time.Until(f.plan.ExpiresAt) + 10*time.Millisecond) }
		f.expect(t, ctx, "FleetPlanExpired")
		if f.writer.writes != 0 || f.tenant.Status.FleetPlan == nil || !f.tenant.Status.FleetPlan.Expired {
			t.Fatal("expiry after checkpoint permitted content write")
		}
	})
}
