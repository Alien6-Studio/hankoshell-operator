//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *fleetAPIFixture) addApplication() {
	f.plan.Content.Apps = []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoApplication","metadata":{"name":%q,"namespace":"fleet-fixtures","labels":{"hanko.sh/tenant":%q}},"spec":{"realmRef":%q,"clientID":"fleet-client","protocol":"oidc"}}`, f.tenant.Name+"-app", f.tenant.Name, f.tenant.Name))}
}

func (f *fleetAPIFixture) override(t *testing.T, ctx context.Context, action string) {
	t.Helper()
	cm := &corev1.ConfigMap{}
	if err := f.kube.Get(ctx, client.ObjectKeyFromObject(f.trust), cm); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "overrides": []any{map[string]any{"target": f.plan.Target, "action": action}}})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["rollout.json"] = string(raw)
	if err := f.kube.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
}

func checkFleetCapabilityRollout(t *testing.T, ctx context.Context, kube client.Client) {
	t.Run("restricted-version-visibility-needs-local-approval", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "rollout-approved-version")
		version := ""
		f.nativeVersion.Store(&version)
		f.expect(t, ctx, "FleetCapabilityRefused")
		if f.writer.writes != 0 {
			t.Fatal("hidden version acquired implicit qualification")
		}
		cm := &corev1.ConfigMap{}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.trust), cm); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "providers": []any{map[string]any{"target": f.plan.Target, "endpoint": f.tenant.Spec.HubEndpoint, "version": "26.8.0"}}})
		cm.Data["rollout.json"] = string(raw)
		if err := kube.Update(ctx, cm); err != nil {
			t.Fatal(err)
		}
		f.expect(t, ctx, "FleetPlanApplied")
		version = "26.7.5"
		f.nativeVersion.Store(&version)
		f.expect(t, ctx, "FleetProviderVersionMismatch")
	})
	t.Run("two-tenants-with-different-effective-capabilities", func(t *testing.T) {
		full := newFleetAPIFixture(t, ctx, kube, "rollout-full")
		limited := newFleetAPIFixture(t, ctx, kube, "rollout-limited")
		for _, f := range []*fleetAPIFixture{full, limited} {
			f.plan.Mode = "partial"
			f.addApplication()
			f.sign(t)
		}
		roles := []string{"manage-realm", "manage-events"}
		limited.nativeRoles.Store(&roles)
		full.expect(t, ctx, "FleetPlanApplied")
		limited.expect(t, ctx, "FleetPlanPartial")
		s := limited.tenant.Status.FleetRollout
		if s == nil || s.Applied != 1 || s.Refused != 1 || s.Pending != 0 || s.State != "Partial" || len(s.Findings) != 1 || s.Findings[0].Reason != "FleetPermissionDenied" || limited.tenant.Status.FleetPlan.AppliedIdentity != "" || limited.tenant.Status.Phase != "Error" {
			t.Fatal("partial delivery was presented as full convergence")
		}
		if err := kube.Get(ctx, client.ObjectKey{Name: limited.tenant.Name + "-app", Namespace: limited.tenant.Namespace}, &api.HankoApplication{}); !apierrors.IsNotFound(err) {
			t.Fatal("unsupported application was written")
		}
		if err := kube.Get(ctx, client.ObjectKey{Name: full.tenant.Name + "-app", Namespace: full.tenant.Namespace}, &api.HankoApplication{}); err != nil {
			t.Fatal("another tenant's supported application was not delivered")
		}
		writes := limited.writer.writes
		limited.expect(t, ctx, "FleetPlanPartial")
		if limited.writer.writes != writes {
			t.Fatal("partial checkpoint replayed creates")
		}
		e := limited.reported.Load()
		if e.FleetRollout == nil || e.FleetRollout.Refused != 1 || e.Health != "degraded" || e.Phase != "Error" || e.Detail != "FleetPlanPartial" {
			t.Fatal("partial status missing from bounded heartbeat")
		}
	})
	for _, boundary := range []string{"atomic", "minimum-version", "provider-version", "global-requirement", "foreign-tenant", "foreign-namespace"} {
		t.Run("refuse-"+boundary, func(t *testing.T) {
			f := newFleetAPIFixture(t, ctx, kube, "rollout-"+boundary)
			f.addApplication()
			reason := "FleetCapabilityRefused"
			switch boundary {
			case "atomic":
				roles := []string{"manage-realm", "manage-events"}
				f.nativeRoles.Store(&roles)
			case "minimum-version":
				f.plan.MinimumOperatorVersion = "99.0.0"
				reason = "FleetOperatorVersionUnsupported"
			case "provider-version":
				v := "99.0.0"
				f.nativeVersion.Store(&v)
			case "global-requirement":
				f.plan.Mode = "partial"
				f.plan.Requirements = []string{"unknown.capability"}
				reason = "FleetCapabilityUnsupported"
			case "foreign-tenant":
				f.plan.Mode = "partial"
				f.plan.Content.Apps[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Apps[0]), fmt.Sprintf(`"hanko.sh/tenant":%q`, f.tenant.Name), `"hanko.sh/tenant":"other"`, 1))
				reason = "FleetContentInvalid"
			case "foreign-namespace":
				f.plan.Mode = "partial"
				f.plan.Content.Apps[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Apps[0]), `"namespace":"fleet-fixtures"`, `"namespace":"other"`, 1))
				reason = "FleetContentInvalid"
			}
			f.sign(t)
			f.expect(t, ctx, reason)
			if f.writer.writes != 0 || f.tenant.Status.FleetPlan != nil {
				t.Fatal("refused rollout wrote desired state or advanced acceptance")
			}
		})
	}
	for _, moment := range []string{"before-fetch", "during-fetch", "after-checkpoint", "local-refuse"} {
		t.Run("override-"+moment, func(t *testing.T) {
			f := newFleetAPIFixture(t, ctx, kube, "rollout-"+moment)
			reason := "FleetRolloutPaused"
			switch moment {
			case "before-fetch":
				callback := func() { t.Error("paused rollout fetched new content") }
				f.before.Store(&callback)
				f.override(t, ctx, "pause")
			case "during-fetch":
				callback := func() { f.override(t, ctx, "pause") }
				f.before.Store(&callback)
			case "after-checkpoint":
				f.writer.afterCheckpoint = func() { f.override(t, ctx, "pause") }
			case "local-refuse":
				f.override(t, ctx, "refuse")
				reason = "FleetRolloutRefused"
			}
			f.expect(t, ctx, reason)
			if f.writer.writes != 0 || f.tenant.Status.FleetRollout == nil {
				t.Fatal("local override failed to stop application")
			}
			if moment == "before-fetch" {
				f.before.Store(nil)
			}
			f.override(t, ctx, "allow")
			f.expect(t, ctx, "FleetPlanApplied")
		})
	}
	t.Run("bounded-public-findings-and-admission", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "rollout-bounded")
		f.plan.Mode = "partial"
		for i := range 40 {
			f.plan.Content.Themes = append(f.plan.Content.Themes, json.RawMessage(fmt.Sprintf(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoTheme","metadata":{"name":"private-name-%d","namespace":"fleet-fixtures","labels":{"hanko.sh/tenant":%q}},"spec":{"buildImage":"registry.example/theme@sha256:%s","keycloakPVC":"theme-volume"}}`, i, f.tenant.Name, strings.Repeat("a", 64))))
		}
		f.sign(t)
		f.expect(t, ctx, "FleetPlanPartial")
		s := f.tenant.Status.FleetRollout
		if s.Applied != 1 || s.Refused != 40 || s.Pending != 0 || len(s.Findings) != 32 || s.Omitted != 8 {
			t.Fatal("finding overflow is missing or unbounded")
		}
		raw, err := json.Marshal(f.reported.Load().FleetRollout)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 8192 || strings.Contains(string(raw), "private-name") || strings.Contains(string(raw), "fixture-provider-credential") {
			t.Fatal("public evidence exceeded its budget or exposed private inputs")
		}
		copy := f.tenant.DeepCopy()
		copy.Status.FleetRollout.Findings = append(copy.Status.FleetRollout.Findings, copy.Status.FleetRollout.Findings[0])
		if err := kube.Status().Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Fatal("oversized status findings admitted")
		}
		copy = f.tenant.DeepCopy()
		copy.Status.FleetRollout.Pending = 200
		if err := kube.Status().Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Fatal("inconsistent status count budget admitted")
		}
	})
}
