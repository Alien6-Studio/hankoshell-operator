package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestFleetRolloutControllerDecisionsAndOverrideRace(t *testing.T) {
	for _, boundary := range []string{"partial", "atomic", "permission", "version", "provider-version", "pinned-version", "pin-mismatch", "scope", "pause", "pause-race", "refuse", "invalid-policy"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFleetUnitFixture(t)
			reason := "FleetCapabilityRefused"
			switch boundary {
			case "partial", "atomic":
				f.plan.Content.Themes = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoTheme","metadata":{"name":"theme","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"buildImage":"registry.example/theme","keycloakPVC":"volume"}}`)}
				if boundary == "partial" {
					f.plan.Mode = "partial"
					reason = "FleetPlanPartial"
				}
			case "permission":
				f.nativeRoles = []string{"view-realm"}
			case "version":
				f.plan.MinimumOperatorVersion = "99.0.0"
				reason = "FleetOperatorVersionUnsupported"
			case "provider-version":
				f.nativeVersion = "99.0.0"
			case "pinned-version", "pin-mismatch":
				cm := &corev1.ConfigMap{}
				if err := f.client.Get(context.Background(), client.ObjectKey{Name: "fleet-trust", Namespace: "auth"}, cm); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "providers": []any{map[string]any{"target": f.plan.Target, "endpoint": f.tenant.Spec.HubEndpoint, "version": "26.8.1"}}})
				cm.Data["rollout.json"] = string(raw)
				if err := f.client.Update(context.Background(), cm); err != nil {
					t.Fatal(err)
				}
				f.nativeVersion = ""
				reason = "FleetPlanApplied"
				if boundary == "pin-mismatch" {
					f.nativeVersion = "26.7.5"
					reason = "FleetProviderVersionMismatch"
				}
			case "scope":
				f.tenant.Spec.RealmRef = "other"
				if err := f.client.Update(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
				reason = "FleetProviderScopeUnknown"
			case "pause", "pause-race", "refuse", "invalid-policy":
				change := func() {
					cm := &corev1.ConfigMap{}
					if err := f.client.Get(context.Background(), client.ObjectKey{Name: "fleet-trust", Namespace: "auth"}, cm); err != nil {
						t.Error(err)
						return
					}
					action := "pause"
					if boundary == "refuse" {
						action = "refuse"
					}
					raw, _ := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "overrides": []any{map[string]any{"target": f.plan.Target, "action": action}}})
					cm.Data["rollout.json"] = string(raw)
					if boundary == "invalid-policy" {
						cm.Data["rollout.json"] = `{}`
					}
					if err := f.client.Update(context.Background(), cm); err != nil {
						t.Error(err)
					}
				}
				if boundary == "pause-race" {
					f.beforeResponse = change
				} else {
					change()
				}
				reason = "FleetRolloutPaused"
				if boundary == "refuse" {
					reason = "FleetRolloutRefused"
				}
				if boundary == "invalid-policy" {
					reason = "FleetRolloutPolicyInvalid"
				}
			}
			f.sign(t)
			if err := f.reconcile(t); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
				t.Fatal(err)
			}
			if len(f.tenant.Status.Conditions) != 1 || f.tenant.Status.Conditions[0].Reason != reason {
				t.Fatalf("expected %s; got %+v", reason, f.tenant.Status.Conditions)
			}
			if boundary == "partial" {
				s := f.tenant.Status.FleetRollout
				if f.client.writes != 1 || s == nil || s.Applied != 1 || s.Refused != 1 || s.Pending != 0 || f.tenant.Status.FleetPlan.AppliedIdentity != "" || f.tenant.Status.BundleVersion != "" {
					t.Fatal("partial plan reported complete delivery")
				}
				if err := f.reconcile(t); err != nil {
					t.Fatal(err)
				}
				if f.client.writes != 1 {
					t.Fatal("current partial replay created another object")
				}
			} else if boundary == "pinned-version" {
				if f.client.writes != 1 || f.tenant.Status.FleetPlan == nil {
					t.Fatal("local version approval did not permit compatible content")
				}
			} else if f.client.writes != 0 || f.tenant.Status.FleetPlan != nil {
				t.Fatal("refused rollout wrote content")
			}
			if e := fleetRolloutEvidence(f.tenant); e != nil {
				raw, _ := json.Marshal(e)
				if len(raw) > 8192 || strings.Contains(string(raw), "registry.example") {
					t.Fatal("unbounded or private rollout evidence")
				}
			}
		})
	}
	if boundedFleetCount(-1) != -1 || boundedFleetCount(201) != -1 || boundedFleetCount(200) != 200 {
		t.Fatal("out-of-budget evidence was truncated")
	}
	if fleetRolloutEvidence(&api.HankoTenant{}) != nil {
		t.Fatal("legacy heartbeat gained rollout evidence")
	}
}

func TestFleetRolloutReportsAcknowledgedPrefixAndResumes(t *testing.T) {
	f := newFleetUnitFixture(t)
	f.plan.Content.Apps = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoApplication","metadata":{"name":"app","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"realmRef":"fleet-realm","clientID":"fixture-client"}}`)}
	f.sign(t)
	f.client.failApplyAt = 2
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
		t.Fatal(err)
	}
	s := f.tenant.Status.FleetRollout
	if s == nil || s.Applied != 1 || s.Pending != 1 || s.Refused != 0 || f.tenant.Status.FleetPlan.AppliedIdentity != "" {
		t.Fatal("partially acknowledged apply reported completion")
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
		t.Fatal(err)
	}
	if f.tenant.Status.FleetRollout.Applied != 2 || f.tenant.Status.FleetRollout.Pending != 0 || f.client.writes != 2 {
		t.Fatal("retry did not confirm the original object set")
	}
}
