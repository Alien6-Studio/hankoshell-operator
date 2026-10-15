package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestFleetEndpointChangeStopsAllHubCalls(t *testing.T) {
	f := newFleetUnitFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	if f.tenant.Status.FleetPlan.HubEndpointHash != fleetplan.EndpointIdentity(f.tenant.Spec.HubEndpoint) {
		t.Fatal("accepted destination not pinned")
	}
	calls := f.hubCalls.Load()
	f.tenant.Spec.HubEndpoint += "/unapproved"
	if err := f.client.Update(context.Background(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetHubEndpointUnapproved")
	if f.hubCalls.Load() != calls || f.r.Pool.Get("auth/tenant") != nil {
		t.Fatal("unapproved endpoint forwarded a credential or retained routing")
	}
}

func TestFleetDecommissionRequiresIndependentExactApproval(t *testing.T) {
	f := newFleetUnitFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.reload(t)
	recorder := events.NewFakeRecorder(5)
	f.r.Recorder = recorder
	command := &hub.DecommissionCommand{RequestedAt: time.Now().Add(-time.Second).UTC(), Deadline: time.Now().Add(time.Minute).UTC()}
	if _, err := f.r.executeDecommission(context.Background(), f.tenant, fleetStatusPatch(f.tenant), nil, command); err != nil {
		t.Fatal(err)
	}
	f.reason(t, "FleetCommandUnapproved")
	select {
	case e := <-recorder.Events:
		if !strings.Contains(e, "FleetCommandUnapproved") {
			t.Fatal("missing public refusal Event")
		}
	default:
		t.Fatal("no refusal Event")
	}
	cm := &corev1.ConfigMap{}
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: "fleet-trust"}, cm); err != nil {
		t.Fatal(err)
	}
	target := fleetTenantTarget(f.tenant)
	raw, _ := json.Marshal(map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "commands": []any{map[string]any{"target": target, "action": "decommission", "identity": fleetplan.DecommissionIdentity(target, command.RequestedAt, command.Deadline)}}})
	cm.Data["rollout.json"] = string(raw)
	if err := f.client.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	if err := f.r.fleetDecommissionAuthority(context.Background(), f.tenant, command); err != nil {
		t.Fatal(err)
	}
	command.Deadline = command.Deadline.Add(time.Second)
	if fleetplan.Reason(f.r.fleetDecommissionAuthority(context.Background(), f.tenant, command)) != "FleetCommandUnapproved" {
		t.Fatal("tampered acknowledgement reused approval")
	}
}

func TestTenantWatchIgnoresItsOwnStatus(t *testing.T) {
	f := newFleetUnitFixture(t)
	original := f.tenant.DeepCopy()
	current := original.DeepCopy()
	current.Status.Phase = "Error"
	current.ResourceVersion = "2"
	p := tenantIntentPredicate()
	if p.Update(event.UpdateEvent{ObjectOld: original, ObjectNew: current}) {
		t.Fatal("status update would create a hot reconcile loop")
	}
	for _, changed := range []string{"generation", "annotation", "label"} {
		current = original.DeepCopy()
		switch changed {
		case "generation":
			current.Generation++
		case "annotation":
			current.Annotations = map[string]string{"local.example/reconcile": "1"}
		case "label":
			current.Labels = map[string]string{"local.example/owner": "1"}
		}
		if !p.Update(event.UpdateEvent{ObjectOld: original, ObjectNew: current}) {
			t.Fatal("local intent update ignored")
		}
	}
}
