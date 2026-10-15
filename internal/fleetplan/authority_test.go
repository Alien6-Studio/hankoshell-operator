package fleetplan_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
)

func TestFleetIndependentHubAndCommandApproval(t *testing.T) {
	f := newFixture(t)
	target := f.plan.Target
	endpoint := "https://hub.example.test"
	accepted := fleetplan.EndpointIdentity(endpoint)
	for _, invalid := range []string{"http://hub.example.test", "https://user@hub.example.test", endpoint + "?token=fixture", endpoint + "#fragment", "https:"} {
		if fleetplan.ApproveHub(nil, target, invalid, "") == nil {
			t.Fatal("unapproved initial credential destination")
		}
	}
	if err := fleetplan.ApproveHub(nil, target, endpoint, accepted); err != nil {
		t.Fatal(err)
	}
	if fleetplan.ApproveHub(nil, target, "https://other.example.test", accepted) == nil {
		t.Fatal("credential destination changed without local approval")
	}
	id := fleetplan.DecommissionIdentity(target, f.now, f.now.Add(time.Minute))
	policy := func(hubs, commands any) []byte {
		return marshal(t, map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "hubs": hubs, "commands": commands})
	}
	h := map[string]any{"target": target, "endpoint": endpoint}
	c := map[string]any{"target": target, "action": "decommission", "identity": id}
	data := policy([]any{h}, []any{c})
	if err := fleetplan.ApproveHub(data, target, endpoint, "different"); err != nil {
		t.Fatal(err)
	}
	if err := fleetplan.ApproveDecommission(data, target, id); err != nil {
		t.Fatal(err)
	}
	other := target
	other.TenantUID = "other"
	for _, check := range []error{fleetplan.ApproveHub(data, other, endpoint, accepted), fleetplan.ApproveDecommission(data, other, id), fleetplan.ApproveDecommission(nil, target, id), fleetplan.ApproveDecommission(data, target, strings.Repeat("e", 64))} {
		if check == nil {
			t.Fatal("foreign or unapproved authority")
		}
	}
	if id == fleetplan.DecommissionIdentity(target, f.now, f.now.Add(2*time.Minute)) {
		t.Fatal("deadline not bound")
	}
	for _, boundary := range []string{"duplicate-hub", "duplicate-command", "bad-endpoint", "userinfo", "query", "fragment", "bad-target", "bad-action", "bad-identity", "too-many", "unknown"} {
		t.Run(boundary, func(t *testing.T) {
			hh := map[string]any{"target": target, "endpoint": endpoint}
			cc := map[string]any{"target": target, "action": "decommission", "identity": id}
			hubs, commands := []any{hh}, []any{cc}
			switch boundary {
			case "duplicate-hub":
				hubs = append(hubs, hh)
			case "duplicate-command":
				commands = append(commands, cc)
			case "bad-endpoint":
				hh["endpoint"] = "http://hub.example.test"
			case "userinfo":
				hh["endpoint"] = "https://user@hub.example.test"
			case "query":
				hh["endpoint"] = endpoint + "?token=fixture"
			case "fragment":
				hh["endpoint"] = endpoint + "#fragment"
			case "bad-target":
				hh["target"] = fleetplan.Target{}
			case "bad-action":
				cc["action"] = "update"
			case "bad-identity":
				cc["identity"] = "invalid"
			case "too-many":
				hubs = make([]any, 65)
			case "unknown":
				hh["unknown"] = true
			}
			data := policy(hubs, commands)
			if fleetplan.Reason(fleetplan.ApproveHub(data, target, endpoint, accepted)) != "FleetRolloutPolicyInvalid" || fleetplan.ApproveDecommission(data, target, id) == nil {
				t.Fatal("malformed local authority accepted")
			}
		})
	}
}
