package fleetplan_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
)

func verifiedRollout(t *testing.T, f fixture) fleetplan.Verified {
	t.Helper()
	v, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func allSupport() fleetplan.Support {
	values := map[string]bool{}
	for _, name := range []string{"iam.policy", "realm.manage", "realm.identity-providers", "application.oidc", "application.saml", "application.client-roles", "application.token-claims", "service-account.manage"} {
		values[name] = true
	}
	return fleetplan.Support{Capabilities: values, Permissions: values}
}

func TestFleetRolloutCapabilityPermissionAndMode(t *testing.T) {
	for _, mode := range []string{"all-or-refuse", "partial"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.plan.Mode = mode
			f.plan.Content.Themes = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoTheme","metadata":{"name":"theme","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{}}`)}
			r, err := fleetplan.Evaluate(verifiedRollout(t, f), "0.1.0-dev.0", []fleetplan.Support{allSupport(), allSupport()})
			if r.Refused != 1 || len(r.Findings) != 1 || r.Findings[0].Reason != "FleetCapabilityUnsupported" || !r.Selected[0] || r.Selected[1] {
				t.Fatal("capability decision is incomplete")
			}
			if mode == "partial" {
				if err != nil || len(r.Content().Realms) != 1 || len(r.Content().Themes) != 0 {
					t.Fatal("explicit partial mode did not select only supported content")
				}
			} else if fleetplan.Reason(err) != "FleetCapabilityRefused" {
				t.Fatal("atomic mode accepted an incompatible object")
			}
		})
	}
	f := newFixture(t)
	s := allSupport()
	s.Permissions = map[string]bool{}
	r, err := fleetplan.Evaluate(verifiedRollout(t, f), "0.1.0", []fleetplan.Support{s})
	if fleetplan.Reason(err) != "FleetCapabilityRefused" || r.Findings[0].Reason != "FleetPermissionDenied" {
		t.Fatal("capability declaration substituted for native permission")
	}
	f.plan.Requirements = []string{"unknown.capability"}
	if _, err := fleetplan.Evaluate(verifiedRollout(t, f), "0.1.0", []fleetplan.Support{allSupport()}); fleetplan.Reason(err) != "FleetCapabilityUnsupported" {
		t.Fatal("global requirements were not mandatory")
	}
	f.plan.Requirements = []string{"realm.manage"}
	if _, err := fleetplan.Evaluate(verifiedRollout(t, f), "0.1.0", []fleetplan.Support{s}); fleetplan.Reason(err) != "FleetPermissionDenied" {
		t.Fatal("global permission requirement was ignored")
	}
}

func TestFleetRolloutDependenciesBudgetsAndInventory(t *testing.T) {
	if _, err := fleetplan.Evaluate(fleetplan.Verified{}, "0.1.0", nil); err == nil {
		t.Fatal("zero verification result granted rollout authority")
	}
	f := newFixture(t)
	f.plan.Mode = "partial"
	f.plan.Content.Apps = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoApplication","metadata":{"name":"app","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"realmRef":"realm","protocol":"saml","roles":[{}],"tokenClaims":[{}],"identityMappings":[{}]}}`)}
	f.plan.Content.ServiceAccounts = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoServiceAccount","metadata":{"name":"worker","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"realmRef":"realm","tokenClaims":[{}]}}`)}
	f.plan.Content.IAMProfiles = []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoIAMProfile","metadata":{"name":"policy","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"security":{}}}`)}
	f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"otpRequired":true`, `"otpRequired":true,"iamProfileRef":"policy","identityProviders":[{}]`, 1))
	v := verifiedRollout(t, f)
	support := []fleetplan.Support{allSupport(), allSupport(), allSupport(), allSupport()}
	if r, err := fleetplan.Evaluate(v, "0.1.0", support); err != nil || len(r.Content().IAMProfiles) != 1 || len(r.Content().Apps) != 1 || len(r.Content().ServiceAccounts) != 1 {
		t.Fatal("compatible finite kinds were not retained")
	}
	support[0] = fleetplan.Support{Unavailable: true}
	r, err := fleetplan.Evaluate(v, "0.1.0", support)
	if fleetplan.Reason(err) != "FleetCapabilityRefused" || r.Refused != 4 || r.Findings[3].Reason != "FleetDependencyRefused" {
		t.Fatal("refused dependency was not propagated")
	}
	if _, err := fleetplan.Evaluate(v, "0.1.0", nil); fleetplan.Reason(err) != "FleetCapabilityInventoryUnavailable" {
		t.Fatal("incomplete inventory was accepted")
	}
	f = newFixture(t)
	f.plan.Content.Realms = nil
	f.plan.Mode = "partial"
	for i := range 100 {
		f.plan.Content.Realms = append(f.plan.Content.Realms, json.RawMessage(fmt.Sprintf(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","metadata":{"name":"realm-%d","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{}}`, i)))
	}
	r, err = fleetplan.Evaluate(verifiedRollout(t, f), "0.1.0", make([]fleetplan.Support, 100))
	if err == nil || len(r.Findings) != fleetplan.MaxRolloutFindings || r.Omitted != 68 || r.Refused != 100 {
		t.Fatal("findings were unbounded or silently omitted")
	}
	raw := marshal(t, r.Findings)
	if len(raw) > 4096 || strings.Contains(string(raw), "realm-") {
		t.Fatal("public findings include remote object data")
	}
}

func TestFleetRolloutSchemaVersionAndOverrides(t *testing.T) {
	for _, change := range []func(*fixture){
		func(f *fixture) { f.plan.MinimumOperatorVersion = "not-semver" },
		func(f *fixture) { f.plan.Requirements = []string{"realm.manage", "realm.manage"} },
		func(f *fixture) {
			f.plan.ObjectRequirements = []fleetplan.ObjectRequirement{{Kind: "HankoRealm", Name: "missing", Requirements: []string{"realm.manage"}}}
		},
		func(f *fixture) {
			r := fleetplan.ObjectRequirement{Kind: "HankoRealm", Name: "realm", Requirements: []string{"realm.manage"}}
			f.plan.ObjectRequirements = []fleetplan.ObjectRequirement{r, r}
		},
		func(f *fixture) { f.plan.Content.Realms = append(f.plan.Content.Realms, f.plan.Content.Realms[0]) },
		func(f *fixture) { f.plan.Content = fleetplan.Content{}; f.plan.Requirements = []string{"realm.manage"} },
	} {
		f := newFixture(t)
		change(&f)
		if _, err := fleetplan.Verify(f.signed(t, nil), marshal(t, f.trust), f.plan.Target, f.now, fleetplan.Checkpoint{}); err == nil {
			t.Fatal("invalid rollout schema accepted")
		}
	}
	f := newFixture(t)
	f.plan.MinimumOperatorVersion = "0.1.0"
	v := verifiedRollout(t, f)
	for _, operator := range []string{"0.1.0-dev.0", "invalid"} {
		if _, err := fleetplan.Evaluate(v, operator, []fleetplan.Support{allSupport()}); fleetplan.Reason(err) != "FleetOperatorVersionUnsupported" {
			t.Fatal("operator minimum was ignored")
		}
	}
	if _, err := fleetplan.Evaluate(v, "0.1.0", []fleetplan.Support{allSupport()}); err != nil {
		t.Fatal(err)
	}
	f.plan.ObjectRequirements = []fleetplan.ObjectRequirement{{Kind: "HankoRealm", Name: "realm", Requirements: []string{"application.saml"}}}
	v = verifiedRollout(t, f)
	p := v.Plan()
	p.ObjectRequirements[0].Requirements[0] = "changed"
	if v.Plan().ObjectRequirements[0].Requirements[0] != "application.saml" {
		t.Fatal("caller changed verified requirements")
	}
	if _, err := fleetplan.Evaluate(v, "0.1.0", []fleetplan.Support{allSupport()}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"allow", "pause", "refuse"} {
		raw := marshal(t, map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "overrides": []any{map[string]any{"target": f.plan.Target, "action": action}}})
		err := fleetplan.LocalOverride(raw, f.plan.Target)
		if (action == "allow") != (err == nil) {
			t.Fatal("local override not enforced")
		}
		other := f.plan.Target
		other.TenantUID = "other"
		if err := fleetplan.LocalOverride(raw, other); err != nil {
			t.Fatal("another tenant override affected this scope")
		}
	}
	for _, raw := range []string{`{}`, `{"version":"hanko.sh/fleet-rollout/v1alpha1","unknown":true}`, strings.Repeat("x", fleetplan.MaxTrust+1), `{"version":"hanko.sh/fleet-rollout/v1alpha1","overrides":[{"target":{},"action":"pause"}]}`} {
		if err := fleetplan.LocalOverride([]byte(raw), f.plan.Target); fleetplan.Reason(err) != "FleetRolloutPolicyInvalid" {
			t.Fatal("invalid local override accepted")
		}
	}
	if err := fleetplan.LocalOverride(nil, f.plan.Target); err != nil {
		t.Fatal(err)
	}
	raw := marshal(t, map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "providers": []any{map[string]any{"target": f.plan.Target, "endpoint": "https://provider.example.test", "version": "26.8.1"}}})
	if v, err := fleetplan.ProviderVersion(raw, f.plan.Target, "https://provider.example.test"); err != nil || v != "26.8.1" {
		t.Fatal("local version approval was not read")
	}
	if v, err := fleetplan.ProviderVersion(raw, f.plan.Target, "https://other.example.test"); err != nil || v != "" {
		t.Fatal("version approval escaped its provider endpoint")
	}
	if _, err := fleetplan.ProviderVersion([]byte(`{}`), f.plan.Target, "https://provider.example.test"); err == nil {
		t.Fatal("malformed local version approval accepted")
	}
	for _, version := range []string{"26.0.0", "26.7.6", "26.8.2", "26.10.0", "27.0.0", "26.8.1-rc.1", "26.08.1", ""} {
		policy := marshal(t, map[string]any{"version": "hanko.sh/fleet-rollout/v1alpha1", "providers": []any{map[string]any{"target": f.plan.Target, "endpoint": "https://provider.example.test", "version": version}}})
		got, err := fleetplan.ProviderVersion(policy, f.plan.Target, "https://provider.example.test")
		accept := version == "26.0.0" || version == "26.7.6" || version == "26.8.2" || version == "26.10.0"
		if accept && (err != nil || got != version) || !accept && err == nil {
			t.Fatal("local provider version eligibility differs", version, err)
		}
	}
}
