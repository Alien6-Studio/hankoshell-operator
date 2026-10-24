package fleetplan

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloakversion"
	utilversion "k8s.io/apimachinery/pkg/util/version"
)

const MaxRolloutFindings = 32

type ObjectRequirement struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Requirements []string `json:"requirements"`
}

// Object is a private execution input. Public findings identify array positions,
// never remote names, requirements, configuration, credentials or personal data.
type Object struct {
	Kind, Name, RealmRef, ProfileRef string
	Raw                              json.RawMessage
	Required                         []string
}

type Support struct {
	Capabilities, Permissions map[string]bool
	Unavailable               bool
}
type Finding struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}
type Rollout struct {
	Objects  []Object
	Selected []bool
	Refused  int
	Findings []Finding
	Omitted  int
}

var capabilityName = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)

func validRequirements(values []string) bool {
	if len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !capabilityName.MatchString(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func validateRollout(p Plan) error {
	if (p.Mode != "all-or-refuse" && p.Mode != "partial") || !validRequirements(p.Requirements) || len(p.ObjectRequirements) > MaxObjects {
		return Refusal("FleetCapabilitiesUnsupported")
	}
	if !validMinimumVersion(p.MinimumOperatorVersion) {
		return Refusal("FleetOperatorVersionInvalid")
	}
	objects := Objects(p)
	if len(objects) == 0 && len(p.Requirements) > 0 {
		return Refusal("FleetCapabilitiesUnsupported")
	}
	available := map[string]bool{}
	for _, obj := range objects {
		key := obj.Kind + "/" + obj.Name
		if available[key] {
			return Refusal("FleetContentInvalid")
		}
		available[key] = true
	}
	seen := map[string]bool{}
	for _, r := range p.ObjectRequirements {
		key := r.Kind + "/" + r.Name
		if !available[key] || seen[key] || !validRequirements(r.Requirements) {
			return Refusal("FleetCapabilitiesUnsupported")
		}
		seen[key] = true
	}
	return nil
}

func validMinimumVersion(value string) bool {
	if value == "" {
		return true
	}
	_, err := utilversion.ParseSemantic(value)
	return err == nil && len(value) <= 64
}

// Objects derives mandatory capabilities from actual typed intent. Omitting
// signed requirements never disables the local permission/capability gate.
type objectSpec struct {
	ArtifactSHA256    string            `json:"artifactSHA256"`
	RealmRef          string            `json:"realmRef"`
	IAMProfileRef     string            `json:"iamProfileRef"`
	Protocol          string            `json:"protocol"`
	Roles             []json.RawMessage `json:"roles"`
	TokenClaims       []json.RawMessage `json:"tokenClaims"`
	IdentityMappings  []json.RawMessage `json:"identityMappings"`
	IdentityProviders []json.RawMessage `json:"identityProviders"`
	RealmRoleScopes   []json.RawMessage `json:"realmRoleScopes"`
}

func Objects(p Plan) []Object {
	var result []Object
	for _, group := range []struct {
		kind string
		raws []json.RawMessage
	}{{"HankoIAMProfile", p.Content.IAMProfiles}, {"HankoRealm", p.Content.Realms}, {"HankoApplication", p.Content.Apps}, {"HankoTheme", p.Content.Themes}, {"HankoServiceAccount", p.Content.ServiceAccounts}} {
		for _, raw := range group.raws {
			var doc struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec objectSpec `json:"spec"`
			}
			_ = json.Unmarshal(raw, &doc) // Full typed/API validation is mandatory before writes.
			o := Object{Kind: group.kind, Name: doc.Metadata.Name, RealmRef: doc.Spec.RealmRef, ProfileRef: doc.Spec.IAMProfileRef, Raw: raw, Required: requiredCapabilities(group.kind, doc.Spec)}
			if o.Kind == "HankoRealm" {
				o.RealmRef = o.Name
			}
			for _, extra := range p.ObjectRequirements {
				if extra.Kind == o.Kind && extra.Name == o.Name {
					o.Required = append(o.Required, extra.Requirements...)
				}
			}
			result = append(result, o)
		}
	}
	return result
}

func requiredCapabilities(kind string, s objectSpec) []string {
	var required []string
	switch kind {
	case "HankoIAMProfile":
		required = []string{"iam.policy"}
	case "HankoRealm":
		required = []string{"realm.manage"}
	case "HankoApplication":
		protocol := "application.oidc"
		if s.Protocol == "saml" {
			protocol = "application.saml"
		}
		required = []string{protocol}
		if len(s.Roles) > 0 {
			required = append(required, "application.client-roles")
		}
	case "HankoServiceAccount":
		required = []string{"service-account.manage"}
	case "HankoTheme":
		required = []string{"theme.build"}
		if s.ArtifactSHA256 != "" {
			required = []string{"theme.install"}
		}
	}
	if len(s.IdentityProviders)+len(s.IdentityMappings) > 0 {
		required = append(required, "realm.identity-providers")
	}
	if len(s.TokenClaims) > 0 {
		required = append(required, "application.token-claims")
	}
	if len(s.RealmRoleScopes) > 0 {
		required = append(required, "realm.manage")
	}
	return required
}

func supportReason(requirements []string, s Support) string {
	if len(requirements) == 0 {
		return ""
	}
	if s.Unavailable {
		return "FleetCapabilityInventoryUnavailable"
	}
	for _, r := range requirements {
		if !s.Capabilities[r] {
			return "FleetCapabilityUnsupported"
		}
		if !s.Permissions[r] {
			return "FleetPermissionDenied"
		}
	}
	return ""
}

// Evaluate performs a complete decision before any checkpoint/content write.
// Atomic means whole-plan refusal on incompatibility, not a write transaction.
func Evaluate(v Verified, operatorVersion string, support []Support) (Rollout, error) {
	p := v.Plan()
	r := Rollout{Objects: Objects(p)}
	if v.Identity() == "" {
		return r, Refusal("FleetEnvelopeInvalid")
	}
	if err := CheckOperatorVersion(p, operatorVersion); err != nil {
		return r, err
	}
	if len(support) != len(r.Objects) {
		return r, Refusal("FleetCapabilityInventoryUnavailable")
	}
	for _, s := range support {
		if reason := supportReason(p.Requirements, s); reason != "" {
			return r, Refusal(reason)
		}
	}
	reasons := make([]string, len(r.Objects))
	for i, o := range r.Objects {
		reasons[i] = supportReason(o.Required, support[i])
	}
	return evaluateObjects(p.Mode, r, reasons)
}

func CheckOperatorVersion(p Plan, operatorVersion string) error {
	if p.MinimumOperatorVersion != "" {
		minimum, _ := utilversion.ParseSemantic(p.MinimumOperatorVersion)
		current, err := utilversion.ParseSemantic(operatorVersion)
		if err != nil || minimum == nil || !current.AtLeast(minimum) {
			return Refusal("FleetOperatorVersionUnsupported")
		}
	}
	return nil
}

func evaluateObjects(mode string, r Rollout, reasons []string) (Rollout, error) {
	propagateRefusals(r.Objects, reasons)
	r.Selected = make([]bool, len(r.Objects))
	for i, reason := range reasons {
		if reason == "" {
			r.Selected[i] = true
			continue
		}
		r.Refused++
		if len(r.Findings) < MaxRolloutFindings {
			r.Findings = append(r.Findings, Finding{Index: i, Reason: reason})
		} else {
			r.Omitted++
		}
	}
	if r.Refused > 0 && (mode == "all-or-refuse" || r.Refused == len(r.Objects)) {
		return r, Refusal("FleetCapabilityRefused")
	}
	return r, nil
}

func propagateRefusals(objects []Object, reasons []string) {
	for range len(objects) {
		changed := false
		for i, o := range objects {
			if reasons[i] == "" && refusedDependency(objects, reasons, o) {
				reasons[i] = "FleetDependencyRefused"
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

func refusedDependency(objects []Object, reasons []string, o Object) bool {
	for j, d := range objects {
		depends := (d.Kind == "HankoRealm" && o.Kind != "HankoRealm" && o.RealmRef == d.Name) || (d.Kind == "HankoIAMProfile" && o.ProfileRef == d.Name)
		if depends && reasons[j] != "" {
			return true
		}
	}
	return false
}

func (r Rollout) Content() Content {
	var c Content
	for i, o := range r.Objects {
		if !r.Selected[i] {
			continue
		}
		switch o.Kind {
		case "HankoIAMProfile":
			c.IAMProfiles = append(c.IAMProfiles, o.Raw)
		case "HankoRealm":
			c.Realms = append(c.Realms, o.Raw)
		case "HankoApplication":
			c.Apps = append(c.Apps, o.Raw)
		case "HankoTheme":
			c.Themes = append(c.Themes, o.Raw)
		case "HankoServiceAccount":
			c.ServiceAccounts = append(c.ServiceAccounts, o.Raw)
		}
	}
	return c
}

// LocalOverride is part of the independently protected trust ConfigMap. Exact
// target tuples prevent an override for another tenant from granting authority.
type localOverride struct {
	Target Target `json:"target"`
	Action string `json:"action"`
}
type localProvider struct {
	Target   Target `json:"target"`
	Endpoint string `json:"endpoint"`
	Version  string `json:"version"`
}
type localConfig struct {
	Version   string          `json:"version"`
	Overrides []localOverride `json:"overrides,omitempty"`
	Providers []localProvider `json:"providers,omitempty"`
	Hubs      []localHub      `json:"hubs,omitempty"`
	Commands  []localCommand  `json:"commands,omitempty"`
}

func localConfiguration(data []byte) (localConfig, error) {
	var config localConfig
	if len(data) == 0 {
		return config, nil
	}
	if !decode(data, MaxTrust, &config) || config.Version != "hanko.sh/fleet-rollout/v1alpha1" || len(config.Overrides) > 64 || len(config.Providers) > 64 {
		return config, Refusal("FleetRolloutPolicyInvalid")
	}
	seen := map[Target]bool{}
	for _, o := range config.Overrides {
		if !validTarget(o.Target) || seen[o.Target] || !slices.Contains([]string{"allow", "pause", "refuse"}, o.Action) {
			return config, Refusal("FleetRolloutPolicyInvalid")
		}
		seen[o.Target] = true
	}
	if !validLocalProviders(config.Providers) {
		return config, Refusal("FleetRolloutPolicyInvalid")
	}
	if !validLocalAuthorities(config.Hubs, config.Commands) {
		return config, Refusal("FleetRolloutPolicyInvalid")
	}
	return config, nil
}

func validLocalProviders(providers []localProvider) bool {
	seen := map[Target]bool{}
	for _, p := range providers {
		if !validTarget(p.Target) || seen[p.Target] || !strings.HasPrefix(p.Endpoint, "https://") || len(p.Endpoint) > 256 || !keycloakversion.Core(p.Version) {
			return false
		}
		seen[p.Target] = true
	}
	return true
}

func LocalOverride(data []byte, target Target) error {
	config, err := localConfiguration(data)
	if err != nil {
		return err
	}
	for _, o := range config.Overrides {
		if o.Target == target {
			switch o.Action {
			case "pause":
				return Refusal("FleetRolloutPaused")
			case "refuse":
				return Refusal("FleetRolloutRefused")
			}
		}
	}
	return nil
}

// ProviderVersion is an explicit independent local deployment assertion, only
// used when restricted provider credentials cannot observe server version.
func ProviderVersion(data []byte, target Target, endpoint string) (string, error) {
	config, err := localConfiguration(data)
	if err != nil {
		return "", err
	}
	for _, p := range config.Providers {
		if p.Target == target && p.Endpoint == endpoint {
			return p.Version, nil
		}
	}
	return "", nil
}
