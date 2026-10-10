package adoption

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func fixture() (TargetIdentity, ProviderIdentity, Observation, []Fact) {
	target := TargetIdentity{Kind: "HankoApplication", Namespace: "auth", Name: "app", UID: "target-uid"}
	provider := ProviderIdentity{Instance: TargetIdentity{Kind: "HankoKeycloakInstance", Namespace: "auth", Name: "reader", UID: "instance-uid"}, Origin: "https://keycloak.example.test", Trust: "public-ca", RealmID: "realm-uuid", ObjectIDs: []string{"client-uuid", "mapper-uuid"}}
	facts := []Fact{{Domain: "application", Identity: "client-uuid", Object: "app", Field: "redirectURIs", Classification: Supported, RoundTrip: Lossless, Value: Value{Set: []string{"https://b.example.test", "https://a.example.test"}}}, {Domain: "application", Identity: "client-uuid", Object: "app", Field: "owner", Classification: Supported, RoundTrip: Lossless, Value: Value{Text: "unmarked"}}}
	return target, provider, Observation{Facts: facts, Complete: true}, append([]Fact(nil), facts[:1]...)
}
func TestCandidateCanonicalIdentityAndDomains(t *testing.T) {
	target, p, o, w := fixture()
	base := Build(target, p, o, w)
	if !base.Complete || !base.Approvable || base.Truncated {
		t.Fatal("qualified complete review is not approvable")
	}
	if base.ObservationHash == base.DiffHash || base.DiffHash == base.CandidateHash {
		t.Fatal("hash domains not separated")
	}
	slices.Reverse(o.Facts)
	slices.Reverse(p.ObjectIDs)
	slices.Reverse(o.Facts[1].Value.Set)
	same := Build(target, p, o, w)
	if base.CandidateHash != same.CandidateHash {
		t.Fatal("ordering changed identity")
	}
	changes := []struct {
		name   string
		change func(*TargetIdentity, *ProviderIdentity, *Observation, *[]Fact)
	}{
		{"tenant metadata", func(target *TargetIdentity, _ *ProviderIdentity, _ *Observation, _ *[]Fact) {
			target.TenantRef = "changed"
		}},
		{"target UID", func(target *TargetIdentity, _ *ProviderIdentity, _ *Observation, _ *[]Fact) { target.UID = "replaced" }},
		{"instance UID", func(_ *TargetIdentity, p *ProviderIdentity, _ *Observation, _ *[]Fact) { p.Instance.UID = "replaced" }},
		{"endpoint", func(_ *TargetIdentity, p *ProviderIdentity, _ *Observation, _ *[]Fact) {
			p.Origin = "https://other.example.test"
		}},
		{"CA identity", func(_ *TargetIdentity, p *ProviderIdentity, _ *Observation, _ *[]Fact) {
			p.Trust = "private-ca"
			p.CAReference = "auth/ca"
			p.CAIdentity = "ca-uid:public-trust"
		}},
		{"realm UUID", func(_ *TargetIdentity, p *ProviderIdentity, _ *Observation, _ *[]Fact) { p.RealmID = "replaced" }},
		{"provider UUID", func(_ *TargetIdentity, p *ProviderIdentity, _ *Observation, _ *[]Fact) {
			p.ObjectIDs = []string{"replacement-client", "mapper-uuid"}
		}},
		{"child graph", func(_ *TargetIdentity, _ *ProviderIdentity, o *Observation, _ *[]Fact) {
			o.Facts = append(o.Facts, Fact{Domain: "client-role", Identity: "child-role", Object: "child", Field: "description", Classification: Supported, RoundTrip: Lossless, Value: Value{Text: "child"}})
		}},
		{"desired spec", func(_ *TargetIdentity, _ *ProviderIdentity, _ *Observation, w *[]Fact) {
			(*w)[0].Value = Value{Set: []string{"https://changed.example.test"}}
		}},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			target, p, o, w := fixture()
			change.change(&target, &p, &o, &w)
			got := Build(target, p, o, w)
			if got.CandidateHash == base.CandidateHash {
				t.Fatal("identity change did not bind candidate")
			}
		})
	}
}
func TestCandidateDiffCodesAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		classification     Classification
		roundtrip          RoundTrip
		field, value, want string
		code               Code
		approvable         bool
	}{
		{Supported, Lossless, "description", "before", "after", WouldChange, true},
		{Supported, Lossless, "protocol", "openid-connect", "saml", RecreationRequired, false},
		{Supported, Lossless, "parent", "old", "new", RecreationRequired, false},
		{Preserved, PreservedNative, "nativePresence", "present", "present", NativeReadOnly, true},
		{Preserved, Lossy, "nativePresence", "present", "present", NativeReadOnly, false},
		{UnsupportedNative, UnsupportedRoundTrip, "nativePresence", "present", "present", Unsupported, false},
		{Conflicting, Lossless, "owner", "foreign", "foreign", OwnershipTransition, false},
		{SecurityExcluded, PreservedNative, "credentialPresence", "present", "present", CredentialExcluded, true},
	} {
		t.Run(string(tc.code)+tc.field+string(tc.roundtrip), func(t *testing.T) {
			target, p, o, _ := fixture()
			f := Fact{Domain: "application", Identity: "client-uuid", Object: "app", Field: tc.field, Value: Value{Text: tc.value}, Classification: tc.classification, RoundTrip: tc.roundtrip}
			o.Facts = []Fact{f}
			desired := f
			desired.Value.Text = tc.want
			c := Build(target, p, o, []Fact{desired})
			if c.Diff[0].Code != tc.code || c.Approvable != tc.approvable {
				t.Fatal("incorrect refusal or typed diff")
			}
			if tc.code == CredentialExcluded && (c.Diff[0].Current != nil || c.Diff[0].Desired != nil) {
				t.Fatal("credential value emitted")
			}
		})
	}
	target, p, o, w := fixture()
	target.UID = ""
	if Build(target, p, o, w).Approvable {
		t.Fatal("missing target UID approvable")
	}
	target, p, o, w = fixture()
	o.Complete = false
	if Build(target, p, o, w).Approvable {
		t.Fatal("failed read approvable")
	}
}
func TestCandidateBudgetsDeterministicWireAndFindings(t *testing.T) {
	target, p, o, _ := fixture()
	o.Facts = nil
	for i := 0; i < 600; i++ {
		o.Facts = append(o.Facts, Fact{Domain: "role", Identity: fmt.Sprintf("id-%04d", i), Object: "safe", Field: "name", Classification: Supported, RoundTrip: Lossless, Value: Value{Text: strings.Repeat("x", 512)}})
	}
	for i := 0; i < 60; i++ {
		o.Findings = append(o.Findings, Finding{Code: fmt.Sprintf("code-%04d", i), Domain: "role", Message: strings.Repeat("x", 512), Blocking: true})
	}
	base := Build(target, p, o, nil)
	slices.Reverse(o.Facts)
	slices.Reverse(o.Findings)
	same := Build(target, p, o, nil)
	if base.Complete || base.Approvable || !base.Truncated || len(base.Diff) > MaxDiff || len(base.Findings) > MaxFindings || base.CandidateHash != same.CandidateHash {
		t.Fatal("overflow is not deterministic and fail closed")
	}
	data, _ := json.Marshal(base)
	if len(data) > MaxSummaryBytes {
		t.Fatal("actual serialized candidate exceeds wire budget")
	}
	target, p, o, w := fixture()
	o.Facts[0].Value.Set = make([]string, 1025)
	if c := Build(target, p, o, w); c.Complete || c.Approvable {
		t.Fatal("edge/value overflow accepted")
	}
	target, p, o, w = fixture()
	o.Facts[0].Field = "raw-provider-json"
	o.Facts[0].Value.Text = "secret-sentinel"
	c := Build(target, p, o, w)
	data, _ = json.Marshal(c)
	if c.Complete || c.Approvable || strings.Contains(string(data), "secret-sentinel") {
		t.Fatal("unreviewed field accepted or emitted")
	}
}

func TestActualEscapedWireBudgetAndOpaqueCredentialLength(t *testing.T) {
	target, provider, observation, _ := fixture()
	observation.Facts = nil
	for i := 0; i < MaxDiff; i++ {
		observation.Facts = append(observation.Facts, Fact{Domain: "role", Identity: fmt.Sprintf("id-%03d", i), Object: "safe", Field: "description", Classification: Supported, RoundTrip: Lossless, Value: Value{Text: strings.Repeat("<", 512)}})
	}
	result := Build(target, provider, observation, observation.Facts)
	data, _ := json.Marshal(result)
	if len(data) > MaxSummaryBytes || result.Complete || result.Approvable || !result.Truncated || len(result.Diff) >= MaxDiff {
		t.Fatal("escaped JSON bypassed the actual wire budget")
	}
	target, provider, observation, desired := fixture()
	for _, count := range []int{1, 513, 10000} {
		fact := Fact{Domain: "application", Identity: "client", Object: "safe", Field: "credentialPresence", Classification: SecurityExcluded, RoundTrip: PreservedNative, Value: Value{Text: strings.Repeat("s", count)}}
		obs := observation
		obs.Facts = append(append([]Fact(nil), obs.Facts...), fact)
		got := Build(target, provider, obs, desired)
		fact.Value.Text = "different"
		obs.Facts[len(obs.Facts)-1] = fact
		if got.CandidateHash != Build(target, provider, obs, desired).CandidateHash {
			t.Fatal("opaque credential length changed evidence")
		}
	}
}
func TestIdentityAndAggregateEdgeBounds(t *testing.T) {
	target, provider, observation, desired := fixture()
	target.UID = strings.Repeat("u", MaxProviderIDBytes+1)
	provider.Origin = strings.Repeat("o", 2049)
	provider.RealmID = strings.Repeat("r", MaxProviderIDBytes+1)
	provider.ObjectIDs = []string{strings.Repeat("i", MaxProviderIDBytes+1)}
	got := Build(target, provider, observation, desired)
	if got.Complete || got.Approvable || !got.Truncated || got.Target.UID != "" || got.ProviderIdentity.Origin != "" || len(got.ProviderIdentity.ObjectIDs) != 0 {
		t.Fatal("identity bounds failed closed")
	}
	target, provider, observation, _ = fixture()
	observation.Facts = nil
	for i := 0; i < 3; i++ {
		values := []string{}
		for j := 0; j < 400; j++ {
			values = append(values, fmt.Sprintf("edge-%04d", j))
		}
		observation.Facts = append(observation.Facts, Fact{Domain: "role", Identity: fmt.Sprintf("role-%d", i), Object: "role", Field: "composites", Classification: Supported, RoundTrip: Lossless, Value: Value{Set: values}})
	}
	got = Build(target, provider, observation, observation.Facts)
	currentEdges, desiredEdges := 0, 0
	for _, entry := range got.Diff {
		if entry.Current != nil {
			currentEdges += len(entry.Current.Set)
		}
		if entry.Desired != nil {
			desiredEdges += len(entry.Desired.Set)
		}
	}
	if got.Complete || !got.Truncated || currentEdges > MaxEdges || desiredEdges > MaxEdges {
		t.Fatal("aggregate edge budget was not applied to both projections")
	}
}
