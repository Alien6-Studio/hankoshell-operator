// Package adoption constructs bounded review evidence. It has no provider or
// Kubernetes client and cannot acquire ownership or execute a plan.
package adoption

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

type ContractVersion string

const Version ContractVersion = "hanko.sh/adoption-contract/v1alpha1"

const (
	MaxRealms          = 16
	MaxInventory       = 1024
	MaxNodes           = 512
	MaxEdges           = 1024
	MaxDepth           = 32
	MaxDiff            = 256
	MaxFindings        = 32
	MaxSummaryBytes    = 192 * 1024
	MaxProviderIDBytes = 128
	MaxReferenceBytes  = 255
	MaxTextBytes       = 512
)

type TargetIdentity struct {
	TenantRef  string `json:"tenantRef,omitempty"`
	Generation int64  `json:"generation,omitempty"`
	ImportRef  string `json:"importRef,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// ProviderIdentity binds configuration and immutable provider identities. The
// AdminRef and credentials are deliberately absent. CAIdentity is the public
// trust bundle digest plus the Secret UID, never a credential digest.
type ProviderIdentity struct {
	Instance    TargetIdentity `json:"instance"`
	Origin      string         `json:"origin"`
	Trust       string         `json:"trust"`
	CAReference string         `json:"caReference,omitempty"`
	CAIdentity  string         `json:"caIdentity,omitempty"`
	RealmID     string         `json:"realmID"`
	ObjectIDs   []string       `json:"objectIDs,omitempty"`
}

type Code string

const (
	Equal               Code = "equal"
	WouldManage         Code = "would-manage"
	WouldChange         Code = "would-change"
	WouldPreserve       Code = "would-preserve"
	NativeReadOnly      Code = "provider-native-readonly"
	Unsupported         Code = "unsupported"
	CredentialExcluded  Code = "credential-excluded"
	RecreationRequired  Code = "recreation-required"
	OwnershipTransition Code = "ownership-transition"
)

type Classification string

const (
	Supported         Classification = "supported-typed-native"
	Preserved         Classification = "preserved-readonly-native"
	UnsupportedNative Classification = "unsupported"
	Conflicting       Classification = "conflicting"
	SecurityExcluded  Classification = "security-sensitive-excluded"
)

type RoundTrip string

const (
	Lossless             RoundTrip = "lossless-represented"
	PreservedNative      RoundTrip = "preserved-native"
	Lossy                RoundTrip = "lossy"
	UnsupportedRoundTrip RoundTrip = "unsupported"
)

// Value is restricted to explicit semantic fields below. No arbitrary JSON,
// mapper configuration, credential value or provider representation is allowed.
type Value struct {
	Text string   `json:"text,omitempty"`
	Set  []string `json:"set,omitempty"`
	Flag *bool    `json:"flag,omitempty"`
}
type Fact struct {
	Domain         string         `json:"domain"`
	Identity       string         `json:"identity"`
	Object         string         `json:"object"`
	Field          string         `json:"field"`
	Classification Classification `json:"classification"`
	RoundTrip      RoundTrip      `json:"roundTrip"`
	Value          Value          `json:"value"`
}
type Finding struct {
	Code     string `json:"code"`
	Domain   string `json:"domain"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}
type Coverage struct {
	Complete         bool   `json:"complete"`
	Truncated        bool   `json:"truncated"`
	InventoryCount   int    `json:"inventoryCount"`
	CandidateCount   int    `json:"candidateCount"`
	UnsupportedCount int    `json:"unsupportedCount"`
	ObservationHash  string `json:"observationHash,omitempty"`
}
type Observation struct {
	Facts     []Fact    `json:"facts"`
	Complete  bool      `json:"complete"`
	Truncated bool      `json:"truncated"`
	Findings  []Finding `json:"findings,omitempty"`
}
type DiffEntry struct {
	Domain         string         `json:"domain"`
	Identity       string         `json:"identity"`
	Object         string         `json:"object"`
	Field          string         `json:"field"`
	Code           Code           `json:"code"`
	Classification Classification `json:"classification"`
	RoundTrip      RoundTrip      `json:"roundTrip"`
	Current        *Value         `json:"current,omitempty"`
	Desired        *Value         `json:"desired,omitempty"`
}
type Diff struct {
	Entries []DiffEntry `json:"entries"`
}
type Candidate struct {
	ContractVersion  ContractVersion  `json:"contractVersion"`
	Target           TargetIdentity   `json:"target"`
	ProviderIdentity ProviderIdentity `json:"providerIdentity"`
	ObservationHash  string           `json:"observationHash"`
	DiffHash         string           `json:"diffHash"`
	CandidateHash    string           `json:"candidateHash"`
	Complete         bool             `json:"complete"`
	Truncated        bool             `json:"truncated"`
	Approvable       bool             `json:"approvable"`
	Diff             []DiffEntry      `json:"diff,omitempty"`
	Findings         []Finding        `json:"findings,omitempty"`
}

// Fields is a closed, reviewed safe projection. A new projection must extend
// this list and its tests, rather than hashing arbitrary provider maps.
var fields = map[string]bool{
	"name": true, "description": true, "protocol": true, "pattern": true,
	"enabled": true, "publicClient": true, "standardFlow": true, "serviceAccounts": true,
	"directAccessGrants": true, "implicitFlow": true, "fullScopeAllowed": true,
	"redirectURIs": true, "postLogoutURIs": true, "webOrigins": true, "owner": true,
	"composites": true, "effectiveComposites": true, "container": true,
	"path": true, "parent": true, "realmRoles": true, "clientRoles": true,
	"alias": true, "domains": true, "mapperType": true, "mapperClaim": true,
	"mapperRoles": true, "mapperFlags": true, "providerType": true, "brokerEndpoints": true,
	"acs": true, "nameID": true, "signedAssertions": true, "signedResponses": true,
	"nativePresence": true, "credentialPresence": true, "attributes": true,
	"nativeLocale": true, "authorizationServices": true,
	"keycloakDefault.realm_client":                             true,
	"keycloakDefault.backchannel.logout.session.required":      true,
	"keycloakDefault.backchannel.logout.revoke.offline.tokens": true,
	"scopes": true, "resources": true, "policies": true, "principals": true,
	"logic": true, "decisionStrategy": true, "uris": true, "type": true,
	"theme": true, "runtimeBindings": true, "mode": true, "realmRef": true, "importLatch": true, "claimSource": true,
	"credentialRotation": true,
}

func key(f Fact) string { return f.Domain + "\x00" + f.Identity + "\x00" + f.Object + "\x00" + f.Field }
func digest(domain string, v any) string {
	b, _ := json.Marshal(v)
	return string(iamcontract.Hash(iamcontract.ContractVersion(Version), domain, "evidence", b))
}
func validFact(f Fact) bool {
	if !validNativeLocaleFact(f) || !validAuthorizationFeatureFact(f) {
		return false
	}
	if !validKeycloakDefaultFact(f) {
		return false
	}
	if !fields[f.Field] || len(f.Domain) > 64 || len(f.Identity) > MaxProviderIDBytes || len(f.Object) > MaxReferenceBytes || len(f.Field) > 64 || len(f.Value.Text) > MaxTextBytes || len(f.Value.Set) > MaxEdges {
		return false
	}
	for _, s := range f.Value.Set {
		if len(s) > MaxTextBytes {
			return false
		}
	}
	return true
}

func validNativeLocaleFact(f Fact) bool {
	if f.Field != "nativeLocale" {
		return true
	}
	return (f.Domain == "group" || f.Domain == "organization" || f.Domain == "application" || f.Domain == "service-account" || f.Domain == "role" || f.Domain == "client-role") && (f.Value.Text == "en" || f.Value.Text == "fr") && len(f.Value.Set) == 0 && f.Value.Flag == nil && f.Classification == Preserved && f.RoundTrip == PreservedNative
}

func validKeycloakDefaultFact(f Fact) bool {
	const prefix = "keycloakDefault."
	if !strings.HasPrefix(f.Field, prefix) {
		return true
	}
	return KeycloakDefault(strings.TrimPrefix(f.Field, prefix), f.Value.Text) && len(f.Value.Set) == 0 && f.Value.Flag == nil && f.Classification == Preserved && f.RoundTrip == PreservedNative
}
func normalize(facts []Fact) ([]Fact, bool) {
	result := make([]Fact, 0, len(facts))
	valid := true
	for _, f := range facts {
		if f.Classification == SecurityExcluded {
			present := f.Value.Text != "" || len(f.Value.Set) > 0 || (f.Value.Flag != nil && *f.Value.Flag)
			f.Value = Value{Flag: &present}
		}
		if !validFact(f) {
			valid = false
			continue
		}
		f.Value.Set = append([]string(nil), f.Value.Set...)
		slices.Sort(f.Value.Set)
		f.Value.Set = slices.Compact(f.Value.Set)
		result = append(result, f)
	}
	slices.SortFunc(result, func(a, b Fact) int {
		if c := strings.Compare(key(a), key(b)); c != 0 {
			return c
		}
		return strings.Compare(digest("sort", a), digest("sort", b))
	})
	for i := 1; i < len(result); i++ {
		if key(result[i-1]) == key(result[i]) {
			valid = false
		}
	}
	return result, valid
}

// Build returns evidence only. Even Approvable=true grants no write authority.
func Build(target TargetIdentity, provider ProviderIdentity, observation Observation, desired []Fact) Candidate {
	facts, valid := normalize(observation.Facts)
	want, desiredValid := normalize(desired)
	c := Candidate{ContractVersion: Version, Target: target, ProviderIdentity: provider, Complete: observation.Complete && valid && desiredValid, Truncated: observation.Truncated, Findings: append([]Finding(nil), observation.Findings...)}
	if observation.Truncated {
		c.Findings = append(c.Findings, Finding{"read_budget_exceeded", "observation", "provider inventory exceeded its bounded read budget", true})
	}
	if !valid || !desiredValid {
		c.Truncated = true
		c.Findings = append(c.Findings, Finding{"unsafe_projection", "observation", "semantic projection is ambiguous or outside the safe field budget", true})
	}
	if len(facts) > MaxNodes || len(want) > MaxNodes {
		c.Truncated = true
		c.Complete = false
		facts = facts[:min(len(facts), MaxNodes)]
		want = want[:min(len(want), MaxNodes)]
		c.Findings = append(c.Findings, Finding{"graph_budget_exceeded", "observation", "semantic graph exceeds the observation budget", true})
	}
	factsTruncated, desiredTruncated := boundEdges(facts), boundEdges(want)
	if factsTruncated || desiredTruncated {
		c.Complete = false
		c.Truncated = true
		c.Findings = append(c.Findings, Finding{"edge_budget_exceeded", "observation", "semantic graph exceeds its aggregate edge budget", true})
	}
	provider.ObjectIDs = append([]string(nil), provider.ObjectIDs...)
	slices.Sort(provider.ObjectIDs)
	provider.ObjectIDs = slices.Compact(provider.ObjectIDs)
	if len(provider.ObjectIDs) > MaxNodes {
		provider.ObjectIDs = provider.ObjectIDs[:MaxNodes]
		c.Truncated = true
		c.Complete = false
		c.Findings = append(c.Findings, Finding{"identity_budget_exceeded", "identity", "provider identities exceed the graph node budget", true})
	}
	c.ProviderIdentity = provider
	c.Diff = compareFacts(facts, want)
	if len(c.Diff) > MaxDiff {
		c.Diff = c.Diff[:MaxDiff]
		c.Truncated = true
		c.Complete = false
		c.Findings = append(c.Findings, Finding{"diff_budget_exceeded", "diff", "typed diff exceeds its public budget", true})
	}
	if c.Truncated {
		c.Complete = false
	}
	c.validateIdentity()
	c.boundFindings()
	c.evaluateApprovability()
	c.boundWire()
	c.ObservationHash = digest("adoption-observation", struct {
		Provider    ProviderIdentity
		Observation Observation
	}{c.ProviderIdentity, Observation{facts, c.Complete, c.Truncated, c.Findings}})
	c.DiffHash = digest("adoption-diff", struct {
		Target  TargetIdentity
		Desired []Fact
		Diff    Diff
	}{c.Target, want, Diff{c.Diff}})
	c.CandidateHash = digest("adoption-candidate", struct {
		Version                         ContractVersion
		Target                          TargetIdentity
		Provider                        ProviderIdentity
		Observation, Diff               string
		Complete, Truncated, Approvable bool
	}{Version, c.Target, c.ProviderIdentity, c.ObservationHash, c.DiffHash, c.Complete, c.Truncated, c.Approvable})
	return c
}
func appendFinding(fs []Finding, f Finding) []Finding {
	for _, v := range fs {
		if v.Code == f.Code {
			return fs
		}
	}
	if len(fs) == MaxFindings {
		fs = fs[:MaxFindings-1]
	}
	return append(fs, f)
}

func compareFacts(facts, want []Fact) []DiffEntry {
	var result []DiffEntry
	wanted := map[string]Fact{}
	for _, f := range want {
		wanted[key(f)] = f
	}
	for _, f := range facts {
		entry := DiffEntry{Domain: f.Domain, Identity: f.Identity, Object: f.Object, Field: f.Field, Classification: f.Classification, RoundTrip: f.RoundTrip, Code: WouldPreserve}
		value := f.Value
		entry.Current = &value
		if w, ok := wanted[key(f)]; ok {
			v := w.Value
			entry.Desired = &v
			entry.Code = Equal
			if digest("value", value) != digest("value", v) {
				entry.Code = WouldChange
			}
			delete(wanted, key(f))
		}
		classifyDiff(&entry, f)
		result = append(result, entry)
	}
	for _, f := range wanted {
		value := f.Value
		entry := DiffEntry{Domain: f.Domain, Identity: f.Identity, Object: f.Object, Field: f.Field, Code: WouldManage, Classification: f.Classification, RoundTrip: f.RoundTrip, Desired: &value}
		classifyDiff(&entry, f)
		result = append(result, entry)
	}
	slices.SortFunc(result, func(a, b DiffEntry) int {
		return strings.Compare(a.Domain+"\x00"+a.Identity+"\x00"+a.Object+"\x00"+a.Field, b.Domain+"\x00"+b.Identity+"\x00"+b.Object+"\x00"+b.Field)
	})

	return result
}

func (c *Candidate) validateIdentity() {
	if c.ProviderIdentity.Trust != "public-ca" && c.ProviderIdentity.Trust != "private-ca" && c.ProviderIdentity.Trust != "explicit-http" {
		c.ProviderIdentity.Trust = "unknown"
		c.Complete = false
		c.Findings = appendFinding(c.Findings, Finding{"trust_identity_incomplete", "identity", "current verified trust selection is unavailable", true})
	}
	if c.Target.UID == "" || c.ProviderIdentity.Instance.UID == "" || c.ProviderIdentity.RealmID == "" || c.ProviderIdentity.Origin == "" {
		c.Findings = append(c.Findings, Finding{"identity_incomplete", "identity", "current Kubernetes and provider identities are required", true})
	}
	validIDs := []string{}
	for _, id := range c.ProviderIdentity.ObjectIDs {
		if id == "" || len(id) > MaxProviderIDBytes {
			c.Complete = false
			c.Truncated = true
			c.Findings = appendFinding(c.Findings, Finding{"identity_budget_exceeded", "identity", "provider identity is outside its byte budget", true})
			continue
		}
		validIDs = append(validIDs, id)
	}
	c.ProviderIdentity.ObjectIDs = validIDs
	c.boundIdentity()
}

func (c *Candidate) boundIdentity() {
	// Reject oversized identity strings instead of publishing or hashing an
	// unbounded endpoint/UID. Empty identity remains diagnostic evidence only.
	identityFields := []struct {
		value *string
		limit int
	}{
		{&c.Target.Kind, 64}, {&c.Target.Namespace, MaxReferenceBytes}, {&c.Target.Name, MaxReferenceBytes}, {&c.Target.UID, MaxProviderIDBytes}, {&c.Target.ImportRef, MaxReferenceBytes}, {&c.Target.TenantRef, MaxReferenceBytes},
		{&c.ProviderIdentity.Instance.Kind, 64}, {&c.ProviderIdentity.Instance.Namespace, MaxReferenceBytes}, {&c.ProviderIdentity.Instance.Name, MaxReferenceBytes}, {&c.ProviderIdentity.Instance.UID, MaxProviderIDBytes},
		{&c.ProviderIdentity.Origin, 2048}, {&c.ProviderIdentity.RealmID, MaxProviderIDBytes}, {&c.ProviderIdentity.Trust, 32}, {&c.ProviderIdentity.CAReference, MaxReferenceBytes}, {&c.ProviderIdentity.CAIdentity, MaxReferenceBytes},
	}
	for _, field := range identityFields {
		if len(*field.value) > field.limit {
			*field.value = ""
			c.Complete = false
			c.Truncated = true
			c.Findings = appendFinding(c.Findings, Finding{"identity_budget_exceeded", "identity", "identity is outside its public byte budget", true})
		}
	}
}

func (c *Candidate) boundFindings() {
	slices.SortFunc(c.Findings, func(a, b Finding) int {
		if order := strings.Compare(a.Domain+"\x00"+a.Code, b.Domain+"\x00"+b.Code); order != 0 {
			return order
		}
		if a.Blocking != b.Blocking {
			if a.Blocking {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Message, b.Message)
	})
	c.Findings = slices.CompactFunc(c.Findings, func(a, b Finding) bool { return a.Domain == b.Domain && a.Code == b.Code })
	if len(c.Findings) > MaxFindings {
		c.Findings = append(c.Findings[:MaxFindings-1], Finding{"finding_budget_exceeded", "observation", "additional findings omitted from bounded evidence", true})
		c.Complete = false
		c.Truncated = true
	}
	for i, f := range c.Findings {
		if len(f.Code) > MaxTextBytes || len(f.Message) > MaxTextBytes || len(f.Domain) > 64 {
			c.Findings[i] = Finding{"unsafe_finding", "observation", "finding exceeds its local text budget", true}
			c.Complete = false
		}
	}
}

func (c *Candidate) evaluateApprovability() {
	c.Approvable = c.Complete && !c.Truncated
	for _, f := range c.Findings {
		c.Approvable = c.Approvable && !f.Blocking
	}
	for _, e := range c.Diff {
		if e.Code == Unsupported || e.Code == RecreationRequired || e.Classification == Conflicting || e.RoundTrip == Lossy || e.RoundTrip == UnsupportedRoundTrip {
			c.Approvable = false
		}
	}
}

func (c *Candidate) boundWire() {
	// Enforce the actual wire budget, including escaped JSON and all envelopes.
	for {
		b, _ := json.Marshal(c)
		if len(b) <= MaxSummaryBytes-1024 {
			break
		}
		c.Complete = false
		c.Truncated = true
		c.Approvable = false
		if len(c.Diff) > 0 {
			c.Diff = c.Diff[:len(c.Diff)-1]
		} else {
			c.ProviderIdentity.ObjectIDs = nil
			break
		}
		c.Findings = appendFinding(c.Findings, Finding{"summary_budget_exceeded", "diff", "serialized public candidate exceeds its byte budget", true})
	}
}

func classifyDiff(entry *DiffEntry, f Fact) {
	switch f.Classification {
	case Preserved:
		entry.Code = NativeReadOnly
	case UnsupportedNative:
		entry.Code = Unsupported
	case Conflicting:
		entry.Code = OwnershipTransition
	case SecurityExcluded:
		entry.Code = CredentialExcluded
		entry.Current = nil
		entry.Desired = nil
	}
	if f.Field == "owner" && f.Value.Text == "unmarked" {
		entry.Code = OwnershipTransition
	}
	if entry.Code == WouldChange && (slices.Contains([]string{"protocol", "container", "parent", "realmRoles", "clientRoles"}, f.Field) || f.Field == "composites" && f.Domain != "role") {
		entry.Code = RecreationRequired
	}
	if f.Field == "credentialRotation" && f.Value.Flag != nil && *f.Value.Flag {
		entry.Code = RecreationRequired
	}
}

func boundEdges(facts []Fact) bool {
	remaining := MaxEdges
	truncated := false
	for i := range facts {
		if len(facts[i].Value.Set) > remaining {
			facts[i].Value.Set = facts[i].Value.Set[:remaining]
			truncated = true
		}
		remaining -= len(facts[i].Value.Set)
	}
	return truncated
}

func validAuthorizationFeatureFact(f Fact) bool {
	if f.Field != "authorizationServices" {
		return true
	}
	return (f.Domain == "application" || f.Domain == "service-account") && f.Value.Flag != nil && f.Value.Text == "" && len(f.Value.Set) == 0 && f.Classification == Preserved && f.RoundTrip == PreservedNative
}
