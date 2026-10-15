// Package fleetplan verifies locally approved, bounded fleet desired state.
// It performs no network, Kubernetes or provider operations. See ADR-049.
package fleetplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	strictjson "sigs.k8s.io/json"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const (
	EnvelopeVersion = "hanko.sh/fleet-envelope/v1alpha1"
	TrustVersion    = "hanko.sh/fleet-trust/v1alpha1"
	MaxEnvelope     = 1 << 20
	MaxTrust        = 64 << 10
	MaxObjects      = 200
	MaxValidity     = time.Hour
	ClockSkew       = 30 * time.Second
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{40}$`)

// Refusal carries a locally authored reason, never remote fields or payloads.
type Refusal string

func (r Refusal) Error() string { return "fleet plan refused: " + string(r) }

// Reason returns safe public evidence independent of remote error bodies.
func Reason(err error) string {
	var refusal Refusal
	if errors.As(err, &refusal) {
		return string(refusal)
	}
	return "FleetPlanFailed"
}

type Envelope struct {
	Version   string `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Scope struct {
	TenantID   string `json:"tenantID"`
	ClusterID  string `json:"clusterID"`
	Namespace  string `json:"namespace"`
	TenantName string `json:"tenantName"`
}

type Target struct {
	Scope
	TenantUID string `json:"tenantUID"`
}

type Source struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
	Digest     string `json:"digest"`
}

// Content retains the existing finite bundle kinds, without remote lifecycle
// metadata or an independent tenant/version override.
type Content struct {
	IAMProfiles     []json.RawMessage `json:"iamProfiles,omitempty"`
	Realms          []json.RawMessage `json:"realms,omitempty"`
	Apps            []json.RawMessage `json:"apps,omitempty"`
	Themes          []json.RawMessage `json:"themes,omitempty"`
	ServiceAccounts []json.RawMessage `json:"serviceAccounts,omitempty"`
}

type Plan struct {
	Issuer                 string              `json:"issuer"`
	KeyID                  string              `json:"keyID"`
	Target                 Target              `json:"target"`
	Source                 Source              `json:"source"`
	ContractVersion        string              `json:"contractVersion"`
	Sequence               int64               `json:"sequence"`
	IssuedAt               time.Time           `json:"issuedAt"`
	NotBefore              time.Time           `json:"notBefore"`
	ExpiresAt              time.Time           `json:"expiresAt"`
	Requirements           []string            `json:"requirements,omitempty"`
	MinimumOperatorVersion string              `json:"minimumOperatorVersion,omitempty"`
	ObjectRequirements     []ObjectRequirement `json:"objectRequirements,omitempty"`
	Mode                   string              `json:"mode"`
	RollbackOf             string              `json:"rollbackOf,omitempty"`
	Content                Content             `json:"content"`
}

type Key struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	PublicKey string    `json:"publicKey"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Scopes    []Scope   `json:"scopes"`
	Sources   []string  `json:"sources"`
}

type Trust struct {
	Version string `json:"version"`
	Keys    []Key  `json:"keys"`
}

// Checkpoint is public monotonic evidence, not a bearer credential. Applied is
// only meaningful for the same identity and never permits skipping verification.
type Checkpoint struct {
	Sequence int64
	Identity string
	Applied  bool
}

// Verified is a sealed in-process result. Accessors copy mutable content.
type Verified struct {
	plan     Plan
	identity string
	current  bool
}

func (v Verified) Identity() string { return v.identity }
func (v Verified) Current() bool    { return v.current }
func (v Verified) Plan() Plan {
	p := v.plan
	p.Requirements = slices.Clone(p.Requirements)
	p.ObjectRequirements = slices.Clone(p.ObjectRequirements)
	for i := range p.ObjectRequirements {
		p.ObjectRequirements[i].Requirements = slices.Clone(p.ObjectRequirements[i].Requirements)
	}
	clone := func(raws []json.RawMessage) []json.RawMessage {
		out := make([]json.RawMessage, len(raws))
		for i, raw := range raws {
			out[i] = bytes.Clone(raw)
		}
		return out
	}
	p.Content = Content{clone(p.Content.IAMProfiles), clone(p.Content.Realms), clone(p.Content.Apps), clone(p.Content.Themes), clone(p.Content.ServiceAccounts)}
	return p
}

// SigningInput binds exact decoded payload bytes to one protocol. No JSON
// reserialization, untrusted algorithm selection or remote key discovery occurs.
func SigningInput(payload []byte) []byte {
	return append([]byte(EnvelopeVersion+"\x00"), payload...)
}

func decode(data []byte, limit int, target any) bool {
	if len(data) == 0 || len(data) > limit || httpsecurity.ValidateJSON(data) != nil {
		return false
	}
	failures, err := strictjson.UnmarshalStrict(data, target)
	return err == nil && len(failures) == 0
}

func decode64(value string, limit int) ([]byte, bool) {
	if len(value) > limit*4/3+4 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && len(decoded) <= limit && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// Verify requires independently approved keys, exact target/source binding and
// durable sequence evidence. Capability requirements are evaluated separately
// against locally observed provider authority before content delivery.
func Verify(envelope, trust []byte, target Target, now time.Time, checkpoint Checkpoint) (Verified, error) {
	var e Envelope
	var t Trust
	if !decode(envelope, MaxEnvelope, &e) || e.Version != EnvelopeVersion {
		return Verified{}, Refusal("FleetEnvelopeInvalid")
	}
	payload, ok := decode64(e.Payload, MaxEnvelope*3/4)
	var p Plan
	if !ok || !decode(payload, MaxEnvelope*3/4, &p) {
		return Verified{}, Refusal("FleetPayloadInvalid")
	}
	if !decodeTrust(trust, &t) {
		return Verified{}, Refusal("FleetTrustInvalid")
	}
	key, err := approvedKey(t, p, now)
	if err != nil {
		return Verified{}, err
	}
	signature, ok := decode64(e.Signature, ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, SigningInput(payload), signature) {
		return Verified{}, Refusal("FleetSignatureInvalid")
	}
	if err := validatePlan(p, target, now); err != nil {
		return Verified{}, err
	}
	digest := sha256.Sum256(SigningInput(payload))
	identity := "sha256:" + hex.EncodeToString(digest[:])
	if err := verifyCheckpoint(p.Sequence, identity, checkpoint); err != nil {
		return Verified{}, err
	}
	return Verified{p, identity, p.Sequence == checkpoint.Sequence && checkpoint.Applied}, nil
}

func decodeTrust(data []byte, trust *Trust) bool {
	return decode(data, MaxTrust, trust) && trust.Version == TrustVersion && len(trust.Keys) > 0 && len(trust.Keys) <= 32
}

func verifyCheckpoint(sequence int64, identity string, checkpoint Checkpoint) error {
	if checkpoint.Sequence < 0 || (checkpoint.Sequence == 0) != (checkpoint.Identity == "") || (checkpoint.Sequence > 0 && !iamcontract.ValidDigest(checkpoint.Identity)) {
		return Refusal("FleetCheckpointInvalid")
	}
	if sequence < checkpoint.Sequence {
		return Refusal("FleetPlanDowngrade")
	}
	if sequence == checkpoint.Sequence && identity != checkpoint.Identity {
		return Refusal("FleetSequenceConflict")
	}
	return nil
}

func validatePlan(p Plan, target Target, now time.Time) error {
	if !validTarget(target) || p.Target != target {
		return Refusal("FleetTargetMismatch")
	}
	if p.ContractVersion != string(iamcontract.Version) || !revision.MatchString(p.Source.Revision) || !iamcontract.ValidDigest(p.Source.Digest) {
		return Refusal("FleetSourceInvalid")
	}
	if err := validity(p, now); err != nil {
		return err
	}
	if err := validateContent(p.Content, p.Target); err != nil {
		return err
	}
	if p.RollbackOf != "" && !iamcontract.ValidDigest(p.RollbackOf) {
		return Refusal("FleetRollbackReferenceInvalid")
	}
	return validateRollout(p)
}

func validScope(s Scope) bool {
	return identifier.MatchString(s.TenantID) && identifier.MatchString(s.ClusterID) && identifier.MatchString(s.Namespace) && identifier.MatchString(s.TenantName)
}

func validTarget(t Target) bool { return validScope(t.Scope) && identifier.MatchString(t.TenantUID) }

func approvedKey(t Trust, p Plan, now time.Time) (ed25519.PublicKey, error) {
	seen := make(map[string]bool)
	var selected *Key
	for i := range t.Keys {
		k := &t.Keys[i]
		if seen[k.ID] || !validKey(*k) {
			return nil, Refusal("FleetTrustInvalid")
		}
		seen[k.ID] = true
		if k.ID == p.KeyID && k.Issuer == p.Issuer {
			selected = k
		}
	}
	if selected == nil {
		return nil, Refusal("FleetKeyUnapproved")
	}
	if now.Before(selected.NotBefore) || !now.Before(selected.NotAfter) {
		return nil, Refusal("FleetKeyExpired")
	}
	if !slices.Contains(selected.Scopes, p.Target.Scope) || !slices.Contains(selected.Sources, p.Source.Repository) {
		return nil, Refusal("FleetIssuerAuthorityMismatch")
	}
	public, _ := decode64(selected.PublicKey, ed25519.PublicKeySize)
	return ed25519.PublicKey(public), nil
}

func validKey(k Key) bool {
	public, ok := decode64(k.PublicKey, ed25519.PublicKeySize)
	if !identifier.MatchString(k.ID) || !ok || len(public) != ed25519.PublicKeySize ||
		k.Issuer == "" || len(k.Issuer) > 256 || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) ||
		len(k.Scopes) == 0 || len(k.Scopes) > 64 || len(k.Sources) == 0 || len(k.Sources) > 16 {
		return false
	}
	return validKeyScope(k)
}

func validKeyScope(k Key) bool {
	for _, scope := range k.Scopes {
		if !validScope(scope) {
			return false
		}
	}
	for _, source := range k.Sources {
		if source == "" || len(source) > 256 {
			return false
		}
	}
	return true
}

func validity(p Plan, now time.Time) error {
	if p.Sequence < 1 || p.IssuedAt.IsZero() || p.NotBefore.IsZero() || p.ExpiresAt.IsZero() ||
		!p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > MaxValidity || p.NotBefore.After(p.ExpiresAt) ||
		p.NotBefore.Before(p.IssuedAt.Add(-ClockSkew)) {
		return Refusal("FleetValidityInvalid")
	}
	if p.IssuedAt.After(now.Add(ClockSkew)) || p.NotBefore.After(now.Add(ClockSkew)) {
		return Refusal("FleetPlanNotYetValid")
	}
	if !now.Before(p.ExpiresAt) {
		return Refusal("FleetPlanExpired")
	}
	return nil
}

func validateContent(content Content, target Target) error {
	total := 0
	for _, group := range []struct {
		kind string
		raws []json.RawMessage
	}{{"HankoIAMProfile", content.IAMProfiles}, {"HankoRealm", content.Realms}, {"HankoApplication", content.Apps},
		{"HankoTheme", content.Themes}, {"HankoServiceAccount", content.ServiceAccounts}} {
		total += len(group.raws)
		if total > MaxObjects {
			return Refusal("FleetContentInvalid")
		}
		for _, raw := range group.raws {
			if err := validateObject(raw, group.kind, target); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateObject(raw json.RawMessage, kind string, target Target) error {
	var object struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations,omitempty"`
		} `json:"metadata"`
		Spec json.RawMessage `json:"spec"`
	}
	if !decode(raw, 64<<10, &object) || object.APIVersion != "hanko.sh/v1alpha1" || object.Kind != kind ||
		object.Metadata.Name == "" || len(object.Metadata.Name) > 253 ||
		object.Metadata.Namespace != target.Namespace || object.Metadata.Labels["hanko.sh/tenant"] != target.TenantName ||
		len(bytes.TrimSpace(object.Spec)) == 0 || bytes.TrimSpace(object.Spec)[0] != '{' {
		return Refusal("FleetContentInvalid")
	}
	for key := range object.Metadata.Annotations {
		if reserved(key) {
			return Refusal("FleetContentAuthorityInvalid")
		}
	}
	for key := range object.Metadata.Labels {
		if key != "hanko.sh/tenant" && reserved(key) {
			return Refusal("FleetContentAuthorityInvalid")
		}
	}
	return nil
}

func reserved(key string) bool {
	return strings.HasPrefix(key, "hanko.sh/") || strings.HasPrefix(key, "hanko.io/") || strings.HasPrefix(key, "mesh.hanko.io/")
}
