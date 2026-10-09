// Package applications separates application identity semantics from provider
// representation, local Kubernetes authority and credential storage.
package applications

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const OwnerAttribute = "hanko.sh/application-owner"
const MigrationUUIDAnnotation = "hanko.sh/migrate-keycloak-client-uuid"
const MigrationObservationAnnotation = "hanko.sh/migrate-keycloak-observation"
const POSTBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

var ErrOwnershipConflict = errors.New("application client requires exact UUID and observation approval before adoption")
var ErrProtocolChange = errors.New("owned application protocol change requires recreation")
var ErrProtocolMismatch = errors.New("observed application protocol differs from desired protocol")

type Role struct{ Name, Description string }
type Claim struct {
	Name, Claim, UserAttribute, JSONType, RealmRolePrefix                  string
	Value                                                                  *string
	RealmRoles, Multivalued, IDToken, AccessToken, UserInfo, Introspection bool
}
type IdentityMapping struct {
	Name, Provider, Claim, MatchValue, SyncMode string
	RealmRole, ClientRole, UserAttribute        string
}
type Projection struct{ Namespace, Name string }
type Rotation struct {
	Enabled       bool
	IntervalDays  int
	ForceRotateAt string
}
type SAML struct {
	ACS              []string
	SignedAssertions bool
	NameIDFormat     string
}

// Intent is explicit semantic input, never a CR, status or Secret payload.
type Intent struct {
	RealmRef, ClientID, Protocol, Pattern, Theme  string
	RedirectURIs, PostLogoutURIs, RealmRoleScopes []string
	ScopesManaged                                 bool
	Roles                                         []Role
	Claims                                        []Claim
	IdentityMappings                              []IdentityMapping
	SAML                                          *SAML
	Rotation                                      *Rotation
	Projections                                   []Projection
}

// ResolvedReferences contains only non-secret local/provider mapping inputs.
// Mapper representations are private adapter inputs and never plan serialization.
type ResolvedReferences struct {
	Realm, Owner, PublicBase string
	Attributes               map[string]string
	Mappers                  []keycloak.ProtocolMapper
	IdentityMappers          []keycloak.IdentityProviderMapper
	MigrationUUID            string
	MigrationObservation     iamcontract.Digest
}
type Capabilities struct {
	OIDC, PublicClient, ConfidentialClient, SAML, SAMLACS   bool
	SAMLAssertionSigning, SAMLResponseSigning, SAMLMetadata bool
	ClientRoles, ProtocolMappers                            bool
}
type CapabilityEvidence struct {
	Supported      Capabilities
	Source, Window string
	Findings       []iamcontract.Finding
}

func KeycloakEvidence() CapabilityEvidence {
	return CapabilityEvidence{Supported: Capabilities{true, true, true, true, true, true, true, true, true, true}, Source: "adapter-and-real-qualification", Window: "26.7.5,26.8.0"}
}

type State struct {
	Present, Owned bool
	Created        bool
	Protocol       string
	ProviderID     string // local migration/deletion check only; never a public authority.
	Observation    iamcontract.Observation
	Findings       []iamcontract.Finding
}
type Metadata struct{ Issuer, Authorization, Token, JWKS, UserInfo, SSO, URL string }
type Driver interface {
	Capabilities(context.Context) (CapabilityEvidence, error)
	Observe(context.Context, Plan) (State, error)
	Ensure(context.Context, Plan) (State, error)
	DeleteOwned(context.Context, Plan) error
	Metadata(context.Context, Plan) (Metadata, error)
}
type Plan struct {
	identity      iamcontract.PlanIdentity
	intent        Intent
	resolved      ResolvedReferences
	evidence      CapabilityEvidence
	preconditions iamcontract.Preconditions
}

func (p Plan) Identity() iamcontract.PlanIdentity { return p.identity }
func (p Plan) Evidence() CapabilityEvidence       { return p.evidence }
func (p Plan) MarshalJSON() ([]byte, error)       { return json.Marshal(p.identity) }
func (p Plan) Validate(current Plan) error {
	if p.identity != current.identity || p.preconditions != current.preconditions || p.identity.Contract != iamcontract.Version {
		return iamcontract.ErrStale
	}
	return validate(p.intent, p.resolved, current.evidence)
}
func Protocol(protocol string) string {
	if protocol == "" {
		return "oidc"
	}
	return protocol
}
func Normalize(i Intent) Intent {
	// Clone explicit domain semantics before sorting; no shared mutable plan input.
	data, _ := json.Marshal(i)
	var result Intent
	_ = json.Unmarshal(data, &result)
	result.Protocol = Protocol(result.Protocol)
	if result.Protocol == "oidc" && result.Pattern == "" {
		result.Pattern = "web"
	}
	result.RedirectURIs = stringSet(result.RedirectURIs)
	result.PostLogoutURIs = stringSet(result.PostLogoutURIs)
	result.RealmRoleScopes = stringSet(result.RealmRoleScopes)
	for n := range result.Claims {
		if result.Claims[n].JSONType == "" {
			result.Claims[n].JSONType = "String"
		}
		if result.Claims[n].RealmRoles {
			result.Claims[n].Multivalued = true
		}
	}
	for n := range result.IdentityMappings {
		if result.IdentityMappings[n].SyncMode == "" {
			result.IdentityMappings[n].SyncMode = "FORCE"
		}
	}
	if result.SAML != nil {
		result.SAML.ACS = stringSet(result.SAML.ACS)
		if result.SAML.NameIDFormat == "" {
			result.SAML.NameIDFormat = "persistent"
		}
	}
	slices.SortFunc(result.Roles, func(a, b Role) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.Claims, func(a, b Claim) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.IdentityMappings, func(a, b IdentityMapping) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.Projections, func(a, b Projection) int { return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name) })
	if result.Roles == nil {
		result.Roles = []Role{}
	}
	if result.Claims == nil {
		result.Claims = []Claim{}
	}
	if result.IdentityMappings == nil {
		result.IdentityMappings = []IdentityMapping{}
	}
	if result.Projections == nil {
		result.Projections = []Projection{}
	}
	return result
}
func stringSet(values []string) []string {
	result := append([]string{}, values...)
	slices.Sort(result)
	return slices.Compact(result)
}
func IntentIdentity(i Intent) iamcontract.Digest {
	data, _ := json.Marshal(Normalize(i))
	return iamcontract.Hash(iamcontract.Version, "applications", "intent", data)
}
func Compile(i Intent, r ResolvedReferences, e CapabilityEvidence, pre iamcontract.Preconditions) (Plan, error) {
	i = Normalize(i)
	e.Findings = append([]iamcontract.Finding(nil), e.Findings...)
	data, _ := json.Marshal(r)
	var resolved ResolvedReferences
	_ = json.Unmarshal(data, &resolved)
	if resolved.Attributes == nil {
		resolved.Attributes = map[string]string{}
	}
	if err := validate(i, resolved, e); err != nil {
		return Plan{}, err
	}
	id := iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: IntentIdentity(i)}
	canonical, _ := json.Marshal(struct {
		Intent                iamcontract.Digest
		Backend               iamcontract.BackendKind
		Resolved              ResolvedReferences
		References, Authority iamcontract.Digest
	}{id.Intent, id.Backend, resolved, pre.References, pre.Authority})
	id.Plan = iamcontract.Hash(iamcontract.Version, "applications", "plan", canonical)
	return Plan{identity: id, intent: i, resolved: resolved, evidence: e, preconditions: pre}, nil
}
func validate(i Intent, r ResolvedReferences, e CapabilityEvidence) error {
	if iamcontract.Accept(e.Findings) != nil || i.RealmRef == "" || i.ClientID == "" || r.Realm == "" || r.Owner == "" {
		return iamcontract.ErrRejected
	}
	for key := range r.Attributes {
		if ReservedAttribute(key) {
			return iamcontract.ErrRejected
		}
	}
	switch i.Protocol {
	case "oidc":
		if err := validateOIDC(i, e); err != nil {
			return err
		}
	case "saml":
		if err := validateSAML(i, e); err != nil {
			return err
		}
	default:
		return iamcontract.ErrRejected
	}

	if requiresMissingCapability(i, e.Supported) {
		return iamcontract.ErrRejected
	}
	return nil
}
func requiresMissingCapability(i Intent, c Capabilities) bool {
	return len(i.Roles) > 0 && !c.ClientRoles || len(i.Claims) > 0 && !c.ProtocolMappers
}
func validateOIDC(i Intent, e CapabilityEvidence) error {
	if !e.Supported.OIDC || i.SAML != nil || !slices.Contains([]string{"web", "spa", "m2m"}, i.Pattern) {
		return iamcontract.ErrRejected
	}
	if i.Pattern == "spa" && !e.Supported.PublicClient || i.Pattern != "spa" && !e.Supported.ConfidentialClient {
		return iamcontract.ErrRejected
	}
	return nil
}
func supportsSAML(c Capabilities) bool {
	return c.SAML && c.SAMLACS && c.SAMLAssertionSigning && c.SAMLResponseSigning && c.SAMLMetadata
}
func validateSAML(i Intent, e CapabilityEvidence) error {
	c := e.Supported
	if !supportsSAML(c) || i.SAML == nil {
		return iamcontract.ErrRejected
	}
	if !i.SAML.SignedAssertions || i.Pattern != "" || len(i.RedirectURIs)+len(i.PostLogoutURIs)+len(i.Claims)+len(i.IdentityMappings)+len(i.Projections) > 0 || i.ScopesManaged || i.Rotation != nil {
		return iamcontract.ErrRejected
	}
	if !validEntity(i.ClientID) || len(i.SAML.ACS) < 1 || len(i.SAML.ACS) > 8 {
		return iamcontract.ErrRejected
	}
	for _, acs := range i.SAML.ACS {
		if !ValidACS(acs) {
			return iamcontract.ErrRejected
		}
	}
	if !slices.Contains([]string{"persistent", "transient", "email", "unspecified"}, i.SAML.NameIDFormat) {
		return iamcontract.ErrRejected
	}
	return nil
}
func validEntity(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 255 && u.IsAbs() && u.User == nil && u.Fragment == "" && !strings.ContainsAny(value, " \t\r\n\\*") && (u.Opaque != "" || u.Hostname() != "")
}

var exactACS = regexp.MustCompile(`^https://([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:[0-9]{1,5})?(/[^\s?#@\\*]*)?$`)

func ValidACS(value string) bool {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || !exactACS.MatchString(value) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, " \t\r\n\\*@") {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return !strings.ContainsAny(u.Path, "\r\n\\*")
}

// ReservedAttribute is shared by validation and observation filtering. Secret
// material is never admitted into native metadata, canonical plans or findings.
func ReservedAttribute(key string) bool {
	k := strings.ToLower(key)
	if sensitiveMetadata(k) {
		return true
	}
	if strings.HasPrefix(k, "saml") || strings.HasPrefix(k, "hanko.") || strings.HasPrefix(k, "hanko.sh/") {
		return true
	}
	return slices.Contains([]string{"protocol", "login_theme", "post.logout.redirect.uris", "password", "client_secret", "client-secret", "access_token", "bearer-token", "private_key", "private-key", "credential"}, k)
}
func cloneAttributes(attributes map[string]string) map[string]string {
	result := maps.Clone(attributes)
	if result == nil {
		return map[string]string{}
	}
	return result
}
