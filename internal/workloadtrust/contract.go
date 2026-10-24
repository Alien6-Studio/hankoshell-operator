// Package workloadtrust seals the approved shared trust, independently of any
// client activation or workload binding. It never handles workload credentials.
package workloadtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloakversion"
)

const JournalVersion = "hanko.sh/workload-trust-journal/v1alpha1"
const AgeApprovalKey = "hanko.sh/workload-trust-age-review"

var ErrAnchor = errors.New("current cluster anchor differs from approved inputs")
var ErrDiscovery = errors.New("discovery source is not qualified for the current cluster")
var ErrOwnership = errors.New("workload trust ownership proof does not match current provider")
var ErrReview = errors.New("exact shared-age dependency review required")

type Intent struct {
	RealmRef, Alias, Issuer, DiscoveryURL, QualifiedVersion string
	NamespaceUID, CAHash                                    string
	MaxAge                                                  int64
}

type References struct {
	Owner                                                                            string
	Generation                                                                       int64
	RealmID, ProviderID, SourceHash, FreshReferencesHash, FlowHash, DependenciesHash string
}

type Plan struct {
	identity iamcontract.PlanIdentity
	intent   Intent
	refs     References
}

func (p Plan) Identity() iamcontract.PlanIdentity { return p.identity }
func (p Plan) Intent() Intent                     { return p.intent }
func (p Plan) References() References             { return p.refs }
func (p Plan) MarshalJSON() ([]byte, error)       { return json.Marshal(p.identity) }
func Digest(purpose string, value any) string {
	data, _ := json.Marshal(value)
	return string(iamcontract.Hash(iamcontract.Version, "workload-trust", purpose, data))
}

func ValidHTTPS(value string) bool {
	u, err := url.Parse(value)
	if err != nil || !validHTTPSShape(u, value) {
		return false
	}

	if u.Host != strings.ToLower(u.Host) || net.ParseIP(u.Hostname()) == nil && !dnsHost.MatchString(u.Hostname()) {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() {
			return false
		}
	}
	return validHTTPSPath(u.Path) && u.String() == value
}

func validHTTPSShape(u *url.URL, value string) bool {
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return false
	}
	return u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && !strings.ContainsAny(value, "\\ \t\r\n%")
}

func validHTTPSPath(path string) bool {
	if strings.Contains(path, "//") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

var dnsHost = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func Compile(i Intent, r References) (Plan, error) {
	if !validIntent(i) || !validReferences(r) {
		return Plan{}, iamcontract.ErrRejected
	}

	id := iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: iamcontract.Digest(Digest("intent", i))}
	id.Plan = iamcontract.Digest(Digest("plan", struct {
		Intent     iamcontract.Digest
		References References
	}{id.Intent, r}))
	return Plan{identity: id, intent: i, refs: r}, nil
}

func validIntent(i Intent) bool {
	if i.MaxAge < 600 || i.MaxAge > 3600 || i.Alias == "" || i.RealmRef == "" || !ValidHTTPS(i.Issuer) || i.NamespaceUID == "" || !iamcontract.ValidDigest(i.CAHash) {
		return false
	}
	if i.QualifiedVersion != "" && !keycloakversion.WorkloadIdentity(i.QualifiedVersion) {
		return false
	}
	return i.DiscoveryURL == "" || (ValidHTTPS(i.DiscoveryURL) && SupportsDiscoveryOverride(i.QualifiedVersion))
}

func validReferences(r References) bool {
	if !ValidOwner(r.Owner) || r.Generation < 1 || !ValidOwner(r.RealmID) || !ValidOwner(r.ProviderID) {
		return false
	}
	for _, hash := range []string{r.SourceHash, r.FreshReferencesHash, r.FlowHash, r.DependenciesHash} {
		if !iamcontract.ValidDigest(hash) {
			return false
		}
	}
	return true
}

func (p Plan) Validate(current Plan) error {
	if p.identity.Contract != iamcontract.Version || p.identity != current.identity || p.intent != current.intent || p.refs != current.refs {
		return iamcontract.ErrStale
	}
	_, err := Compile(p.intent, p.refs)
	return err
}

// APICAHash hashes the public DER of the one exact configured CA. Bundles with
// several different CAs, insecure transports, and system-root ambiguity must be
// rejected by the caller; PEM whitespace is not an identity change.
func APICAHash(data []byte) (string, error) {
	certs := map[string]bool{}
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", ErrAnchor
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return "", ErrAnchor
		}
		h := sha256.Sum256(cert.Raw)
		certs["sha256:"+hex.EncodeToString(h[:])] = true
		data = rest
	}
	if len(certs) != 1 {
		return "", ErrAnchor
	}
	for identity := range certs {
		return identity, nil
	}
	return "", ErrAnchor
}

// PlannedProviderID is chosen before POST and supplied as native internalId.
// Both qualified native JPA providers honor it. The first journal can therefore
// bind exact provider identity even when the POST acknowledgement is lost.
func PlannedProviderID(owner, realm, source string) string {
	h := sha256.Sum256([]byte(Digest("provider-id", []string{owner, realm, source})))
	b := hex.EncodeToString(h[:16])
	return b[:8] + "-" + b[8:12] + "-" + b[12:16] + "-" + b[16:20] + "-" + b[20:]
}

type Journal struct {
	Version    string `json:"version"`
	Owner      string `json:"owner"`
	Generation int64  `json:"generation"`
	ProviderID string `json:"providerID"`
	RealmID    string `json:"realmID"`
	SourceHash string `json:"sourceHash"`
	InputHash  string `json:"inputHash"`
	PlanHash   string `json:"planHash"`
	StateHash  string `json:"stateHash"`
	Step       string `json:"step"`
}

func (p Plan) Journal(stateHash, step string) (string, error) {
	j := Journal{JournalVersion, p.refs.Owner, p.refs.Generation, p.refs.ProviderID, p.refs.RealmID, p.refs.SourceHash, string(p.identity.Intent), string(p.identity.Plan), stateHash, step}
	if !j.valid() {
		return "", ErrOwnership
	}
	b, _ := json.Marshal(j)
	return string(b), nil
}
func (j Journal) valid() bool {
	return j.Version == JournalVersion && j.Owner != "" && len(j.Owner) <= 128 && j.Generation > 0 && j.ProviderID != "" && len(j.ProviderID) <= 128 && j.RealmID != "" && len(j.RealmID) <= 128 && iamcontract.ValidDigest(j.SourceHash) && iamcontract.ValidDigest(j.InputHash) && iamcontract.ValidDigest(j.PlanHash) && iamcontract.ValidDigest(j.StateHash) && (j.Step == "Applied" || j.Step == "Acquired")
}
func ParseJournal(value string) (Journal, error) {
	var j Journal
	if len(value) > 8192 {
		return j, ErrOwnership
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || !j.valid() {
		return Journal{}, ErrOwnership
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Journal{}, ErrOwnership
	}
	b, _ := json.Marshal(j)
	if string(b) != value {
		return Journal{}, ErrOwnership
	}
	return j, nil
}
func (j Journal) Matches(p Plan, stateHash string) bool {
	return j.valid() && j.Owner == p.refs.Owner && j.ProviderID == p.refs.ProviderID && j.RealmID == p.refs.RealmID && j.SourceHash == p.refs.SourceHash && j.StateHash == stateHash
}

// SharedAgeApproval is exact structured metadata, never a status latch or
// permanent permission. Review binds current generation/plan and full inventory.
type SharedAgeApproval struct {
	Contract         iamcontract.ContractVersion `json:"contract"`
	PlanHash         string                      `json:"planHash"`
	DependenciesHash string                      `json:"dependenciesHash"`
	ReviewHash       string                      `json:"reviewHash"`
}

func (p Plan) AgeReview(before int64) SharedAgeApproval {
	a := SharedAgeApproval{Contract: iamcontract.Version, PlanHash: string(p.identity.Plan), DependenciesHash: p.refs.DependenciesHash}
	a.ReviewHash = Digest("shared-age-review", struct {
		Approval      SharedAgeApproval
		Before, After int64
	}{a, before, p.intent.MaxAge})
	return a
}
func (p Plan) ApproveAge(value string, before int64) error {
	var approved SharedAgeApproval
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if len(value) > 1024 || d.Decode(&approved) != nil || approved != p.AgeReview(before) {
		return ErrReview
	}
	canonical, _ := json.Marshal(approved)
	if string(canonical) != value {
		return ErrReview
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrReview
	}
	return nil
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func ValidOwner(value string) bool { return safeID.MatchString(value) }

// SupportsDiscoveryOverride is a feature floor, not an exact qualification list.
// Native discovery, resolved-source read-back and ownership remain mandatory.
func SupportsDiscoveryOverride(version string) bool {
	return keycloakversion.DiscoveryOverride(version)
}
