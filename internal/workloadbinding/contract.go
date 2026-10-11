// Package workloadbinding seals public workload configuration and delivers only
// metadata. It has no provider mutation or runtime credential interface.
package workloadbinding

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"k8s.io/apimachinery/pkg/util/validation"
)

const Schema = "hanko.sh/workload-runtime/v1alpha1"
const MetadataKey = "workload-identity.json"
const JournalKey = "hanko.sh/workload-runtime-journal"
const RuntimeFinalizer = "hanko.sh/workload-runtime-cleanup"
const TargetLabel = "hanko.sh/runtime-target"
const ConsentPrefix = "hanko.sh/workload-runtime-"

type Failure string

func (e Failure) Error() string { return string(e) }
func Reason(err error) string {
	var e Failure
	if errors.As(err, &e) {
		return string(e)
	}
	return "WorkloadBindingUnavailable"
}

var uidPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func KubernetesMode(sa *api.HankoServiceAccount) bool {
	return sa.Spec.Authentication != nil && sa.Spec.Authentication.Mode == "Kubernetes"
}
func ValidUID(value string) bool { return uidPattern.MatchString(value) }
func Validate(sa *api.HankoServiceAccount) error {
	if !validSource(sa) {
		return Failure("InvalidWorkloadBinding")
	}
	if reservedAttributes(sa) {
		return Failure("ReservedWorkloadAttribute")
	}
	if !KubernetesMode(sa) || sa.Spec.Authentication.Kubernetes == nil {
		return Failure("InvalidWorkloadBinding")
	}
	k := sa.Spec.Authentication.Kubernetes
	if len(validation.IsDNS1123Subdomain(k.TrustRef)) != 0 || len(validation.IsDNS1123Subdomain(k.SourceRef)) != 0 || !validWorkload(k.Workload) {
		return Failure("InvalidWorkloadBinding")
	}
	if sa.Spec.SecretRotationPolicy != nil && sa.Spec.SecretRotationPolicy.Enabled {
		return Failure("SecretRotationIncompatible")
	}
	if duration := Expiration(sa); duration < 600 || duration > 3600 {
		return Failure("InvalidProjectionLifetime")
	}
	if t := sa.Spec.RuntimeMetadata; t != nil && (len(validation.IsDNS1123Subdomain(t.ConfigMapRef)) != 0 || !ValidUID(t.ExpectedUID)) {
		return Failure("InvalidRuntimeTarget")
	}
	return nil
}

func validSource(sa *api.HankoServiceAccount) bool {
	return ValidUID(string(sa.UID)) && sa.Generation >= 1 && sa.Spec.ClientID != "" && len(sa.Spec.ClientID) <= 255 && !strings.ContainsAny(sa.Spec.ClientID, "\r\n\t")
}
func reservedAttributes(sa *api.HankoServiceAccount) bool {
	for key := range sa.Spec.Attributes {
		if strings.HasPrefix(key, "jwt.credential.") || strings.HasPrefix(key, "hanko.sh/workload-") {
			return true
		}
	}
	return false
}
func validWorkload(w api.KubernetesWorkloadBinding) bool {
	return len(validation.IsDNS1123Label(w.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(w.ServiceAccountRef)) == 0 && w.ServiceAccountRef != "default" && ValidUID(w.ExpectedUID)
}
func Expiration(sa *api.HankoServiceAccount) int64 {
	n := sa.Spec.Authentication.Kubernetes.ExpirationSeconds
	if n == 0 {
		return 600
	}
	return n
}

// References contains freshly verified public identities only. Credential UID
// and resourceVersion may contribute to SourceHash; credential bytes never do.
type References struct {
	TrustUID, ProviderID, RealmID, ClusterUID, CAHash string
	TrustGeneration                                   int64
	SourceHash, TrustHash, FlowHash                   string
	WorkloadUID, TargetUID, ConsentHash               string
	AssertionAudience, TokenEndpoint                  string
	TrustMaxAge                                       int64
	NativeClientID                                    string
}
type Plan struct {
	identity   iamcontract.PlanIdentity
	refs       References
	ownerUID   string
	generation int64
	revision   string
}

func Digest(purpose string, value any) string {
	b, _ := json.Marshal(value)
	return string(iamcontract.Hash(iamcontract.Version, "workload-binding", purpose, b))
}
func Compile(sa *api.HankoServiceAccount, r References) (Plan, error) {
	if err := Validate(sa); err != nil {
		return Plan{}, err
	}
	if r.WorkloadUID != sa.Spec.Authentication.Kubernetes.Workload.ExpectedUID {
		return Plan{}, Failure("WorkloadUIDMismatch")
	}
	if !r.valid() {
		return Plan{}, Failure("WorkloadTrustNotReady")
	}
	if r.TrustMaxAge < 600 || r.TrustMaxAge > 3600 || Expiration(sa) > r.TrustMaxAge {
		return Plan{}, Failure("ProjectionExceedsTrustAge")
	}
	if !publicEndpoint(r.AssertionAudience) || !publicEndpoint(r.TokenEndpoint) {
		return Plan{}, Failure("WorkloadTrustNotReady")
	}
	if sa.Spec.RuntimeMetadata != nil && (r.TargetUID != sa.Spec.RuntimeMetadata.ExpectedUID || !iamcontract.ValidDigest(r.ConsentHash)) {
		return Plan{}, Failure("TargetNotAuthorized")
	}
	intent := struct {
		Realm, ClientID string
		Authentication  *api.ServiceAccountAuthentication
		Metadata        *api.WorkloadRuntimeMetadataTarget
	}{sa.Spec.RealmRef, sa.Spec.ClientID, sa.Spec.Authentication, sa.Spec.RuntimeMetadata}
	id := iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: iamcontract.Digest(Digest("intent", intent))}
	id.Plan = iamcontract.Digest(Digest("plan", struct {
		Intent     iamcontract.Digest
		Owner      string
		Generation int64
		References References
	}{id.Intent, string(sa.UID), sa.Generation, r}))
	return Plan{identity: id, refs: r, ownerUID: string(sa.UID), generation: sa.Generation, revision: Digest("revision", id)}, nil
}

func (r References) valid() bool {
	return ValidUID(r.TrustUID) && ValidUID(r.ProviderID) && ValidUID(r.RealmID) && ValidUID(r.ClusterUID) && r.TrustGeneration >= 1 && iamcontract.ValidDigest(r.CAHash) && iamcontract.ValidDigest(r.SourceHash) && iamcontract.ValidDigest(r.TrustHash) && iamcontract.ValidDigest(r.FlowHash)
}
func publicEndpoint(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func (p Plan) Identity() iamcontract.PlanIdentity { return p.identity }
func (p Plan) References() References             { return p.refs }
func (p Plan) Revision() string                   { return p.revision }
func (p Plan) Validate(current Plan) error {
	if p.identity.Contract != iamcontract.Version || !iamcontract.ValidDigest(string(p.identity.Plan)) || p != current {
		return iamcontract.ErrStale
	}
	return nil
}

type Document struct {
	SchemaVersion               string                        `json:"schemaVersion"`
	ClientID                    string                        `json:"clientID"`
	TokenEndpoint               string                        `json:"tokenEndpoint"`
	AssertionType               string                        `json:"assertionType"`
	AssertionAudience           string                        `json:"assertionAudience"`
	RecommendedPath             string                        `json:"recommendedPath"`
	ExpirationSeconds           int64                         `json:"expirationSeconds"`
	TrustAssertionMaxAgeSeconds int64                         `json:"trustAssertionMaxAgeSeconds"`
	Workload                    api.KubernetesWorkloadBinding `json:"workload"`
	SourceNamespace             string                        `json:"sourceNamespace"`
	SourceName                  string                        `json:"sourceName"`
	SourceUID                   string                        `json:"sourceUID"`
	SourceGeneration            int64                         `json:"sourceGeneration"`
	BindingRevision             string                        `json:"bindingRevision"`
	// Binding metadata alone never claims that authentication has been enabled.
	AuthenticationActivation string `json:"authenticationActivation"`
}

func (p Plan) Metadata(sa *api.HankoServiceAccount) ([]byte, string, error) {
	if p.ownerUID != string(sa.UID) || p.generation != sa.Generation || !iamcontract.ValidDigest(p.revision) {
		return nil, "", iamcontract.ErrStale
	}
	d := Document{SchemaVersion: Schema, ClientID: sa.Spec.ClientID, TokenEndpoint: p.refs.TokenEndpoint, AssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", AssertionAudience: p.refs.AssertionAudience, RecommendedPath: "/var/run/hanko/assertion.jwt", ExpirationSeconds: Expiration(sa), TrustAssertionMaxAgeSeconds: p.refs.TrustMaxAge, Workload: sa.Spec.Authentication.Kubernetes.Workload, SourceNamespace: sa.Namespace, SourceName: sa.Name, SourceUID: string(sa.UID), SourceGeneration: sa.Generation, BindingRevision: p.revision, AuthenticationActivation: "ManagedSeparately"}
	b, err := json.Marshal(d)
	if err != nil || len(b) > 8192 {
		return nil, "", Failure("OutputTooLarge")
	}
	return b, Digest("metadata", d), nil
}
