// Package applicationbinding delivers proven application identity through
// preauthorized Kubernetes resources. It contains no provider operations.
package applicationbinding

import (
	"encoding/json"
	"fmt"
	"strconv"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const Schema = "hanko.sh/application-runtime/v1alpha1"
const MetadataKey = "identity.json"
const CredentialKey = "client_secret"
const MaxBindings = 32
const MaxDocumentBytes = 16384
const RevisionAnnotation = "hanko.sh/runtime-binding-revision"
const JournalAnnotation = "hanko.sh/runtime-bindings-journal"

// Proof is calculated from current provider read-back by the caller. Persisted
// status alone cannot construct execution authority; Deliver requires a verifier.
type Proof struct {
	ApplicationUID                               string
	Generation                                   int64
	ContractVersion, IntentHash, AppliedPlanHash string
	Protocol, Pattern, ClientID                  string
	OIDC                                         *api.OIDCEndpoints
	SAML                                         *api.SAMLEndpoints
	NameIDFormat                                 string
}

// Document is the versioned, public workload contract. No credential values,
// provider UUIDs, administrative endpoints or metadata XML belong here.
type Document struct {
	SchemaVersion     string                         `json:"schemaVersion"`
	Protocol          string                         `json:"protocol"`
	ClientID          string                         `json:"clientID"`
	Workload          api.ApplicationRuntimeWorkload `json:"workload"`
	ServiceAccountUID string                         `json:"serviceAccountUID"`
	OIDC              *api.OIDCEndpoints             `json:"oidc,omitempty"`
	SAML              *SAMLMetadata                  `json:"saml,omitempty"`
	Credentials       *CredentialReference           `json:"credentials,omitempty"`
	Source            SourceEvidence                 `json:"source"`
	BindingRevision   string                         `json:"bindingRevision"`
}

// SAMLMetadata contains only the qualified IdP-facing subset.
type SAMLMetadata struct {
	Issuer       string `json:"issuer"`
	SSO          string `json:"sso"`
	Metadata     string `json:"metadata"`
	NameIDFormat string `json:"nameIDFormat"`
}

// CredentialReference names the workload-owned output, never the source value.
type CredentialReference struct {
	SecretRef string `json:"secretRef"`
	Key       string `json:"key"`
}

// SourceEvidence identifies the generation proven by the IAM adapter.
type SourceEvidence struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	Generation      int64  `json:"generation"`
	ContractVersion string `json:"contractVersion"`
	IntentHash      string `json:"intentHash"`
	AppliedPlanHash string `json:"appliedPlanHash"`
}

// CredentialVersion is Kubernetes identity/version metadata, never a digest of
// a credential. ResourceVersion also changes for harmless source metadata edits.
type CredentialVersion struct{ UID, ResourceVersion string }

func runtimeDocument(app *api.HankoApplication, binding api.ApplicationRuntimeBinding, uid string, proof Proof) Document {
	d := Document{SchemaVersion: Schema, Protocol: proof.Protocol, ClientID: proof.ClientID,
		Workload: binding.Workload, ServiceAccountUID: uid, OIDC: proof.OIDC,
		Source: SourceEvidence{app.Namespace, app.Name, proof.Generation, proof.ContractVersion, proof.IntentHash, proof.AppliedPlanHash}}
	if proof.SAML != nil {
		d.SAML = &SAMLMetadata{proof.SAML.Issuer, proof.SAML.SSO, proof.SAML.Metadata, proof.NameIDFormat}
	}
	if binding.Credentials != nil {
		d.Credentials = &CredentialReference{binding.Credentials.SecretRef, CredentialKey}
	}
	return d
}

// Encode uses a fixed struct shape and Go's deterministic map-free JSON. The
// revision hashes public contract and non-secret Kubernetes identities only.
func Encode(document Document, credential CredentialVersion, configMapUID, secretUID string) ([]byte, string, string, error) {
	document.BindingRevision = ""
	base, err := json.Marshal(document)
	if err != nil {
		return nil, "", "", err
	}
	identity, err := json.Marshal(struct {
		Document                json.RawMessage
		Credential              CredentialVersion
		ConfigMapUID, SecretUID string
	}{base, credential, configMapUID, secretUID})
	if err != nil {
		return nil, "", "", err
	}
	revision := string(iamcontract.Hash(iamcontract.ContractVersion(Schema), "runtime", "revision", identity))
	document.BindingRevision = revision
	data, err := json.Marshal(document)
	if err != nil {
		return nil, "", "", err
	}
	if len(data) > MaxDocumentBytes {
		return nil, "", "", failure("OutputTooLarge")
	}
	hash := string(iamcontract.Hash(iamcontract.ContractVersion(Schema), "runtime", "metadata", data))
	return data, hash, revision, nil
}

// Failure renders only locally selected stable reasons. Kubernetes errors may
// contain object payloads; those are not rendered into status, logs or Events.
type Failure struct{ Reason string }

func (e *Failure) Error() string  { return "runtime binding: " + e.Reason }
func failure(reason string) error { return &Failure{Reason: reason} }
func Reason(err error) string {
	if value, ok := err.(*Failure); ok {
		return value.Reason
	}
	return "OutputFailed"
}

func proofMatches(app *api.HankoApplication, p Proof) bool {
	s := app.Status
	return string(app.UID) != "" && string(app.UID) == p.ApplicationUID && app.Generation == p.Generation &&
		s.EvaluatedGeneration == p.Generation && s.AppliedGeneration == p.Generation && s.ObservationGeneration == p.Generation &&
		s.ObservationComplete && s.DriftState == "InSync" && s.ContractVersion == p.ContractVersion &&
		s.IntentHash == p.IntentHash && s.EvaluatedPlanHash == p.AppliedPlanHash && s.AppliedPlanHash == p.AppliedPlanHash && s.ObservationPlanHash == p.AppliedPlanHash &&
		validProofIdentity(p)
}
func validProofIdentity(p Proof) bool {
	return p.ContractVersion == string(iamcontract.Version) && iamcontract.ValidDigest(p.IntentHash) && iamcontract.ValidDigest(p.AppliedPlanHash)
}

func outputAnnotations(app *api.HankoApplication, binding string, hash, revision string, proof Proof) map[string]string {
	return map[string]string{
		"hanko.sh/runtime-schema": Schema, "hanko.sh/runtime-source-uid": string(app.UID),
		"hanko.sh/runtime-delivered-binding": binding, "hanko.sh/runtime-source-generation": strconv.FormatInt(proof.Generation, 10),
		"hanko.sh/runtime-applied-plan-hash": proof.AppliedPlanHash, RevisionAnnotation: revision,
		"hanko.sh/runtime-metadata-hash": hash,
	}
}

func validateProtocol(p Proof) error {
	switch p.Protocol {
	case "oidc":
		if p.OIDC == nil || p.SAML != nil || p.OIDC.Issuer == "" || p.OIDC.Token == "" || p.OIDC.JWKS == "" {
			return failure("ApplicationNotReady")
		}
	case "saml":
		if p.SAML == nil || p.OIDC != nil || p.SAML.Issuer == "" || p.SAML.SSO == "" || p.SAML.Metadata == "" || p.NameIDFormat == "" {
			return failure("ApplicationNotReady")
		}
	default:
		return failure("InvalidProtocol")
	}
	return nil
}

func targetIdentity(kind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}
