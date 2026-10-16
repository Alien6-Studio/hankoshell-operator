package iamconformance

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// PortableCorpus is test data, not a universal production provider interface.
// Each real executor still uses domain-specific compilers and drivers.
type PortableCorpus struct {
	SchemaVersion int               `json:"schemaVersion"`
	Name          string            `json:"name"`
	Providers     []string          `json:"providers"`
	Fixtures      []PortableFixture `json:"fixtures"`
}
type PortableExpectation struct {
	Classification iamcontract.FindingClassification `json:"classification"`
	Reason         string                            `json:"reason"`
	Evidence       string                            `json:"evidence"`
	Phase          string                            `json:"phase"`
	PlanEvidence   bool                              `json:"planEvidence"`
	StatusReason   string                            `json:"statusReason"`
}
type PortableManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}
type PortableFixture struct {
	Name       string                         `json:"name"`
	Capability string                         `json:"capability"`
	Manifest   PortableManifest               `json:"manifest"`
	Expected   map[string]PortableExpectation `json:"expected"`
	// IntentIdentity freezes compiler output where two implementations exist.
	IntentIdentity iamcontract.Digest `json:"intentIdentity,omitempty"`
}

//go:embed testdata/portable-v1/corpus.json
var portableCorpus embed.FS

func ReadPortableCorpus() (PortableCorpus, error) {
	data, err := portableCorpus.ReadFile("testdata/portable-v1/corpus.json")
	if err != nil {
		return PortableCorpus{}, fmt.Errorf("read portable corpus: %w", err)
	}
	return DecodePortableCorpus(data)
}
func DecodePortableCorpus(data []byte) (PortableCorpus, error) {
	var result PortableCorpus
	if len(data) > 262144 {
		return result, errors.New("portable corpus exceeds its budget")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("invalid portable corpus wire format")
	}
	if result.SchemaVersion != 1 || result.Name != "portable-v1" || !slices.Equal(result.Providers, []string{"keycloak", "authentik"}) || len(result.Fixtures) != 14 {
		return result, errors.New("portable corpus has an unreviewed provider or domain inventory")
	}
	seen := map[string]bool{}
	names := map[string]bool{}
	capabilities := []string{"identity_domain", "iam_profile", "oidc_public", "oidc_confidential", "machine_identity", "saml", "realm_roles", "composite_roles", "organization", "resource_server", "service_account", "workload_federation", "bounded_delegation", "native_extension"}
	for _, f := range result.Fixtures {
		if seen[f.Capability] || names[f.Name] || !slices.Contains(capabilities, f.Capability) || !validPortableManifest(f) || len(f.Expected) != len(result.Providers) {
			return result, errors.New("portable fixture has missing or duplicate intent/classification")
		}
		seen[f.Capability] = true
		names[f.Name] = true
		if !validExpectations(f.Expected, result.Providers) {
			return result, errors.New("portable fixture has an unreviewed semantic outcome")
		}
	}
	return result, nil
}

func validExpectations(values map[string]PortableExpectation, providers []string) bool {
	for _, provider := range providers {
		expected, ok := values[provider]
		if !ok || expected.Evidence == "" {
			return false
		}
		switch expected.Classification {
		case iamcontract.Lossless:
			if expected.Reason != "" || expected.Phase != "Ready" || expected.StatusReason != "" {
				return false
			}
		case iamcontract.Unsupported:
			if expected.Reason == "" || expected.Phase != "Error" || expected.PlanEvidence || expected.StatusReason == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validPortableManifest(f PortableFixture) bool {
	kinds := map[string]string{"identity_domain": "HankoRealm", "iam_profile": "HankoIAMProfile", "oidc_public": "HankoApplication", "oidc_confidential": "HankoApplication", "machine_identity": "HankoApplication", "saml": "HankoApplication", "realm_roles": "HankoRole", "composite_roles": "HankoRole", "organization": "HankoOrganization", "resource_server": "HankoResourceServer", "service_account": "HankoServiceAccount", "workload_federation": "HankoWorkloadTrust", "bounded_delegation": "HankoResourceServer", "native_extension": "HankoApplication"}
	if (f.Name == "spa" || f.Name == "web") && !portableDigest.MatchString(string(f.IntentIdentity)) {
		return false
	}
	return f.Name != "" && f.Manifest.APIVersion == "hanko.sh/v1alpha1" && f.Manifest.Metadata.Name != "" && f.Manifest.Kind == kinds[f.Capability] && json.Valid(f.Manifest.Spec)
}
