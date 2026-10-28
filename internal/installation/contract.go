// Package installation verifies administrator-prepared OLM protections before
// the operator starts. The approved digest comes from the Subscription, not
// from the ConfigMap containing the contract.
package installation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/util/validation"
)

const MaxContractBytes = 512 * 1024

// Object records only security-relevant desired state; Kubernetes and OLM may
// legitimately add ownership metadata, resource versions and status.
type Object struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	Namespace  string          `json:"namespace,omitempty"`
	Spec       json.RawMessage `json:"spec"`
}

type CRD struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// Contract is rendered from the same chart as the corresponding installation.
type Contract struct {
	Namespace         string   `json:"namespace"`
	Deployment        string   `json:"deployment"`
	MinimumKubernetes string   `json:"minimumKubernetes"`
	MaximumKubernetes string   `json:"maximumKubernetes"`
	Objects           []Object `json:"objects"`
	CRDs              []CRD    `json:"crds"`
}

func Load(path, approvedDigest string) (*Contract, error) {
	if err := validateDigest(approvedDigest); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("installation contract is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxContractBytes+1))
	if err != nil {
		return nil, errors.New("installation contract cannot be read")
	}
	return Decode(data, approvedDigest)
}

func validateDigest(approvedDigest string) error {
	if len(approvedDigest) != sha256.Size*2 {
		return errors.New("an independently approved installation contract SHA-256 is required")
	}
	if _, err := hex.DecodeString(approvedDigest); err != nil {
		return errors.New("installation contract SHA-256 is invalid")
	}
	return nil
}

// Decode verifies a bounded contract read directly from a ConfigMap or file.
// Approval must come independently from the administrator's Subscription.
func Decode(data []byte, approvedDigest string) (*Contract, error) {
	if err := validateDigest(approvedDigest); err != nil {
		return nil, err
	}
	if len(data) > MaxContractBytes {
		return nil, errors.New("installation contract cannot be read within its size limit")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != approvedDigest {
		return nil, errors.New("installation contract differs from the independently approved SHA-256")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return nil, errors.New("installation contract JSON is invalid")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("installation contract must contain exactly one JSON object")
	}
	if err := contract.Validate(); err != nil {
		return nil, err
	}
	return &contract, nil
}

func (c *Contract) Validate() error {
	if len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.Deployment)) != 0 {
		return errors.New("installation contract requires an exact namespace and Deployment")
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, object := range c.Objects {
		key := object.Kind + "/" + object.Namespace + "/" + object.Name
		if seen[key] || len(validation.IsDNS1123Subdomain(object.Name)) != 0 {
			return errors.New("installation contract contains duplicate or invalid protection identities")
		}
		seen[key] = true
		if err := validateObjectIdentity(object, c.Namespace); err != nil {
			return err
		}
		if _, err := canonicalSpec(object.Kind, object.Spec); err != nil {
			return fmt.Errorf("installation contract contains an invalid %s specification", object.Kind)
		}
		counts[object.Kind]++
	}
	// The first OLM profile retains all eight baseline guards and both network
	// policies. Opt-in chart features may add protections, never remove them.
	if counts["ValidatingAdmissionPolicy"] < 8 || counts["ValidatingAdmissionPolicyBinding"] < 8 || counts["NetworkPolicy"] < 2 {
		return errors.New("installation contract omits baseline admission or network protections")
	}
	return validateCRDs(c.CRDs)
}

func validateCRDs(crds []CRD) error {
	if len(crds) < 17 {
		return errors.New("installation contract omits owned CRDs")
	}
	seen := map[string]bool{}
	for _, crd := range crds {
		if seen[crd.Name] || len(validation.IsDNS1123Subdomain(crd.Name)) != 0 || crd.Version != "v1alpha1" || crd.Kind == "" {
			return errors.New("installation contract contains an invalid or duplicate CRD")
		}
		seen[crd.Name] = true
	}
	return nil
}

func validateObjectIdentity(object Object, namespace string) error {
	switch object.Kind {
	case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
		if object.APIVersion == "admissionregistration.k8s.io/v1" && object.Namespace == "" {
			return nil
		}
	case "NetworkPolicy":
		if object.APIVersion == "networking.k8s.io/v1" && object.Namespace == namespace {
			return nil
		}
	}
	return errors.New("installation contract contains an unsupported protection identity")
}
