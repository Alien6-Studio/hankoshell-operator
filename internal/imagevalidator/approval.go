package imagevalidator

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/distribution/reference"
)

// Purpose separates theme execution from managed identity-provider execution.
type Purpose string

const (
	// ThemeBuilder covers build, prune and deletion Jobs with theme PVC access.
	ThemeBuilder Purpose = "theme-builder"
	// Keycloak covers managed Keycloak Deployments with credential access.
	Keycloak       Purpose = "keycloak"
	maxPolicyBytes         = 64 * 1024
)

// ErrVerificationDenied deliberately excludes untrusted references and verifier
// output, either of which can contain credentials.
var ErrVerificationDenied = errors.New("imagevalidator: signed immutable workload image approval required")

var revisionPattern = regexp.MustCompile(`^([a-f0-9]{40}|[a-f0-9]{64})$`)

// SignatureVerifier checks the digest and signed source revision with a public key.
type SignatureVerifier interface {
	Verify(context.Context, string, string, string) error
}

// Approval binds a release-reviewed immutable image to its purpose and publisher.
// KeyFile is a public PEM key filename relative to the policy directory.
type Approval struct {
	Purpose  Purpose `json:"purpose"`
	Image    string  `json:"image"`
	Revision string  `json:"revision"`
	KeyFile  string  `json:"key_file"`
}

type approvalPolicy struct {
	Version   int        `json:"version"`
	Approvals []Approval `json:"approvals"`
}

// NewWithPolicy returns a validator backed by a release-owned policy file.
// Empty configuration denies all execution. Files are reloaded for each check,
// so projected ConfigMap key revocation does not depend on process restart.
func NewWithPolicy(policyFile string, verifier SignatureVerifier) *Validator {
	return &Validator{policyFile: policyFile, verifier: verifier}
}

// VerifyImage requires an exact digest approval and a valid publisher signature.
// Identity-only validators and nil validators cannot authorize execution.
func (v *Validator) VerifyImage(ctx context.Context, purpose Purpose, image string) error {
	approval, err := v.approvedImage(purpose, image)
	if err != nil {
		return err
	}
	key := filepath.Join(filepath.Dir(v.policyFile), approval.KeyFile)
	if v.verifier.Verify(ctx, image, key, approval.Revision) != nil {
		return ErrVerificationDenied
	}
	return nil
}

// ValidateWorkloadImage checks policy admission without fetching a signature.
// It cannot authorize submission; VerifyImage is required at creation/update.
func (v *Validator) ValidateWorkloadImage(purpose Purpose, image string) error {
	_, err := v.approvedImage(purpose, image)
	return err
}

func (v *Validator) approvedImage(purpose Purpose, image string) (Approval, error) {
	if v == nil || v.policyFile == "" || v.verifier == nil || !immutableImage(image) {
		return Approval{}, ErrVerificationDenied
	}
	policy, err := readPolicy(v.policyFile)
	if err != nil {
		return Approval{}, ErrVerificationDenied
	}
	for _, approval := range policy.Approvals {
		if approval.Purpose == purpose && approval.Image == image {
			key := filepath.Join(filepath.Dir(v.policyFile), approval.KeyFile)
			if !publicKeyFile(key) {
				return Approval{}, ErrVerificationDenied
			}
			return approval, nil
		}
	}
	return Approval{}, ErrVerificationDenied
}

func immutableImage(image string) bool {
	named, err := reference.ParseNamed(image)
	if err != nil || named.String() != image {
		return false
	}
	if _, tagged := named.(reference.Tagged); tagged {
		return false
	}
	digested, ok := named.(reference.Digested)
	return ok && digested.Digest().Algorithm().String() == "sha256"
}

func readPolicy(path string) (approvalPolicy, error) {
	var policy approvalPolicy
	data, err := readBoundedFile(path, maxPolicyBytes)
	if err != nil {
		return policy, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, err
	}
	if decoder.Decode(new(any)) != io.EOF || policy.Version != 1 || len(policy.Approvals) > 128 {
		return policy, ErrVerificationDenied
	}
	seen := make(map[string]bool, len(policy.Approvals))
	for _, approval := range policy.Approvals {
		identity := string(approval.Purpose) + ":" + approval.Image
		if seen[identity] || !validApproval(approval) {
			return policy, ErrVerificationDenied
		}
		seen[identity] = true
	}
	return policy, nil
}

func validApproval(approval Approval) bool {
	return (approval.Purpose == ThemeBuilder || approval.Purpose == Keycloak) &&
		immutableImage(approval.Image) && revisionPattern.MatchString(approval.Revision) &&
		approval.KeyFile != "" && filepath.Base(approval.KeyFile) == approval.KeyFile &&
		!strings.ContainsAny(approval.KeyFile, `/\\`) && strings.HasSuffix(approval.KeyFile, ".pub")
}

func publicKeyFile(path string) bool {
	data, err := readBoundedFile(path, 16*1024)
	if err != nil {
		return false
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	return err == nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open image policy material: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrVerificationDenied
	}
	return data, nil
}
