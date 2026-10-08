package imagevalidator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const approvedImage = "registry.example/hanko/theme-builder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type recordingVerifier struct {
	calls                int
	err                  error
	image, key, revision string
}

func (v *recordingVerifier) Verify(_ context.Context, image, key, revision string) error {
	v.calls++
	v.image, v.key, v.revision = image, key, revision
	return v.err
}

func policyFixture(t *testing.T) (string, Approval) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	approval := Approval{Purpose: ThemeBuilder, Image: approvedImage, Revision: strings.Repeat("1", 40), KeyFile: "publisher.pub"}
	path := filepath.Join(dir, "policy.json")
	writeApprovalPolicy(t, path, approval)
	return path, approval
}

func writeApprovalPolicy(t *testing.T, path string, approvals ...Approval) {
	t.Helper()
	data, err := json.Marshal(approvalPolicy{Version: 1, Approvals: approvals})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadApprovalRequiresDigestPurposeAndPublisher(t *testing.T) {
	path, approval := policyFixture(t)
	verifier := &recordingVerifier{}
	v := NewWithPolicy(path, verifier)
	for _, image := range []string{
		"registry.example/hanko/theme-builder:latest",
		"registry.example/hanko/theme-builder:v1@sha256:" + strings.Repeat("a", 64),
		"registry.example/hanko/theme-builder@sha256:" + strings.Repeat("b", 64),
		strings.Replace(approvedImage, "registry.example/", "registry.example.attacker.test/", 1),
		strings.Replace(approvedImage, "theme-builder@", "theme-builder-attacker@", 1),
		"https://user:secret@registry.example/hanko/theme-builder",
	} {
		if err := v.VerifyImage(context.Background(), ThemeBuilder, image); !errors.Is(err, ErrVerificationDenied) {
			t.Fatalf("accepted %q: %v", image, err)
		}
	}
	if v.VerifyImage(context.Background(), Keycloak, approvedImage) == nil || verifier.calls != 0 {
		t.Fatal("invalid admission reached signature verifier")
	}
	if err := v.VerifyImage(context.Background(), ThemeBuilder, approvedImage); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.image != approval.Image || verifier.revision != approval.Revision || verifier.key != filepath.Join(filepath.Dir(path), approval.KeyFile) {
		t.Fatalf("publisher binding lost: %+v", verifier)
	}
	verifier.err = errors.New("registry unavailable: password=do-not-disclose")
	if err := v.VerifyImage(context.Background(), ThemeBuilder, approvedImage); err != ErrVerificationDenied || strings.Contains(err.Error(), "do-not-disclose") {
		t.Fatalf("verification did not fail closed/redact: %v", err)
	}
}

func TestWorkloadApprovalRevocationHasNoSuccessCache(t *testing.T) {
	path, approval := policyFixture(t)
	verifier := &recordingVerifier{}
	v := NewWithPolicy(path, verifier)
	for range 2 {
		if err := v.VerifyImage(context.Background(), ThemeBuilder, approvedImage); err != nil {
			t.Fatal(err)
		}
	}
	if verifier.calls != 2 {
		t.Fatal("signature verification was cached")
	}
	writeApprovalPolicy(t, path)
	if v.VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil {
		t.Fatal("revoked digest remained admitted")
	}
	writeApprovalPolicy(t, path, approval)
	if err := os.Remove(filepath.Join(filepath.Dir(path), approval.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if v.VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil {
		t.Fatal("revoked publisher key remained admitted")
	}
}

func TestDatabaseBackupApprovalIsIndependentAndRechecksRevocation(t *testing.T) {
	path, approval := policyFixture(t)
	approval.Purpose = DatabaseBackup
	writeApprovalPolicy(t, path, approval)
	verifier := &recordingVerifier{}
	v := NewWithPolicy(path, verifier)
	if err := v.VerifyImage(context.Background(), DatabaseBackup, approval.Image); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []Purpose{ThemeBuilder, Keycloak, OperatorUpdate} {
		if err := v.VerifyImage(context.Background(), purpose, approval.Image); err != ErrVerificationDenied {
			t.Fatalf("backup approval authorized %s: %v", purpose, err)
		}
	}
	if verifier.calls != 1 {
		t.Fatal("unrelated purpose reached publisher verification")
	}
	changing := changingKeyVerifier{change: func() { writeApprovalPolicy(t, path) }}
	if err := NewWithPolicy(path, changing).VerifyImage(context.Background(), DatabaseBackup, approval.Image); err != ErrVerificationDenied {
		t.Fatalf("revoked backup approval survived signature verification: %v", err)
	}
}

func TestWorkloadPublisherKeyReplacementDuringVerificationDenied(t *testing.T) {
	for _, purpose := range []Purpose{ThemeBuilder, Keycloak, DatabaseBackup} {
		t.Run(string(purpose), func(t *testing.T) {
			path, approval := policyFixture(t)
			approval.Purpose = purpose
			writeApprovalPolicy(t, path, approval)
			otherPath, otherApproval := policyFixture(t)
			replacement, err := os.ReadFile(filepath.Join(filepath.Dir(otherPath), otherApproval.KeyFile))
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			verifier := changingKeyVerifier{change: func() {
				if err := root.WriteFile("publisher.pub", replacement, 0600); err != nil {
					t.Fatal(err)
				}
			}}
			if err := NewWithPolicy(path, verifier).VerifyImage(context.Background(), purpose, approval.Image); err != ErrVerificationDenied {
				t.Fatalf("replaced workload publisher key remained authorized: %v", err)
			}
		})
	}
}

func TestMalformedPolicyAndMissingVerifierDenyExecution(t *testing.T) {
	path, approval := policyFixture(t)
	verifier := &recordingVerifier{}
	for _, v := range []*Validator{nil, NewWithPrefixes("registry.example"), NewWithPolicy(path, nil), NewWithPolicy("", verifier)} {
		if v.VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil {
			t.Fatal("missing signature policy admitted execution")
		}
	}
	for _, mutate := range []func(*Approval){
		func(a *Approval) { a.KeyFile = "../publisher.pub" },
		func(a *Approval) { a.KeyFile = "azurekms://signing-key" },
		func(a *Approval) { a.Purpose = "unknown" },
		func(a *Approval) { a.Revision = "main" },
	} {
		invalid := approval
		mutate(&invalid)
		writeApprovalPolicy(t, path, invalid)
		if NewWithPolicy(path, verifier).VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil {
			t.Fatal("invalid policy admitted execution")
		}
	}
	writeApprovalPolicy(t, path, approval, approval)
	if NewWithPolicy(path, verifier).VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil {
		t.Fatal("ambiguous duplicate approval accepted")
	}
	writeApprovalPolicy(t, path, approval)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), approval.KeyFile), []byte("-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	if NewWithPolicy(path, verifier).VerifyImage(context.Background(), ThemeBuilder, approvedImage) == nil || verifier.calls != 0 {
		t.Fatal("private/nonpublic key passed to verifier")
	}
}
