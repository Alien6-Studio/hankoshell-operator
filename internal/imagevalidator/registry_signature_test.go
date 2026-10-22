package imagevalidator

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type registryVerifier struct {
	recordingVerifier
	registryCalls int
	afterVerify   func()
}

func (v *registryVerifier) VerifyRegistrySignature(_ context.Context, image, key, revision string) error {
	v.registryCalls++
	v.image, v.key, v.revision = image, key, revision
	if v.afterVerify != nil {
		v.afterVerify()
	}
	return v.err
}

func TestRegistrySignatureRequiresExactExplicitApproval(t *testing.T) {
	path, approval := policyFixture(t)
	verifier := &registryVerifier{}
	v := NewWithPolicy(path, verifier)
	if err := v.VerifyImage(context.Background(), ThemeBuilder, approval.Image); err != nil || verifier.calls != 1 || verifier.registryCalls != 0 {
		t.Fatal("default verification did not retain transparency", err)
	}
	approval.RegistryOnly = true
	writeApprovalPolicy(t, path, approval)
	if NewWithPolicy(path, &recordingVerifier{}).VerifyImage(context.Background(), ThemeBuilder, approval.Image) != ErrVerificationDenied {
		t.Fatal("unsupported private verification fell back to another verifier")
	}
	if err := v.VerifyImage(context.Background(), ThemeBuilder, approval.Image); err != nil {
		t.Fatal(err)
	}
	if verifier.registryCalls != 1 || verifier.key != filepath.Join(filepath.Dir(path), approval.KeyFile) || verifier.revision != approval.Revision || verifier.image != approval.Image {
		t.Fatal("private verification lost the exact key, revision or image")
	}
	if v.VerifyImage(context.Background(), Keycloak, approval.Image) != ErrVerificationDenied || verifier.registryCalls != 1 {
		t.Fatal("private verification bypassed the approved purpose")
	}
	verifier.err = errors.New("untrusted verifier output")
	if v.VerifyImage(context.Background(), ThemeBuilder, approval.Image) != ErrVerificationDenied {
		t.Fatal("private signature failure was accepted or disclosed")
	}
}

func TestRegistrySignatureModeRevocationWins(t *testing.T) {
	path, approval := policyFixture(t)
	approval.RegistryOnly = true
	writeApprovalPolicy(t, path, approval)
	verifier := &registryVerifier{afterVerify: func() {
		approval.RegistryOnly = false
		writeApprovalPolicy(t, path, approval)
	}}
	if NewWithPolicy(path, verifier).VerifyImage(context.Background(), ThemeBuilder, approval.Image) != ErrVerificationDenied {
		t.Fatal("revoked private verification mode remained authorized")
	}
}

func TestKeylessApprovalCannotDisableTransparency(t *testing.T) {
	approval := Approval{Purpose: OperatorUpdate, Image: approvedImage, Revision: "1111111111111111111111111111111111111111", ReleaseVersion: "1.0.0", CertificateIdentity: releaseIdentityPrefix + "1.0.0", CertificateOIDCIssuer: releaseOIDCIssuer}
	if !validApproval(approval) {
		t.Fatal("valid keyless approval refused")
	}
	approval.RegistryOnly = true
	if validApproval(approval) {
		t.Fatal("keyless approval disabled transparency")
	}
}
