package imagevalidator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type changingKeyVerifier struct{ change func() }

func (v changingKeyVerifier) Verify(context.Context, string, string, string) error {
	v.change()
	return nil
}

func TestPublisherKeyReplacementDuringVerificationDeniesUpdate(t *testing.T) {
	path, approval := policyFixture(t)
	approval.Purpose, approval.ReleaseVersion = OperatorUpdate, "0.1.0"
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
	if err := NewWithPolicy(path, verifier).VerifyOperatorImage(context.Background(), approval.Image, "0.1.0"); err != ErrVerificationDenied {
		t.Fatalf("replaced publisher key remained authorized: %v", err)
	}
}

type keylessVerifier struct {
	recordingVerifier
	identity, issuer string
	beforeReturn     func()
}

func (v *keylessVerifier) VerifyKeyless(_ context.Context, image, identity, issuer, revision string) error {
	v.calls++
	v.image, v.identity, v.issuer, v.revision = image, identity, issuer, revision
	if v.beforeReturn != nil {
		v.beforeReturn()
	}
	return v.err
}

func TestRevocationDuringOperatorSignatureVerificationWins(t *testing.T) {
	path, _ := policyFixture(t)
	approval := operatorApproval()
	writeApprovalPolicy(t, path, approval)
	verifier := &keylessVerifier{beforeReturn: func() { writeApprovalPolicy(t, path) }}
	if err := NewWithPolicy(path, verifier).VerifyOperatorImage(context.Background(), approval.Image, "0.1.0"); err != ErrVerificationDenied {
		t.Fatalf("revoked approval survived pending signature verification: %v", err)
	}
}

func operatorApproval() Approval {
	return Approval{Purpose: OperatorUpdate, Image: approvedImage, Revision: strings.Repeat("1", 40),
		ReleaseVersion: "0.1.0", CertificateIdentity: releaseIdentityPrefix + "0.1.0", CertificateOIDCIssuer: releaseOIDCIssuer}
}

func TestOperatorApprovalBindsLocalDigestVersionSourceAndReleaseIdentity(t *testing.T) {
	path, _ := policyFixture(t)
	approval := operatorApproval()
	writeApprovalPolicy(t, path, approval)
	verifier := &keylessVerifier{}
	v := NewWithPolicy(path, verifier)
	ctx := context.Background()
	if err := v.VerifyOperatorImage(ctx, approval.Image, "0.1.0"); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.image != approval.Image || verifier.revision != approval.Revision ||
		verifier.identity != approval.CertificateIdentity || verifier.issuer != approval.CertificateOIDCIssuer {
		t.Fatalf("release binding lost: %+v", verifier)
	}
	if v.VerifyOperatorImage(ctx, approval.Image, "0.2.0") == nil || v.VerifyImage(ctx, OperatorUpdate, approval.Image) == nil {
		t.Fatal("release version binding bypassed")
	}
	if verifier.calls != 1 {
		t.Fatal("invalid version reached signature verifier")
	}
	verifier.err = errors.New("untrusted credential=do-not-disclose")
	if err := v.VerifyOperatorImage(ctx, approval.Image, "0.1.0"); err != ErrVerificationDenied {
		t.Fatalf("unredacted verification failure: %v", err)
	}
	verifier.err = nil
	writeApprovalPolicy(t, path)
	if v.VerifyOperatorImage(ctx, approval.Image, "0.1.0") == nil {
		t.Fatal("revoked release remained authorized")
	}
}

func TestOperatorApprovalRejectsOtherWorkflowsAndAmbiguousTrust(t *testing.T) {
	path, keyed := policyFixture(t)
	for _, mutate := range []func(*Approval){
		func(a *Approval) { a.CertificateIdentity = releaseIdentityPrefix + "0.2.0" },
		func(a *Approval) {
			a.CertificateIdentity = strings.Replace(a.CertificateIdentity, "Alien6-Studio", "attacker", 1)
		},
		func(a *Approval) {
			a.CertificateIdentity = strings.Replace(a.CertificateIdentity, "release.yml", "ci.yml", 1)
		},
		func(a *Approval) { a.CertificateIdentity = ".*" },
		func(a *Approval) { a.CertificateOIDCIssuer = "https://attacker.invalid" },
		func(a *Approval) { a.KeyFile = "publisher.pub" },
		func(a *Approval) { a.ReleaseVersion = "" },
		func(a *Approval) { a.ReleaseVersion = "01.0.0" },
		func(a *Approval) { a.Revision = "main" },
		func(a *Approval) { a.Purpose = Keycloak },
	} {
		approval := operatorApproval()
		mutate(&approval)
		writeApprovalPolicy(t, path, approval)
		verifier := &keylessVerifier{}
		if NewWithPolicy(path, verifier).VerifyOperatorImage(context.Background(), approval.Image, approval.ReleaseVersion) == nil || verifier.calls != 0 {
			t.Fatalf("invalid approval reached verification: %+v", approval)
		}
	}
	approval := operatorApproval()
	writeApprovalPolicy(t, path, approval)
	for _, v := range []*Validator{nil, NewWithPolicy(path, nil), NewWithPolicy(path, &recordingVerifier{})} {
		if v.VerifyOperatorImage(context.Background(), approval.Image, "0.1.0") == nil {
			t.Fatal("missing keyless verifier admitted an update")
		}
	}
	// An administrator can approve a separately signed mirror with a public key.
	keyed.Purpose, keyed.ReleaseVersion = OperatorUpdate, "0.1.0"
	writeApprovalPolicy(t, path, keyed)
	if err := NewWithPolicy(path, &recordingVerifier{}).VerifyOperatorImage(context.Background(), keyed.Image, "0.1.0"); err != nil {
		t.Fatal(err)
	}
}
