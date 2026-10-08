package imagevalidator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCosignUsesOnlyPublicKeyAndPullCredentials(t *testing.T) {
	t.Setenv("HANKO_KC_CLIENT_SECRET", "platform-secret")
	t.Setenv("AZURE_CLIENT_SECRET", "signing-secret")
	t.Setenv("COSIGN_REPOSITORY", "attacker.example/signatures")
	binary := filepath.Join(t.TempDir(), "cosign")
	script := `#!/bin/sh
test "$#" -eq 6 || exit 2
test "$1" = verify && test "$2" = --key && test "$3" = /policy/publisher.pub || exit 3
test "$4" = -a && test "$5" = hanko.git.revision=1111111111111111111111111111111111111111 || exit 4
test "$6" = registry.example/hanko/theme-builder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || exit 5
test -z "${HANKO_KC_CLIENT_SECRET:-}${AZURE_CLIENT_SECRET:-}${COSIGN_REPOSITORY:-}" || exit 6
test "$DOCKER_CONFIG" = /pull-only && test "$HOME" = /tmp || exit 7
`
	// #nosec G306 -- Owner-only executable fixture in the test's private directory.
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	v := &CosignVerifier{Binary: binary, DockerConfig: "/pull-only"}
	if err := v.Verify(context.Background(), approvedImage, "/policy/publisher.pub", "1111111111111111111111111111111111111111"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho credential=do-not-disclose >&2\nexit 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), approvedImage, "/policy/publisher.pub", "revision"); err != ErrVerificationDenied {
		t.Fatalf("raw process failure exposed: %v", err)
	}
}

func TestCosignCancellationDeniesExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	v := &CosignVerifier{Binary: "/bin/sh"}
	if err := v.Verify(ctx, approvedImage, "/policy/publisher.pub", "revision"); err != ErrVerificationDenied {
		t.Fatalf("cancelled verification: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancelled verifier blocked")
	}
}

func TestCosignKeylessPinsExactIdentityIssuerRevisionAndDigest(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ambient-secret")
	t.Setenv("SIGSTORE_ROOT_FILE", "/attacker/root")
	binary := filepath.Join(t.TempDir(), "cosign")
	script := `#!/bin/sh
test "$#" -eq 8 || exit 2
test "$1" = verify && test "$2" = --certificate-identity || exit 3
test "$3" = https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v0.1.0 || exit 4
test "$4" = --certificate-oidc-issuer && test "$5" = https://token.actions.githubusercontent.com || exit 5
test "$6" = -a && test "$7" = hanko.git.revision=1111111111111111111111111111111111111111 || exit 6
test "$8" = registry.example/hanko/theme-builder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || exit 7
test -z "${GITHUB_TOKEN:-}${SIGSTORE_ROOT_FILE:-}" || exit 8
`
	// #nosec G306 -- Owner-only executable fixture in the test's private directory.
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	v := &CosignVerifier{Binary: binary}
	if err := v.VerifyKeyless(context.Background(), approvedImage, releaseIdentityPrefix+"0.1.0", releaseOIDCIssuer, "1111111111111111111111111111111111111111"); err != nil {
		t.Fatal(err)
	}
}
