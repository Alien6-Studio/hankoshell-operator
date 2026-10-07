package imagevalidator

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// CosignVerifier executes the pinned runtime verifier without ambient platform
// credentials. DockerConfig must be a separate pull-only credential directory.
type CosignVerifier struct {
	Binary       string
	DockerConfig string
}

// Verify preserves Cosign digest, signature and transparency verification and
// binds the signed source annotation to the release approval. Failure details
// are intentionally discarded rather than recorded in CR status or logs.
func (v *CosignVerifier) Verify(ctx context.Context, image, keyFile, revision string) error {
	if v == nil || v.Binary == "" {
		return ErrVerificationDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 -- No shell; runtime-pinned binary and validated policy arguments.
	cmd := exec.CommandContext(ctx, v.Binary, "verify", "--key", keyFile,
		"-a", "hanko.git.revision="+revision, image)
	cmd.Env = []string{"HOME=/tmp", "XDG_CACHE_HOME=/tmp/.cache", "PATH=/usr/bin:/bin", "TMPDIR=/tmp"}
	if v.DockerConfig != "" {
		cmd.Env = append(cmd.Env, "DOCKER_CONFIG="+v.DockerConfig)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		return ErrVerificationDenied
	}
	return nil
}
