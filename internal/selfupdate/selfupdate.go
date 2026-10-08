// Package selfupdate converges this operator's own Deployment on the
// digest-pinned agent release commanded by Hub. The repository of the running
// container image is always preserved and only its digest is swapped, so a
// Hub cannot redirect the operator to another registry. A local release policy
// and publisher signature authorize the digest before any patch. The kubelet
// then replaces the running pod; the new binary reports
// the commanded version on its first heartbeat, which clears the command.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

// Config identifies the Deployment that runs this operator process.
type Config struct {
	Namespace      string
	DeploymentName string
	ContainerName  string
}

// Validate reports whether the configuration identifies a patchable target.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Namespace) == "" || strings.TrimSpace(c.DeploymentName) == "" || strings.TrimSpace(c.ContainerName) == "" {
		return errors.New("agent self-update requires the deployment namespace, name, and container name")
	}
	return nil
}

// digestPattern accepts only a full sha256 content digest; anything else
// (tags, uppercase, truncations) is refused before touching the Deployment.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Engine patches the operator's own Deployment to the commanded digest.
type Engine struct {
	Writer   client.Client
	Reader   client.Reader
	Config   Config
	Verifier ReleaseVerifier
}

// ReleaseVerifier authorizes an exact image/version through independent local trust.
type ReleaseVerifier interface {
	VerifyOperatorImage(context.Context, string, string) error
}

func (e *Engine) validateRequest(command *hub.AgentUpdateCommand) error {
	if err := e.Config.Validate(); err != nil {
		return err
	}
	if e.Reader == nil || e.Writer == nil {
		return errors.New("agent update requires a configured deployment reader and writer")
	}
	if command == nil || strings.TrimSpace(command.Version) == "" {
		return errors.New("agent update command carries no release version")
	}
	if !digestPattern.MatchString(command.Digest) {
		return errors.New("agent update requires a sha256 content digest")
	}
	return nil
}

// Run pins the configured container to its current repository at the
// commanded digest and returns the resulting image reference. It is
// idempotent: a Deployment already pinned to that digest is left untouched.
func (e *Engine) Run(ctx context.Context, command *hub.AgentUpdateCommand) (string, error) {
	if err := e.validateRequest(command); err != nil {
		return "", err
	}

	var deployment appsv1.Deployment
	key := types.NamespacedName{Namespace: e.Config.Namespace, Name: e.Config.DeploymentName}
	if err := e.Reader.Get(ctx, key, &deployment); err != nil {
		return "", fmt.Errorf("read operator deployment %s/%s: %w", key.Namespace, key.Name, err)
	}

	containers := deployment.Spec.Template.Spec.Containers
	index := -1
	for i := range containers {
		if containers[i].Name == e.Config.ContainerName {
			index = i
			break
		}
	}
	if index < 0 {
		return "", fmt.Errorf("container %q not found in deployment %s/%s", e.Config.ContainerName, key.Namespace, key.Name)
	}

	image := repository(containers[index].Image) + "@" + command.Digest
	if e.Verifier == nil || e.Verifier.VerifyOperatorImage(ctx, image, command.Version) != nil {
		return "", errors.New("agent update requires a locally approved release and verified publisher signature")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if containers[index].Image == image {
		return image, nil
	}
	patch := client.MergeFromWithOptions(deployment.DeepCopy(), client.MergeFromWithOptimisticLock{})
	deployment.Spec.Template.Spec.Containers[index].Image = image
	if err := e.Writer.Patch(ctx, &deployment, patch); err != nil {
		return "", fmt.Errorf("pin operator image to %s: %w", image, err)
	}
	return image, nil
}

// repository strips any digest and tag from an image reference, keeping the
// registry (including an optional port) and path untouched.
func repository(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
		image = image[:colon]
	}
	return image
}
