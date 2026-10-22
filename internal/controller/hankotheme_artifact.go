package controller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

const themeArtifactInstallScript = `set -eu
temporary="$(mktemp /output/.hanko-theme.XXXXXXXX)"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cp /theme/theme.jar "$temporary"
printf '%s  %s\n' "$THEME_JAR_SHA256" "$temporary" | sha256sum -c -
chmod 0644 "$temporary"
mv -f "$temporary" "/output/$THEME_JAR_NAME"
`

func validateThemeArtifact(spec api.HankoThemeSpec) error {
	if spec.ArtifactSHA256 == "" {
		return nil
	}
	digest, err := hex.DecodeString(spec.ArtifactSHA256)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != spec.ArtifactSHA256 {
		return fmt.Errorf("artifact SHA-256 must identify the precompiled JAR")
	}
	if spec.PrimaryColor != "" || spec.BackgroundColor != "" || spec.ForegroundColor != "" || spec.LogoURL != "" || spec.FontFamily != "" || spec.Headline != "" || spec.Subline != "" {
		return fmt.Errorf("artifact installation cannot contain build-time visual settings")
	}
	return nil
}

// Fleet artifact authority comes from an independent local image approval and
// an existing providers mount, never from native realm-management roles.
func (r *HankoTenantReconciler) themeArtifactSupport(ctx context.Context, namespace string, object fleetplan.Object) fleetplan.Support {
	var theme api.HankoTheme
	if json.Unmarshal(object.Raw, &theme) != nil || theme.Spec.ArtifactSHA256 == "" || validateThemeArtifact(theme.Spec) != nil || r.ImageValidator == nil {
		return fleetplan.Support{}
	}
	if r.ImageValidator.VerifyImage(ctx, imagevalidator.ThemeBuilder, theme.Spec.BuildImage) != nil {
		return fleetplan.Support{}
	}
	var deployment appsv1.Deployment
	name := r.ThemeKeycloakDeploymentName
	if name == "" {
		name = defaultKeycloakDeploymentName
	}
	if r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &deployment) != nil {
		return fleetplan.Support{}
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/opt/keycloak/providers" {
				continue
			}
			for _, volume := range deployment.Spec.Template.Spec.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == theme.Spec.KeycloakPVC {
					return fleetplan.Support{Capabilities: map[string]bool{"theme.install": true}, Permissions: map[string]bool{"theme.install": true}}
				}
			}
		}
	}
	return fleetplan.Support{}
}
