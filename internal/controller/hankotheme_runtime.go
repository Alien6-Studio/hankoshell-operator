package controller

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Keycloak must read the build's provider PVC and discover new JARs at startup.
// Optimized startup requires image re-augmentation instead of this live workflow.
func (r *HankoThemeReconciler) validateThemeRuntime(ctx context.Context, namespace, pvcName string) error {
	var deployment appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: r.keycloakDeploymentName()}, &deployment); err != nil {
		return fmt.Errorf("read Keycloak runtime before theme installation: %w", err)
	}
	providerVolumes := map[string]bool{}
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvcName {
			providerVolumes[volume.Name] = true
		}
	}
	providersMounted := false
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "keycloak" {
			continue
		}
		arguments := append(append([]string(nil), container.Command...), container.Args...)
		for _, argument := range arguments {
			for _, field := range strings.Fields(argument) {
				flag := strings.Trim(field, "\"'();")
				if flag == "--optimized" || flag == "--optimized=true" {
					return fmt.Errorf("keycloak starts with --optimized: install the theme JAR in the Keycloak image before kc.sh build; live provider-PVC installation is unavailable")
				}
			}
		}
		for _, mount := range container.VolumeMounts {
			// Jobs write the PVC root. A subPath mount would expose different
			// bytes even if it names the same claim and provider directory.
			if providerVolumes[mount.Name] && strings.TrimRight(mount.MountPath, "/") == strings.TrimRight(keycloakProvidersPath, "/") && mount.SubPath == "" && mount.SubPathExpr == "" {
				providersMounted = true
			}
		}
	}
	if !providersMounted {
		return fmt.Errorf("the keycloak container must mount the root of theme PVC %q at %s without subPath; the built theme would otherwise be unavailable", pvcName, keycloakProvidersPath)
	}
	return nil
}
