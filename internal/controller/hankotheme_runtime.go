package controller

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
)

// An optimized Keycloak cannot discover a newly mounted provider JAR without
// re-augmentation. Reject this deployment path before any build can write its
// PVC; changing startup arguments or rebuilding the server is a separate action.
func (r *HankoThemeReconciler) validateThemeRuntime(ctx context.Context, namespace string) error {
	var deployment appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: r.keycloakDeploymentName()}, &deployment); err != nil {
		return fmt.Errorf("read Keycloak runtime before theme installation: %w", err)
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		arguments := append(append([]string(nil), container.Command...), container.Args...)
		for _, argument := range arguments {
			for _, field := range strings.Fields(argument) {
				flag := strings.Trim(field, "\"'();")
				if flag == "--optimized" || flag == "--optimized=true" {
					return fmt.Errorf("keycloak starts with --optimized: install the theme JAR in the Keycloak image before kc.sh build; live provider-PVC installation is unavailable")
				}
			}
		}
	}
	return nil
}
