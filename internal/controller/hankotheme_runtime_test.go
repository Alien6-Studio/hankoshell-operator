package controller

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestThemeOptimizedRuntimeCannotWriteProvidersOrRestartKeycloak(t *testing.T) {
	for _, arguments := range [][]string{{"start", "--optimized"}, {"start", "--optimized=true"}, {"/bin/sh", "-c", "exec /opt/keycloak/bin/kc.sh start --optimized;"}} {
		t.Run(arguments[len(arguments)-1], func(t *testing.T) {
			theme := testTheme()
			theme.Spec = projectSpec(t)
			deployment := testKeycloakDeployment(theme.Namespace)
			deployment.Spec.Template.Spec.Containers = []corev1.Container{{Name: "keycloak", Args: arguments}}
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
			c := newThemeClient(t, theme, pvc, deployment)
			r := &HankoThemeReconciler{Client: c, Scheme: newThemeScheme(t), ImageValidator: approvedFixtureValidator(t)}
			key := types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got api.HankoTheme
			if err := c.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			condition := themeCondition(&got, "Built")
			if got.Status.Phase != "Error" || condition == nil || condition.Reason != "UnsupportedThemeRuntime" {
				t.Fatalf("unsafe runtime accepted: %+v", got.Status)
			}
			var jobs batchv1.JobList
			var inputs corev1.ConfigMapList
			if err := c.List(context.Background(), &jobs); err != nil {
				t.Fatal(err)
			}
			if err := c.List(context.Background(), &inputs); err != nil {
				t.Fatal(err)
			}
			if len(jobs.Items) != 0 || len(inputs.Items) != 0 {
				t.Fatal("unsupported runtime received a provider-writing Job or source")
			}
			if err := c.Get(context.Background(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, deployment); err != nil {
				t.Fatal(err)
			}
			if len(deployment.Spec.Template.Annotations) != 0 {
				t.Fatal("unsupported Keycloak was restarted")
			}
		})
	}
}

func TestThemeRuntimeMustReadTheBuildPVC(t *testing.T) {
	for name, mount := range map[string]corev1.VolumeMount{
		"missing mount":        {},
		"wrong path":           {Name: "providers", MountPath: "/other"},
		"subdirectory":         {Name: "providers", MountPath: "/opt/keycloak/providers", SubPath: "themes"},
		"dynamic subdirectory": {Name: "providers", MountPath: "/opt/keycloak/providers", SubPathExpr: "$(THEME)"},
		"other volume":         {Name: "other", MountPath: "/opt/keycloak/providers"},
		"wrong claim":          {Name: "providers", MountPath: "/opt/keycloak/providers"},
		"sidecar only":         {Name: "providers", MountPath: "/opt/keycloak/providers"},
	} {
		t.Run(name, func(t *testing.T) {
			theme := testTheme()
			theme.Spec = projectSpec(t)
			deployment := testKeycloakDeployment(theme.Namespace)
			deployment.Spec.Template.Spec.Containers = []corev1.Container{{Name: "keycloak", Args: []string{"start"}, VolumeMounts: []corev1.VolumeMount{mount}}}
			deployment.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "providers", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: theme.Spec.KeycloakPVC}}}}
			if name == "wrong claim" {
				deployment.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "other-providers"
			}
			if name == "sidecar only" {
				deployment.Spec.Template.Spec.Containers[0].Name = "sidecar"
				deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{Name: "keycloak", Args: []string{"start"}})
			}
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
			c := newThemeClient(t, theme, pvc, deployment)
			r := &HankoThemeReconciler{Client: c, Scheme: newThemeScheme(t), ImageValidator: approvedFixtureValidator(t)}
			key := types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got api.HankoTheme
			if err := c.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			condition := themeCondition(&got, "Built")
			if got.Status.Phase != "Error" || condition == nil || condition.Reason != "UnsupportedThemeRuntime" {
				t.Fatalf("build output invisible to Keycloak was accepted: %+v", got.Status)
			}
			var jobs batchv1.JobList
			var inputs corev1.ConfigMapList
			if err := c.List(context.Background(), &jobs); err != nil {
				t.Fatal(err)
			}
			if err := c.List(context.Background(), &inputs); err != nil {
				t.Fatal(err)
			}
			if len(jobs.Items) != 0 || len(inputs.Items) != 0 {
				t.Fatal("unmounted output received a build Job or source")
			}
		})
	}
}
