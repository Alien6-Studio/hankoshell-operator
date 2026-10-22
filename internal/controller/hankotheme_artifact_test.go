package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
)

func artifactTheme() *api.HankoTheme {
	theme := testTheme()
	theme.Spec = api.HankoThemeSpec{BuildImage: approvedThemeImage, ArtifactSHA256: strings.Repeat("a", 64), KeycloakPVC: "keycloak-providers", JarName: "hanko-theme.jar"}
	return theme
}

func TestThemeArtifactRequiresSeparateInstallationInputs(t *testing.T) {
	theme := artifactTheme()
	if err := validateThemeArtifact(theme.Spec); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*api.HankoThemeSpec){
		func(spec *api.HankoThemeSpec) { spec.ArtifactSHA256 = "not-a-digest" },
		func(spec *api.HankoThemeSpec) { spec.ArtifactSHA256 = strings.Repeat("A", 64) },
		func(spec *api.HankoThemeSpec) { spec.PrimaryColor = "#123456" },
	} {
		spec := theme.Spec
		mutate(&spec)
		if validateThemeArtifact(spec) == nil {
			t.Fatal("invalid or mixed artifact/build inputs accepted")
		}
	}
	job := (&HankoThemeReconciler{}).buildJob(theme, "install-artifact")
	container := job.Spec.Template.Spec.Containers[0]
	if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("artifact installer root filesystem is writable")
	}
	if container.Name != "installer" || strings.Contains(strings.Join(container.Command, " "), "build-theme.sh") {
		t.Fatal("artifact mode executed a builder entrypoint")
	}
	if !strings.Contains(container.Command[2], "sha256sum -c") || !strings.Contains(container.Command[2], "mv -f") {
		t.Fatal("artifact mode lost digest verification or atomic replacement")
	}
	if !themeJobSpecMatches(job, job.DeepCopy()) {
		t.Fatal("artifact job could not resume")
	}
	changed := job.DeepCopy()
	changed.Spec.Template.Spec.Containers[0].Env[1].Value = strings.Repeat("b", 64)
	if themeJobSpecMatches(changed, job) {
		t.Fatal("artifact digest changed without refusal")
	}
}

func TestFleetArtifactNeedsIndependentApprovalAndExistingProviderStorage(t *testing.T) {
	theme := artifactTheme()
	deployment := testKeycloakDeployment(theme.Namespace)
	deployment.Spec.Template.Spec.Containers = []corev1.Container{{Name: "keycloak", VolumeMounts: []corev1.VolumeMount{{Name: "providers", MountPath: "/opt/keycloak/providers"}}}}
	deployment.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "providers", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: theme.Spec.KeycloakPVC}}}}
	r := &HankoTenantReconciler{Client: newThemeClient(t, deployment), ImageValidator: approvedFixtureValidator(t)}
	object := func() fleetplan.Object {
		raw, _ := json.Marshal(theme)
		return fleetplan.Object{Kind: "HankoTheme", Raw: raw}
	}
	if !r.themeArtifactSupport(context.Background(), theme.Namespace, object()).Capabilities["theme.install"] {
		t.Fatal("approved precompiled artifact could not use the existing providers storage")
	}
	theme.Spec.KeycloakPVC = "unrelated-data"
	if r.themeArtifactSupport(context.Background(), theme.Namespace, object()).Capabilities["theme.install"] {
		t.Fatal("remote artifact selected unrelated PVC storage")
	}
	theme.Spec.KeycloakPVC = "keycloak-providers"
	r.ImageValidator = nil
	if r.themeArtifactSupport(context.Background(), theme.Namespace, object()).Capabilities["theme.install"] {
		t.Fatal("Hub identity replaced an independent local artifact approval")
	}
}
