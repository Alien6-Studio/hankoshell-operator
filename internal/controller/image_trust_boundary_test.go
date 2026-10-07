package controller

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

func TestThemeLookalikeImageCreatesNoJob(t *testing.T) {
	ctx := context.Background()
	for _, image := range []string{"registry.example.attacker.test/hanko/theme-builder:v1", "registry.example/hanko/theme-builder-attacker:v1", "registry.example/hanko/theme-builder:latest", approvedKeycloakImage} {
		t.Run(image, func(t *testing.T) {
			theme := testTheme()
			theme.Spec.BuildImage = image
			kube := newThemeClient(t, theme)
			reconciler := &HankoThemeReconciler{Client: kube, Scheme: newThemeScheme(t),
				ImageValidator: approvedFixtureValidator(t)}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(theme)}); err != nil {
				t.Fatal(err)
			}
			var actual hankoshv1alpha1.HankoTheme
			if err := kube.Get(ctx, client.ObjectKeyFromObject(theme), &actual); err != nil {
				t.Fatal(err)
			}
			condition := themeCondition(&actual, "Built")
			if actual.Status.Phase != "Error" || condition == nil || condition.Reason != "UntrustedImageRef" {
				t.Fatalf("image was not rejected before workload construction: %+v", actual.Status)
			}
			var jobs batchv1.JobList
			if err := kube.List(ctx, &jobs); err != nil || len(jobs.Items) != 0 {
				t.Fatalf("untrusted build job created: count=%d err=%v", len(jobs.Items), err)
			}
		})
	}
}

func TestManagedKeycloakLookalikeImageCreatesNoDeployment(t *testing.T) {
	ctx := context.Background()
	for _, image := range []string{"quay.io.attacker.test/keycloak/keycloak:26.0", "quay.io/keycloak-attacker/keycloak:26.0", "registry.example/hanko/keycloak:latest", approvedThemeImage} {
		t.Run(image, func(t *testing.T) {
			scheme := controllerTestScheme(t)
			instance := managedTestInstance("test", "managed")
			instance.Spec.Managed.Image = image
			kube := controllerTestClient(scheme, instance)
			reconciler := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme,
				ImageValidator: approvedFixtureValidator(t)}
			_, handled, err := reconciler.reconcileInstanceMode(ctx, instance, client.MergeFrom(instance.DeepCopy()))
			if err != nil || !handled || instance.Status.Phase != "Error" || conditionReason(instance.Status.Conditions, "AdminAPIReachable") != "UntrustedImageRef" {
				t.Fatalf("image was not rejected: handled=%t err=%v", handled, err)
			}
			var deployments appsv1.DeploymentList
			if err := kube.List(ctx, &deployments); err != nil || len(deployments.Items) != 0 {
				t.Fatalf("untrusted deployment created: count=%d err=%v", len(deployments.Items), err)
			}
		})
	}
}

func TestSignatureFailureAndMissingValidatorCreateNoWorkload(t *testing.T) {
	for _, name := range []string{"missing-validator", "invalid-signature"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var validator *imagevalidator.Validator
			if name == "invalid-signature" {
				validator = fixtureValidator(t, fixtureSignatureVerifier{err: errors.New("untrusted publisher")})
			}
			theme := testTheme()
			kube := newThemeClient(t, theme)
			themes := &HankoThemeReconciler{Client: kube, Scheme: newThemeScheme(t), ImageValidator: validator}
			if _, err := themes.submitThemeBuild(ctx, theme, &themeBuildState{jobName: "denied-build"}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := themes.reconcileThemeCleanupJob(ctx, theme, "denied-cleanup", "old.jar"); err != nil {
				t.Fatal(err)
			}
			if _, err := themes.reconcilePruneJob(ctx, theme, "old.jar", "", previousThemeImage, "old"); !errors.Is(err, imagevalidator.ErrVerificationDenied) {
				t.Fatalf("prune accepted invalid signature: %v", err)
			}
			var jobs batchv1.JobList
			if err := kube.List(ctx, &jobs); err != nil || len(jobs.Items) != 0 {
				t.Fatalf("unverified Job created: %v count=%d", err, len(jobs.Items))
			}
			instance := managedTestInstance("test", "managed")
			instances := &HankoKeycloakInstanceReconciler{Client: controllerTestClient(controllerTestScheme(t), instance), Scheme: controllerTestScheme(t), ImageValidator: validator}
			if err := instances.ensureDeployment(ctx, instance); !errors.Is(err, imagevalidator.ErrVerificationDenied) {
				t.Fatalf("managed Deployment accepted invalid signature: %v", err)
			}
			var deployments appsv1.DeploymentList
			if err := instances.List(ctx, &deployments); err != nil || len(deployments.Items) != 0 {
				t.Fatalf("unverified Deployment created: %v count=%d", err, len(deployments.Items))
			}
		})
	}
}

func TestCleanupCannotExecuteTamperedInstalledImage(t *testing.T) {
	ctx := context.Background()
	theme := testTheme()
	theme.Status.InstalledBuildImage = "registry.example/hanko/theme-builder:old"
	kube := newThemeClient(t, theme)
	r := &HankoThemeReconciler{Client: kube, Scheme: newThemeScheme(t), ImageValidator: approvedFixtureValidator(t)}
	if _, _, err := r.reconcileThemeCleanupJob(ctx, theme, "cleanup", "old.jar"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcilePruneJob(ctx, theme, "old.jar", "", theme.Status.InstalledBuildImage, "old"); !errors.Is(err, imagevalidator.ErrVerificationDenied) {
		t.Fatalf("prune accepted mutable installed image: %v", err)
	}
	var jobs batchv1.JobList
	if err := kube.List(ctx, &jobs); err != nil || len(jobs.Items) != 0 {
		t.Fatalf("tampered installed image executed: %v count=%d", err, len(jobs.Items))
	}
}
