package controller

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func projectSpec(t *testing.T) api.HankoThemeSpec {
	t.Helper()
	raw := []byte(`{"format":"hanko.theme-studio.project/v1","name":"demo","pages":{"login:0":{"blocks":[]}}}`)
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return api.HankoThemeSpec{ProjectGzip: base64.StdEncoding.EncodeToString(buffer.Bytes()), ProjectSHA256: hex.EncodeToString(digest[:]), BuildImage: approvedThemeImage, KeycloakPVC: "providers", JarName: "studio.jar"}
}
func TestThemeProjectSnapshotAndJobContract(t *testing.T) {
	spec := projectSpec(t)
	if _, err := validateThemeProject(spec); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*api.HankoThemeSpec){
		func(s *api.HankoThemeSpec) { s.ProjectSHA256 = "" }, func(s *api.HankoThemeSpec) { s.ProjectGzip = "invalid" }, func(s *api.HankoThemeSpec) { s.ProjectSHA256 = string(bytes.Repeat([]byte("a"), 64)) }, func(s *api.HankoThemeSpec) { s.PrimaryColor = "#123456" }, func(s *api.HankoThemeSpec) { s.ArtifactSHA256 = spec.ProjectSHA256 },
	} {
		invalid := spec
		change(&invalid)
		if _, err := validateThemeProject(invalid); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	theme := &api.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "studio", Namespace: "auth", UID: "owner", Generation: 1}, Spec: spec}
	job := (&HankoThemeReconciler{}).buildJob(theme, "build")
	if job.Spec.Template.Spec.AutomountServiceAccountToken == nil || *job.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("build received an API credential")
	}
	mounts := job.Spec.Template.Spec.Containers[0].VolumeMounts
	if len(mounts) != 2 || mounts[1].MountPath != "/input" || !mounts[1].ReadOnly {
		t.Fatal("project input must be a separate read-only mount")
	}
}
func TestThemeProjectSourceIsImmutableAndCollectedWithItsJob(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	theme := &api.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "studio", Namespace: "auth", UID: "owner", Generation: 1}, Spec: projectSpec(t)}
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &HankoThemeReconciler{Client: client, Scheme: scheme}
	if err := r.ensureThemeProject(ctx, theme); err != nil {
		t.Fatal(err)
	}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "auth", UID: "job-owner"}}
	if err := r.bindThemeProject(ctx, theme, job); err != nil {
		t.Fatal(err)
	}
	var input corev1.ConfigMap
	if err := client.Get(ctx, types.NamespacedName{Namespace: "auth", Name: themeProjectName(theme)}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Immutable == nil || !*input.Immutable || !metav1.IsControlledBy(&input, job) || len(input.OwnerReferences) != 1 {
		t.Fatal("source must be immutable and garbage-collected with the Job")
	}
	if err := r.bindThemeProject(ctx, theme, job); err != nil {
		t.Fatal("idempotent source binding:", err)
	}
	foreign := job.DeepCopy()
	foreign.UID = "different-job"
	if err := r.bindThemeProject(ctx, theme, foreign); err == nil {
		t.Fatal("foreign Job adopted immutable source")
	}
}

func TestThemeProjectJobContractSurvivesAPIDefaulting(t *testing.T) {
	theme := &api.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "studio", Namespace: "auth", UID: "owner", Generation: 1}, Spec: projectSpec(t)}
	expected := (&HankoThemeReconciler{}).buildJob(theme, "build")
	stored := expected.DeepCopy()
	// The API server persists this mode even when a submitted ConfigMap volume omits it.
	mode := int32(0644)
	stored.Spec.Template.Spec.Volumes[1].ConfigMap.DefaultMode = &mode
	if !themeJobSpecMatches(stored, expected) {
		t.Fatal("API-defaulted project Job no longer matches its build contract")
	}
	for name, tamper := range map[string]func(*batchv1.Job){
		"mode":     func(job *batchv1.Job) { *job.Spec.Template.Spec.Volumes[1].ConfigMap.DefaultMode = 0777 },
		"source":   func(job *batchv1.Job) { job.Spec.Template.Spec.Volumes[1].ConfigMap.Name = "foreign-source" },
		"path":     func(job *batchv1.Job) { job.Spec.Template.Spec.Volumes[1].ConfigMap.Items[0].Path = "different.gz" },
		"writable": func(job *batchv1.Job) { job.Spec.Template.Spec.Containers[0].VolumeMounts[1].ReadOnly = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := stored.DeepCopy()
			tamper(changed)
			if themeJobSpecMatches(changed, expected) {
				t.Fatal("modified project input accepted")
			}
		})
	}
}

func TestThemeProjectInstallationAndCollectedBuildRecovery(t *testing.T) {
	ctx := context.Background()
	theme := testTheme()
	theme.Spec = projectSpec(t)
	deployment := testKeycloakDeployment(theme.Namespace)
	deployment.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = theme.Spec.KeycloakPVC
	deployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].ReadOnly = true
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	c := fake.NewClientBuilder().WithScheme(newThemeScheme(t)).WithObjects(theme, deployment, pvc).
		WithStatusSubresource(&api.HankoTheme{}, &batchv1.Job{}, &appsv1.Deployment{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.CreateOption) error {
				if job, ok := object.(*batchv1.Job); ok {
					job.UID = "build-job-uid"
				}
				return c.Create(ctx, object, opts...)
			},
		}).Build()
	r := &HankoThemeReconciler{Client: c, Scheme: newThemeScheme(t), ImageValidator: approvedFixtureValidator(t)}
	key := client.ObjectKeyFromObject(theme)
	reconcile := func(phase string) {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, key, theme); err != nil {
			t.Fatal(err)
		}
		if theme.Status.Phase != phase {
			t.Fatalf("phase = %q, want %q: %+v", theme.Status.Phase, phase, theme.Status)
		}
	}
	reconcile("Building")
	var job batchv1.Job
	if err := c.Get(ctx, types.NamespacedName{Name: theme.Status.BuildJob, Namespace: theme.Namespace}, &job); err != nil {
		t.Fatal(err)
	}
	var input corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: themeProjectName(theme), Namespace: theme.Namespace}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Immutable == nil || !*input.Immutable || !metav1.IsControlledBy(&input, &job) {
		t.Fatal("project source was not bound immutably to its build Job")
	}
	job.Status = completedJobStatus()
	if err := c.Status().Update(ctx, &job); err != nil {
		t.Fatal(err)
	}
	// A deployment change during compilation must not produce false readiness
	// or restart Keycloak against an unrelated providers volume.
	deployment.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "other-providers"
	if err := c.Update(ctx, deployment); err != nil {
		t.Fatal(err)
	}
	reconcile("Error")
	assertNoThemeRestart(t, c, theme)
	deployment.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = theme.Spec.KeycloakPVC
	if err := c.Update(ctx, deployment); err != nil {
		t.Fatal(err)
	}
	reconcile("Installing")
	if theme.Status.ObservedGeneration == theme.Generation {
		t.Fatal("theme became current before Keycloak's rollout")
	}
	completeKeycloakRollout(t, c, theme.Namespace)
	reconcile("Ready")
	if theme.Status.ObservedGeneration != theme.Generation || theme.Status.InstalledPVC != theme.Spec.KeycloakPVC {
		t.Fatal("installed theme does not identify its current generation and storage")
	}
	// The cache can observe source collection before Job deletion. An installed
	// theme must stay Ready in either order, without rebuilding or restarting.
	if err := c.Delete(ctx, &input); err != nil {
		t.Fatal(err)
	}
	reconcile("Ready")
	if err := c.Delete(ctx, &job); err != nil {
		t.Fatal(err)
	}
	reconcile("Ready")
	if err := c.Get(ctx, client.ObjectKeyFromObject(&job), &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Fatalf("installed project was rebuilt after collection: %v", err)
	}
}
