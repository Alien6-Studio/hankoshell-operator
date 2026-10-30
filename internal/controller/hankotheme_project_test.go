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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
