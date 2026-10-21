//go:build integration

package v1alpha1_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

// snapshotPublisherFixture isolates registry crypto while testing actual API
// defaulting, status subresources and the credential-bearing admission boundary.
type snapshotPublisherFixture struct {
	t     *testing.T
	image string
	calls int
}

func (v *snapshotPublisherFixture) Verify(_ context.Context, image, _, revision string) error {
	v.t.Helper()
	if image != v.image || revision != strings.Repeat("1", 40) {
		v.t.Fatal("backup publisher digest/source binding lost")
	}
	v.calls++
	return nil
}

func checkSnapshotBackupContract(t *testing.T, ctx context.Context, admin client.Client, scheme *runtime.Scheme) {
	t.Helper()
	image := "registry.example/iam/pgdump@sha256:" + strings.Repeat("e", 64)
	base := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "qualified-backup", Namespace: "auth"},
		Spec: hankoshv1alpha1.HankoSnapshotSpec{
			InstanceRef: "snapshot-managed", IncludeData: true, BackupPVC: "backup-volume",
			BackupImage: image, BackupSecretRef: "backup-credentials",
		},
	}
	for _, test := range []struct {
		name   string
		mutate func(*hankoshv1alpha1.HankoSnapshot)
	}{
		{name: "missing image", mutate: func(s *hankoshv1alpha1.HankoSnapshot) { s.Spec.BackupImage = "" }},
		{name: "missing credentials", mutate: func(s *hankoshv1alpha1.HankoSnapshot) { s.Spec.BackupSecretRef = "" }},
		{name: "missing pvc", mutate: func(s *hankoshv1alpha1.HankoSnapshot) { s.Spec.BackupPVC = "" }},
		{name: "mutable image", mutate: func(s *hankoshv1alpha1.HankoSnapshot) { s.Spec.BackupImage = "postgres:16-alpine" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base.DeepCopy()
			test.mutate(snapshot)
			if err := admin.Create(ctx, snapshot); !apierrors.IsInvalid(err) {
				t.Fatalf("incomplete/mutable backup declaration admitted: %v", err)
			}
		})
	}
	configOnly := base.DeepCopy()
	configOnly.Name = "qualified-config-only"
	configOnly.Spec = hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: base.Spec.InstanceRef}
	if err := admin.Create(ctx, configOnly); err != nil {
		t.Fatal(err)
	}
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: base.Spec.InstanceRef, Namespace: "auth"},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			Mode: "managed", AdminRef: corev1.LocalObjectReference{Name: "snapshot-admin"},
			Managed: &hankoshv1alpha1.ManagedKeycloakSpec{
				Image: image, TLSSecretRef: "snapshot-serving-tls",
				Database: corev1.LocalObjectReference{Name: "snapshot-database"},
			},
		},
	}
	credentials := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: base.Spec.BackupSecretRef, Namespace: "auth"},
		Data: map[string][]byte{
			"PGHOST": []byte("postgres.auth.svc"), "PGDATABASE": []byte("keycloak"),
			"PGUSER": []byte("backup"), "PGPASSWORD": []byte("fixture-not-a-production-credential"),
		},
	}
	for _, object := range []client.Object{instance, credentials, base} {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	verifier := &snapshotPublisherFixture{t: t, image: image}
	r := &controller.HankoSnapshotReconciler{
		Client: admin, Scheme: scheme, ImageValidator: snapshotApprovalFixture(t, image, verifier),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(base)}
	result, err := r.Reconcile(ctx, req)
	if err != nil || result.RequeueAfter == 0 || verifier.calls != 1 {
		t.Fatalf("verified backup Job creation failed: result=%v calls=%d err=%v", result, verifier.calls, err)
	}
	job := &batchv1.Job{}
	if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "snap-" + base.Name + "-pgdump"}, job); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "qualified-backup-pod", Namespace: "auth"}, Spec: job.Spec.Template.Spec}
	if err := admin.Create(ctx, pod, client.DryRunAll, client.FieldValidation("Strict")); err != nil {
		t.Fatalf("generated backup pod failed Restricted admission: %v", err)
	}
	result, err = r.Reconcile(ctx, req)
	if err != nil || result.RequeueAfter == 0 || verifier.calls != 2 {
		t.Fatalf("API defaulting broke existing backup contract: result=%v calls=%d err=%v", result, verifier.calls, err)
	}
	now := metav1.Now()
	job.Status.StartTime, job.Status.CompletionTime = &now, &now
	job.Status.Succeeded = 1
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue},
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	if err := admin.Status().Update(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(base), base); err != nil {
		t.Fatal(err)
	}
	if base.Status.Phase != "Done" || verifier.calls != 3 {
		t.Fatalf("verified completed backup was not accepted: %+v calls=%d", base.Status, verifier.calls)
	}
}

func snapshotApprovalFixture(t *testing.T, image string, verifier imagevalidator.SignatureVerifier) *imagevalidator.Validator {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	approval := imagevalidator.Approval{Purpose: imagevalidator.DatabaseBackup, Image: image, Revision: strings.Repeat("1", 40), KeyFile: "publisher.pub"}
	raw, err := json.Marshal(map[string]any{"version": 1, "approvals": []imagevalidator.Approval{approval}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return imagevalidator.NewWithPolicy(path, verifier)
}
