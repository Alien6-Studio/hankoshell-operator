package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

func snapshotDataFixture() *hankoshv1alpha1.HankoSnapshot {
	return &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "test", UID: "snapshot-uid"},
		Spec: hankoshv1alpha1.HankoSnapshotSpec{
			InstanceRef: "keycloak", IncludeData: true, BackupPVC: "backups",
			BackupImage: approvedBackupImage, BackupSecretRef: "backup-credentials",
		},
	}
}

func snapshotBackupSecret(snapshot *hankoshv1alpha1.HankoSnapshot) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: snapshot.Spec.BackupSecretRef, Namespace: snapshot.Namespace},
		Data: map[string][]byte{
			"PGHOST": []byte("postgres.test.svc"), "PGDATABASE": []byte("keycloak"),
			"PGUSER": []byte("backup"), "PGPASSWORD": []byte("fixture-credential-do-not-disclose"),
			"UNRELATED_SECRET": []byte("unrelated-do-not-disclose"),
		},
	}
}

func snapshotOwnedJob(t *testing.T, r *HankoSnapshotReconciler, snapshot *hankoshv1alpha1.HankoSnapshot) *batchv1.Job {
	t.Helper()
	job := r.buildPGDumpJob("snap-"+snapshot.Name+"-pgdump", snapshot)
	if err := controllerutil.SetControllerReference(snapshot, job, r.Scheme); err != nil {
		t.Fatal(err)
	}
	return job
}

func TestSnapshotBackupRejectsUntrustedExecutionAndSharedCredentials(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		mutate       func(*hankoshv1alpha1.HankoSnapshot, *hankoshv1alpha1.HankoKeycloakInstance, *corev1.Secret)
		noValidator  bool
		badSignature bool
		noSecret     bool
	}{
		{name: "missing image", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = ""
		}},
		{name: "legacy tag", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = "postgres:16-alpine"
		}},
		{name: "unapproved digest", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = strings.Replace(approvedBackupImage, "eeee", "ffff", 1)
		}},
		{name: "theme purpose", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = approvedThemeImage
		}},
		{name: "keycloak purpose", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = approvedKeycloakImage
		}},
		{name: "operator purpose", reason: "UntrustedBackupImage", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupImage = approvedOperatorImage
		}},
		{name: "missing validator", reason: "UntrustedBackupImage", noValidator: true},
		{name: "invalid signature", reason: "UntrustedBackupImage", badSignature: true},
		{name: "missing secret ref", reason: "BackupCredentialsInvalid", mutate: func(s *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupSecretRef = ""
		}},
		{name: "missing secret", reason: "BackupCredentialsInvalid", noSecret: true},
		{name: "admin secret", reason: "BackupCredentialsInvalid", mutate: func(s *hankoshv1alpha1.HankoSnapshot, i *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupSecretRef = i.Spec.AdminRef.Name
		}},
		{name: "server database secret", reason: "BackupCredentialsInvalid", mutate: func(s *hankoshv1alpha1.HankoSnapshot, i *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupSecretRef = i.Spec.Managed.Database.Name
		}},
		{name: "serving key secret", reason: "BackupCredentialsInvalid", mutate: func(s *hankoshv1alpha1.HankoSnapshot, i *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			s.Spec.BackupSecretRef = i.Spec.Managed.TLSSecretRef
		}},
		{name: "missing password", reason: "BackupCredentialsInvalid", mutate: func(_ *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, secret *corev1.Secret) {
			delete(secret.Data, "PGPASSWORD")
		}},
		{name: "empty database", reason: "BackupCredentialsInvalid", mutate: func(_ *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance, secret *corev1.Secret) {
			secret.Data["PGDATABASE"] = nil
		}},
		{name: "external with leftover managed spec", reason: "ManagedSpecMissing", mutate: func(_ *hankoshv1alpha1.HankoSnapshot, i *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			i.Spec.Mode = "external"
		}},
		{name: "missing managed database", reason: "ManagedSpecMissing", mutate: func(_ *hankoshv1alpha1.HankoSnapshot, i *hankoshv1alpha1.HankoKeycloakInstance, _ *corev1.Secret) {
			i.Spec.Managed.Database.Name = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, instance := snapshotDataFixture(), managedTestInstance("test", "keycloak")
			secret := snapshotBackupSecret(snapshot)
			if test.mutate != nil {
				test.mutate(snapshot, instance, secret)
			}
			objects := []client.Object{snapshot, instance}
			if !test.noSecret {
				objects = append(objects, secret)
			}
			var validator *imagevalidator.Validator
			if !test.noValidator {
				verifier := fixtureSignatureVerifier{}
				if test.badSignature {
					verifier.err = errors.New("publisher denied credential=do-not-disclose")
				}
				validator = fixtureValidator(t, verifier)
			}
			scheme := controllerTestScheme(t)
			kube := controllerTestClient(scheme, objects...)
			r := &HankoSnapshotReconciler{Client: kube, Scheme: scheme, ImageValidator: validator}
			ctx := context.Background()
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Status.Phase != "Failed" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != test.reason {
				t.Fatalf("did not fail closed: %+v", snapshot.Status)
			}
			var jobs batchv1.JobList
			if err := kube.List(ctx, &jobs); err != nil || len(jobs.Items) != 0 {
				t.Fatalf("untrusted credential-bearing workload created: jobs=%d err=%v", len(jobs.Items), err)
			}
			assertSnapshotNoCredentials(t, snapshot)
		})
	}
}

func TestSnapshotBackupJobUsesOnlyExplicitCredentialsAndHardenedPod(t *testing.T) {
	snapshot := snapshotDataFixture()
	r := &HankoSnapshotReconciler{Scheme: controllerTestScheme(t)}
	job := snapshotOwnedJob(t, r, snapshot)
	pod := job.Spec.Template.Spec
	container := pod.Containers[0]
	if container.Image != approvedBackupImage || len(container.EnvFrom) != 0 || len(container.Env) != 6 {
		t.Fatal("backup image or credential selection lost")
	}
	for _, env := range container.Env {
		if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil || env.ValueFrom.SecretKeyRef.Name != snapshot.Spec.BackupSecretRef || env.ValueFrom.SecretKeyRef.Key != env.Name {
			t.Fatal("backup credentials are not isolated Secret key references")
		}
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.EnableServiceLinks == nil || *pod.EnableServiceLinks {
		t.Fatal("backup Job must not inherit Kubernetes credentials or Service environment")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != 70 || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 70 || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("backup Job must run nonroot with RuntimeDefault seccomp and writable backup volume group")
	}
	security := container.SecurityContext
	if security == nil || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.Capabilities == nil || len(security.Capabilities.Drop) != 1 || security.Capabilities.Drop[0] != "ALL" {
		t.Fatal("backup container hardening lost")
	}
	assertSnapshotNoCredentials(t, job)
}

func assertSnapshotNoCredentials(t *testing.T, object any) {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-disclose") || strings.Contains(string(raw), "UNRELATED_SECRET") {
		t.Fatal("credential or unrelated Secret key leaked into snapshot/Job")
	}
}

func TestSnapshotDoesNotAdoptLegacyOrAlteredJobs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*batchv1.Job)
	}{
		{name: "foreign owner", mutate: func(j *batchv1.Job) { j.OwnerReferences[0].UID = "other-snapshot" }},
		{name: "no owner", mutate: func(j *batchv1.Job) { j.OwnerReferences = nil }},
		{name: "legacy image", mutate: func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].Image = "postgres:16-alpine" }},
		{name: "changed command", mutate: func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].Command = []string{"sh", "-c", "env"} }},
		{name: "broad secret", mutate: func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "database"}}}}
		}},
		{name: "different credentials", mutate: func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name = "database"
		}},
		{name: "token mount", mutate: func(j *batchv1.Job) { j.Spec.Template.Spec.AutomountServiceAccountToken = boolPtr(true) }},
		{name: "privileged", mutate: func(j *batchv1.Job) { j.Spec.Template.Spec.Containers[0].SecurityContext.Privileged = boolPtr(true) }},
		{name: "sidecar", mutate: func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers = append(j.Spec.Template.Spec.Containers, corev1.Container{Name: "sidecar", Image: approvedBackupImage})
		}},
		{name: "init container", mutate: func(j *batchv1.Job) {
			j.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "init", Image: approvedBackupImage}}
		}},
		{name: "extra volume", mutate: func(j *batchv1.Job) {
			j.Spec.Template.Spec.Volumes = append(j.Spec.Template.Spec.Volumes, corev1.Volume{Name: "secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "admin"}}})
		}},
		{name: "host networking", mutate: func(j *batchv1.Job) { j.Spec.Template.Spec.HostNetwork = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := snapshotDataFixture()
			scheme := controllerTestScheme(t)
			r := &HankoSnapshotReconciler{Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
			job := snapshotOwnedJob(t, r, snapshot)
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
			test.mutate(job)
			r.Client = controllerTestClient(scheme, snapshot, job, snapshotBackupSecret(snapshot))
			_, handled := r.reconcileSnapshotData(context.Background(), snapshot, managedTestInstance("test", "keycloak"), client.MergeFrom(snapshot.DeepCopy()))
			if !handled || snapshot.Status.Phase != "Failed" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "JobContractMismatch" {
				t.Fatalf("existing Job bypassed trust: %+v", snapshot.Status)
			}
		})
	}
}

func TestSnapshotExistingJobStillRequiresLiveSignature(t *testing.T) {
	snapshot := snapshotDataFixture()
	scheme := controllerTestScheme(t)
	r := &HankoSnapshotReconciler{Scheme: scheme, ImageValidator: fixtureValidator(t, fixtureSignatureVerifier{err: errors.New("publisher revoked")})}
	job := snapshotOwnedJob(t, r, snapshot)
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	r.Client = controllerTestClient(scheme, snapshot, job, snapshotBackupSecret(snapshot))
	_, handled := r.reconcileSnapshotData(context.Background(), snapshot, managedTestInstance("test", "keycloak"), client.MergeFrom(snapshot.DeepCopy()))
	if !handled || snapshot.Status.Phase != "Failed" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "UntrustedBackupImage" {
		t.Fatalf("completed Job bypassed publisher verification: %+v", snapshot.Status)
	}
}
