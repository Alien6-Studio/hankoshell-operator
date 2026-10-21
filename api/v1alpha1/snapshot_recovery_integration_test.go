//go:build integration

package v1alpha1_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errSnapshotWrite = errors.New("injected snapshot API acknowledgement failure")

type snapshotRecoveryClient struct {
	client.Client
	active, after             bool
	createKind                string
	statusAt, statusWrites    int
	configCreates, jobCreates int
}

func (c *snapshotRecoveryClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	kind := "config"
	if _, ok := obj.(*batchv1.Job); ok {
		kind = "job"
	}
	fail := c.active && c.createKind == kind
	if fail && !c.after {
		return errSnapshotWrite
	}
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if kind == "config" {
		c.configCreates++
	} else {
		c.jobCreates++
	}
	if fail {
		return errSnapshotWrite
	}
	return nil
}

func (c *snapshotRecoveryClient) Status() client.SubResourceWriter {
	return snapshotRecoveryStatus{SubResourceWriter: c.Client.Status(), parent: c}
}

type snapshotRecoveryStatus struct {
	client.SubResourceWriter
	parent *snapshotRecoveryClient
}

func (s snapshotRecoveryStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	s.parent.statusWrites++
	fail := s.parent.active && s.parent.statusWrites == s.parent.statusAt
	if fail && !s.parent.after {
		return errSnapshotWrite
	}
	if err := s.SubResourceWriter.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if fail {
		return errSnapshotWrite
	}
	return nil
}

func snapshotAPIFixture(t *testing.T, ctx context.Context, kube client.Client, suffix string, data bool) (*api.HankoSnapshot, *api.HankoKeycloakInstance) {
	t.Helper()
	ns := "snapshot-" + suffix
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	source := &api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: ns}, Spec: api.HankoKeycloakInstanceSpec{
		Mode: "managed", AdminRef: corev1.LocalObjectReference{Name: "admin"}, Managed: &api.ManagedKeycloakSpec{
			Image: "registry.example/iam/pgdump@sha256:" + strings.Repeat("e", 64), TLSSecretRef: "serving-tls", Database: corev1.LocalObjectReference{Name: "database"},
		},
	}}
	snapshot := &api.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "capture", Namespace: ns}, Spec: api.HankoSnapshotSpec{InstanceRef: source.Name}}
	if data {
		snapshot.Spec.IncludeData = true
		snapshot.Spec.BackupImage = source.Spec.Managed.Image
		snapshot.Spec.BackupPVC = "backup"
		snapshot.Spec.BackupSecretRef = "backup-credentials"
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: snapshot.Spec.BackupSecretRef, Namespace: ns}, Data: map[string][]byte{
			"PGHOST": []byte("postgres.test.svc"), "PGDATABASE": []byte("keycloak"), "PGUSER": []byte("backup"), "PGPASSWORD": []byte("fixture-not-a-production-credential"),
		}}
		if err := kube.Create(ctx, secret); err != nil {
			t.Fatal(err)
		}
	}
	for _, obj := range []client.Object{source, snapshot} {
		if err := kube.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	return snapshot, source
}

func snapshotAPIReconcile(t *testing.T, ctx context.Context, kube client.Client, snapshot *api.HankoSnapshot) error {
	t.Helper()
	r := &controller.HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}
	if snapshot.Spec.IncludeData {
		r.ImageValidator = snapshotApprovalFixture(t, snapshot.Spec.BackupImage, &snapshotPublisherFixture{t: t, image: snapshot.Spec.BackupImage})
	}
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)})
	return err
}

func checkSnapshotRecovery(t *testing.T, ctx context.Context, kube client.Client) {
	for index, tc := range []struct {
		name, kind string
		status     int
		data       bool
	}{
		{name: "initial-status", status: 1, data: true},
		{name: "config-create", kind: "config", data: true},
		{name: "config-status", status: 2, data: true},
		{name: "job-create", kind: "job", data: true},
		{name: "job-status", status: 3, data: true},
		{name: "completion-status", status: 3},
	} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-after-%t", tc.name, after), func(t *testing.T) {
				snapshot, _ := snapshotAPIFixture(t, ctx, kube, fmt.Sprintf("write-%d-%t", index, after), tc.data)
				wrapped := &snapshotRecoveryClient{Client: kube, active: true, after: after, createKind: tc.kind, statusAt: tc.status}
				if err := snapshotAPIReconcile(t, ctx, wrapped, snapshot); !errors.Is(err, errSnapshotWrite) {
					t.Fatalf("write failure was swallowed: %v", err)
				}
				if tc.status == 1 && (wrapped.configCreates != 0 || wrapped.jobCreates != 0) {
					t.Fatal("child created before authority was acknowledged")
				}
				if tc.status == 2 && wrapped.jobCreates != 0 {
					t.Fatal("database action preceded configuration checkpoint")
				}
				cm := &corev1.ConfigMap{}
				cmKey := client.ObjectKey{Namespace: snapshot.Namespace, Name: "snap-capture-config"}
				stored := ""
				if err := kube.Get(ctx, cmKey, cm); err == nil {
					stored = cm.Data["snapshot.json"]
					// A retry must retain the capture even when the namespace changes.
					if err := kube.Create(ctx, &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "later", Namespace: snapshot.Namespace}}); err != nil {
						t.Fatal(err)
					}
					altered := cm.DeepCopy()
					altered.Data["snapshot.json"] = `{"tampered":true}`
					if err := kube.Update(ctx, altered); !apierrors.IsInvalid(err) {
						t.Fatalf("snapshot content was mutable: %v", err)
					}
				} else if !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
				wrapped.active = false
				// Fresh reconciler instances exercise process restart recovery on real storage.
				for range 2 {
					if err := snapshotAPIReconcile(t, ctx, wrapped, snapshot); err != nil {
						t.Fatal(err)
					}
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, cmKey, cm); err != nil {
					t.Fatal(err)
				}
				if stored != "" && cm.Data["snapshot.json"] != stored {
					t.Fatal("retry replaced the original configuration capture")
				}
				if snapshot.Status.ConfigMapUID != string(cm.UID) || snapshot.Status.ConfigHash == "" || snapshot.Status.IntentHash == "" {
					t.Fatalf("API server dropped identity checkpoints: %+v", snapshot.Status)
				}
				expectedPhase, expectedJobs := "Done", 0
				if tc.data {
					expectedPhase, expectedJobs = "Running", 1
				}
				if snapshot.Status.Phase != expectedPhase || wrapped.configCreates != 1 || wrapped.jobCreates != expectedJobs {
					t.Fatalf("unsafe recovery: status=%+v configs=%d jobs=%d", snapshot.Status, wrapped.configCreates, wrapped.jobCreates)
				}
				if tc.data && snapshot.Status.DBJobUID == "" {
					t.Fatal("job identity checkpoint missing")
				}
			})
		}
	}
	for _, kind := range []string{"config", "job"} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-replaced-%t", kind, replace), func(t *testing.T) {
				snapshot, _ := snapshotAPIFixture(t, ctx, kube, fmt.Sprintf("child-%s-%t", kind, replace), true)
				if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
					t.Fatal(err)
				}
				var child client.Object = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "snap-capture-config", Namespace: snapshot.Namespace}}
				if kind == "job" {
					child = &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "snap-capture-pgdump", Namespace: snapshot.Namespace}}
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(child), child); err != nil {
					t.Fatal(err)
				}
				if err := kube.Delete(ctx, child, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
					t.Fatal(err)
				}
				if replace {
					child.SetUID("")
					child.SetResourceVersion("")
					if job, ok := child.(*batchv1.Job); ok {
						job.Spec.Selector = nil
						job.Spec.Template.Labels = nil
						job.Labels = nil
						job.Status = batchv1.JobStatus{}
					}
					if err := kube.Create(ctx, child); err != nil {
						t.Fatal(err)
					}
				}
				if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
					t.Fatal(err)
				}
				if snapshot.Status.Phase != "Failed" {
					t.Fatalf("deleted/replaced child accepted: %+v", snapshot.Status)
				}
				if !replace {
					if err := kube.Get(ctx, client.ObjectKeyFromObject(child), child); !apierrors.IsNotFound(err) {
						t.Fatalf("checkpointed child replayed: %v", err)
					}
				}
			})
		}
	}
	for _, change := range []string{"spec", "tenant", "source", "legacy", "foreign-config"} {
		t.Run("reject-"+change, func(t *testing.T) {
			snapshot, source := snapshotAPIFixture(t, ctx, kube, "reject-"+change, true)
			if change == "foreign-config" {
				if err := kube.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "snap-capture-config", Namespace: snapshot.Namespace}, Data: map[string]string{"snapshot.json": "{}"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "spec":
					snapshot.Spec.BackupPVC = "changed"
					if err := kube.Update(ctx, snapshot); err != nil {
						t.Fatal(err)
					}
				case "tenant":
					snapshot.Labels = map[string]string{"hanko.sh/tenant": "other"}
					if err := kube.Update(ctx, snapshot); err != nil {
						t.Fatal(err)
					}
				case "source":
					if err := kube.Delete(ctx, source); err != nil {
						t.Fatal(err)
					}
					source.SetUID("")
					source.SetResourceVersion("")
					if err := kube.Create(ctx, source); err != nil {
						t.Fatal(err)
					}
				case "legacy":
					snapshot.Status.IntentHash = ""
					if err := kube.Status().Update(ctx, snapshot); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Status.Phase != "Failed" {
				t.Fatalf("unsafe recovery accepted: %+v", snapshot.Status)
			}
			if change == "foreign-config" {
				var jobs batchv1.JobList
				if err := kube.List(ctx, &jobs, client.InNamespace(snapshot.Namespace)); err != nil {
					t.Fatal(err)
				}
				if len(jobs.Items) != 0 {
					t.Fatal("foreign configuration authorized database execution")
				}
			}
		})
	}

	t.Run("failed-job", func(t *testing.T) {
		snapshot, _ := snapshotAPIFixture(t, ctx, kube, "failed-job", true)
		if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
			t.Fatal(err)
		}
		job := &batchv1.Job{}
		if err := kube.Get(ctx, client.ObjectKey{Namespace: snapshot.Namespace, Name: "snap-capture-pgdump"}, job); err != nil {
			t.Fatal(err)
		}
		now := metav1.Now()
		job.Status.StartTime = &now
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue}, {Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
		if err := kube.Status().Update(ctx, job); err != nil {
			t.Fatal(err)
		}
		if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Status.Phase != "Failed" {
			t.Fatal("failed Job produced a successful snapshot")
		}
	})
}
