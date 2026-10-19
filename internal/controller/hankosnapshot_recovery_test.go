package controller

import (
	"context"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func snapshotTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	for _, obj := range objects {
		if obj.GetUID() == "" {
			obj.SetUID(uuid.NewUUID())
		}
		if obj.GetGeneration() == 0 {
			obj.SetGeneration(1)
		}
	}
	base := controllerTestClient(controllerTestScheme(t), objects...)
	return interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			obj.SetUID(uuid.NewUUID())
			obj.SetGeneration(1)
			return c.Create(ctx, obj, opts...)
		},
	})
}

func TestSnapshotConfigRejectsForeignOrAlteredCaptures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.ConfigMap)
	}{
		{"foreign UID", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].UID = "other" }},
		{"foreign kind", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].Kind = "HankoOperation" }},
		{"foreign name", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].Name = "other" }},
		{"foreign API", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].APIVersion = "other/v1" }},
		{"unowned", func(cm *corev1.ConfigMap) { cm.OwnerReferences = nil }},
		{"mutable", func(cm *corev1.ConfigMap) { cm.Immutable = nil }},
		{"missing marker", func(cm *corev1.ConfigMap) { cm.Annotations = nil }},
		{"tenant changed", func(cm *corev1.ConfigMap) { cm.Labels["hanko.sh/tenant"] = "other" }},
		{"content changed", func(cm *corev1.ConfigMap) { cm.Data["snapshot.json"] = `{"changed":true}` }},
		{"invalid JSON", func(cm *corev1.ConfigMap) {
			cm.Data["snapshot.json"] = `broken`
			cm.Annotations[snapshotHashAnnotation] = snapshotHash([]byte("broken"))
		}},
		{"extra data", func(cm *corev1.ConfigMap) { cm.Data["extra"] = "untrusted" }},
		{"binary data", func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"extra": {1}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			snapshot := snapshotDataFixture()
			snapshot.Status.IntentHash = snapshotIntentHash(snapshot)
			kube := snapshotTestClient(t, snapshot)
			r := &HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}
			if handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot)); handled || err != nil {
				t.Fatalf("create config: handled=%v err=%v", handled, err)
			}
			cm := &corev1.ConfigMap{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: snapshot.Namespace, Name: snapshot.Status.ConfigMapRef}, cm); err != nil {
				t.Fatal(err)
			}
			tc.mutate(cm)
			// Fake storage deliberately permits edits denied by the real immutable API.
			if err := kube.Update(ctx, cm); err != nil {
				t.Fatal(err)
			}
			if handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot)); !handled || err != nil || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "ConfigMapContractMismatch" {
				t.Fatalf("capture accepted: handled=%v err=%v status=%+v", handled, err, snapshot.Status)
			}
		})
	}
}

func TestSnapshotRetriesEveryWriteBoundaryWithoutRepeatingCaptureOrJob(t *testing.T) {
	for _, tc := range []struct {
		name, createKind string
		statusWrite      int
	}{
		{name: "initial checkpoint", statusWrite: 1},
		{name: "configuration create", createKind: "config"},
		{name: "configuration checkpoint", statusWrite: 2},
		{name: "job create", createKind: "job"},
		{name: "job checkpoint", statusWrite: 3},
	} {
		for _, after := range []bool{false, true} {
			name := tc.name + " before"
			if after {
				name = tc.name + " after"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				snapshot := snapshotDataFixture()
				source := managedTestInstance("test", "keycloak")
				kube := snapshotTestClient(t, snapshot, source, snapshotBackupSecret(snapshot))
				injected := errors.New("injected write acknowledgement failure")
				statusWrites, configCreates, jobCreates := 0, 0, 0
				fault := true
				wrapped := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						kind := "config"
						if _, ok := obj.(*batchv1.Job); ok {
							kind = "job"
						}
						fail := fault && tc.createKind == kind
						if fail && !after {
							return injected
						}
						if err := c.Create(ctx, obj, opts...); err != nil {
							return err
						}
						if kind == "config" {
							configCreates++
						} else {
							jobCreates++
						}
						if fail {
							return injected
						}
						return nil
					},
					SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						statusWrites++
						fail := fault && tc.statusWrite == statusWrites
						if fail && !after {
							return injected
						}
						if err := c.SubResource(sub).Patch(ctx, obj, patch, opts...); err != nil {
							return err
						}
						if fail {
							return injected
						}
						return nil
					},
				})
				reconcile := func() error {
					r := &HankoSnapshotReconciler{Client: wrapped, Scheme: kube.Scheme(), ImageValidator: approvedFixtureValidator(t)}
					_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)})
					return err
				}
				if err := reconcile(); !errors.Is(err, injected) {
					t.Fatalf("write failure not returned: %v", err)
				}
				if tc.statusWrite == 1 && (configCreates != 0 || jobCreates != 0) {
					t.Fatal("child created without persisted authority")
				}
				if tc.statusWrite == 2 && jobCreates != 0 {
					t.Fatal("job started before capture checkpoint")
				}
				fault = false
				if err := reconcile(); err != nil {
					t.Fatal(err)
				}
				if err := reconcile(); err != nil {
					t.Fatal(err)
				}
				if configCreates != 1 || jobCreates != 1 {
					t.Fatalf("duplicate capture/execution: config=%d job=%d", configCreates, jobCreates)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
					t.Fatal(err)
				}
				if snapshot.Status.Phase != "Running" || snapshot.Status.ConfigMapUID == "" || snapshot.Status.DBJobUID == "" {
					t.Fatalf("missing checkpoints: %+v", snapshot.Status)
				}
			})
		}
	}
}

func TestSnapshotFailureStatusErrorsPropagate(t *testing.T) {
	ctx := context.Background()
	snapshot := snapshotDataFixture()
	kube := snapshotTestClient(t, snapshot)
	injected := errors.New("injected failure status write")
	wrapped := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
			return injected
		},
	})
	r := &HankoSnapshotReconciler{Client: wrapped}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); !errors.Is(err, injected) {
		t.Fatalf("failure acknowledgement swallowed: %v", err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.Phase == "Failed" {
		t.Fatal("failed status was not stored")
	}
}

func TestSnapshotCheckpointRejectsRetargetedOrLegacyWork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*api.HankoSnapshot, *api.HankoKeycloakInstance)
	}{
		{"spec", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) { s.Spec.BackupPVC = "other" }},
		{"generation", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) { s.Generation++ }},
		{"tenant", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) {
			s.Labels = map[string]string{"hanko.sh/tenant": "other"}
		}},
		{"source replaced", func(_ *api.HankoSnapshot, i *api.HankoKeycloakInstance) { i.UID = "replacement" }},
		{"source deleting", func(_ *api.HankoSnapshot, i *api.HankoKeycloakInstance) {
			now := metav1.Now()
			i.DeletionTimestamp = &now
		}},
		{"legacy", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) { s.Status.IntentHash = "" }},
		{"incomplete capture", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) { s.Status.ConfigMapRef = "snap-data-config" }},
		{"orphan job", func(s *api.HankoSnapshot, _ *api.HankoKeycloakInstance) {
			s.Status.DBJobRef = "snap-data-pgdump"
			s.Status.DBJobUID = "job"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := snapshotDataFixture()
			s.Generation = 1
			i := managedTestInstance("test", "keycloak")
			i.UID = "source"
			s.Status = api.HankoSnapshotStatus{Phase: "Running", IntentHash: snapshotIntentHash(s), StartedGeneration: s.Generation, InstanceUID: string(i.UID)}
			if reason := validateSnapshotCheckpoint(s, i); reason != "" {
				t.Fatal(reason)
			}
			tc.mutate(s, i)
			if validateSnapshotCheckpoint(s, i) == "" {
				t.Fatal("unsafe checkpoint accepted")
			}
		})
	}
}

func TestSnapshotRecoveryDoesNotRequireNewInventory(t *testing.T) {
	ctx := context.Background()
	snapshot := snapshotDataFixture()
	snapshot.Status.IntentHash = snapshotIntentHash(snapshot)
	kube := snapshotTestClient(t, snapshot)
	r := &HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}
	if handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot)); handled || err != nil {
		t.Fatalf("capture failed: handled=%v err=%v", handled, err)
	}
	// A failed list must not prevent recovery of the already stored capture.
	r.Client = snapshotFaultClient{Client: kube, failList: "realms"}
	if handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot)); handled || err != nil {
		t.Fatalf("recovery re-enumerated live state: handled=%v err=%v", handled, err)
	}
}

func TestSnapshotConcurrentSpecEditCannotCommitSuccess(t *testing.T) {
	ctx := context.Background()
	snapshot := snapshotDataFixture()
	snapshot.Spec.IncludeData = false
	source := managedTestInstance("test", "keycloak")
	kube := snapshotTestClient(t, snapshot, source)
	writes := 0
	wrapped := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			writes++
			if writes == 3 {
				current := &api.HankoSnapshot{}
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
					return err
				}
				current.Spec.BackupPVC = "edited"
				if err := c.Update(ctx, current); err != nil {
					return err
				}
			}
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	})
	r := &HankoSnapshotReconciler{Client: wrapped, Scheme: kube.Scheme()}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err == nil {
		t.Fatal("concurrent edit did not conflict with completion")
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.Phase == "Done" {
		t.Fatal("old intent was marked successful")
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
		t.Fatal(err)
	}
	if conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "CheckpointRejected" {
		t.Fatalf("edited intent accepted: %+v", snapshot.Status)
	}
}
