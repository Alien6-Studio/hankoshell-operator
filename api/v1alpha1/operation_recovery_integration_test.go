//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errOperationFault = errors.New("injected operation API acknowledgement failure")

// Keep the real API server as the storage/validation authority; faults surround
// actual accepted writes. A new reconciler is constructed for every retry.
type operationFaultClient struct {
	client.Client
	createFault string
	statusFault string
	creates     int
}

func (c *operationFaultClient) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	if c.createFault == "before" {
		return errOperationFault
	}
	if err := c.Client.Create(ctx, o, opts...); err != nil {
		return err
	}
	c.creates++
	if c.createFault == "after" {
		return errOperationFault
	}
	return nil
}

func (c *operationFaultClient) Status() client.SubResourceWriter {
	return operationFaultStatus{SubResourceWriter: c.Client.Status(), parent: c}
}

type operationFaultStatus struct {
	client.SubResourceWriter
	parent *operationFaultClient
}

func (s operationFaultStatus) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
	if s.parent.statusFault == "before" {
		return errOperationFault
	}
	if err := s.SubResourceWriter.Patch(ctx, o, p, opts...); err != nil {
		return err
	}
	if s.parent.statusFault == "after" {
		return errOperationFault
	}
	return nil
}

func operationAPIFixture(t *testing.T, ctx context.Context, kube client.Client, name string, clone bool) (*api.HankoOperation, *api.HankoKeycloakInstance) {
	t.Helper()
	ns := "operation-" + name
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	source := &api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: ns}, Spec: api.HankoKeycloakInstanceSpec{
		Mode: "managed", AdminRef: corev1.LocalObjectReference{Name: "admin"}, TLSCARef: "provider-ca", Managed: &api.ManagedKeycloakSpec{
			Image: "registry.example/keycloak@sha256:" + strings.Repeat("a", 64), TLSSecretRef: "serving-tls", Database: corev1.LocalObjectReference{Name: "database"},
		},
	}}
	if err := kube.Create(ctx, source); err != nil {
		t.Fatal(err)
	}
	op := &api.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "work", Namespace: ns}, Spec: api.HankoOperationSpec{Type: api.OperationUpgrade, InstanceRef: source.Name, Upgrade: &api.UpgradeSpec{ToImage: "registry.example/keycloak@sha256:" + strings.Repeat("b", 64)}}}
	if clone {
		disabled := false
		op.Spec.Type, op.Spec.Upgrade, op.Spec.SnapshotBefore = api.OperationClone, nil, &disabled
		op.Spec.Clone = &api.CloneSpec{TargetName: "target"}
	}
	if err := kube.Create(ctx, op); err != nil {
		t.Fatal(err)
	}
	return op, source
}

func reconcileOperationAPI(ctx context.Context, kube client.Client, op *api.HankoOperation) error {
	_, err := (&controller.HankoOperationReconciler{Client: kube}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)})
	return err
}

func checkOperationRecovery(t *testing.T, ctx context.Context, kube client.Client) {
	for _, boundary := range []string{"initial-status", "before-create", "after-create", "before-status", "after-status"} {
		t.Run(boundary, func(t *testing.T) {
			op, source := operationAPIFixture(t, ctx, kube, boundary, false)
			faults := &operationFaultClient{Client: kube}
			if boundary == "initial-status" {
				faults.statusFault = "before"
				if err := reconcileOperationAPI(ctx, faults, op); !errors.Is(err, errOperationFault) {
					t.Fatalf("initial status error lost: %v", err)
				}
				if faults.creates != 0 {
					t.Fatal("child created before authority checkpoint")
				}
				faults.statusFault = ""
			}
			if err := reconcileOperationAPI(ctx, faults, op); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
				t.Fatal(err)
			}
			if op.Status.InstanceUID != string(source.UID) || op.Status.IntentHash == "" || op.Status.StartedGeneration != op.Generation {
				t.Fatal("authority checkpoint not persisted")
			}
			switch boundary {
			case "before-create":
				faults.createFault = "before"
			case "after-create":
				faults.createFault = "after"
			case "before-status":
				faults.statusFault = "before"
			case "after-status":
				faults.statusFault = "after"
			}
			err := reconcileOperationAPI(ctx, faults, op)
			if boundary != "initial-status" && !errors.Is(err, errOperationFault) {
				t.Fatalf("injected error lost: %v", err)
			}
			faults.createFault, faults.statusFault = "", ""
			for range 2 {
				if err := reconcileOperationAPI(ctx, faults, op); err != nil {
					t.Fatal(err)
				}
			}
			var snapshots api.HankoSnapshotList
			if err := kube.List(ctx, &snapshots, client.InNamespace(op.Namespace)); err != nil {
				t.Fatal(err)
			}
			if faults.creates != 1 || len(snapshots.Items) != 1 {
				t.Fatal("restart duplicated snapshot creation")
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
				t.Fatal(err)
			}
			child := &snapshots.Items[0]
			if op.Status.Steps[0].ChildUID != string(child.UID) || op.Status.Steps[0].ChildGeneration != child.Generation {
				t.Fatal("exact child identity not checkpointed")
			}
			child.Status.Phase = "Failed"
			child.Status.Conditions = []metav1.Condition{{Type: "SnapshotReady", Status: metav1.ConditionFalse, Reason: "Failure", Message: "private-child-error-sentinel", LastTransitionTime: metav1.Now()}}
			if err := kube.Status().Update(ctx, child); err != nil {
				t.Fatal(err)
			}
			if err := reconcileOperationAPI(ctx, faults, op); err == nil {
				t.Fatal("failed snapshot ignored")
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(op.Status)
			if op.Status.Phase != "Failed" || strings.Contains(string(data), "private-child-error-sentinel") {
				t.Fatal("child failure not safely propagated")
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(source), source); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(source.Spec.Managed.Image, strings.Repeat("a", 64)) {
				t.Fatal("image changed after failed snapshot")
			}
		})
	}
	t.Run("foreign and replaced children", func(t *testing.T) { checkOperationChildConflicts(t, ctx, kube) })
	t.Run("clone validates target and import coverage", func(t *testing.T) { checkOperationCloneRecovery(t, ctx, kube) })
}

func checkOperationChildConflicts(t *testing.T, ctx context.Context, kube client.Client) {
	for _, kind := range []string{"foreign", "replacement", "edited", "missing", "intent-changed", "source-replaced"} {
		t.Run(kind, func(t *testing.T) {
			op, source := operationAPIFixture(t, ctx, kube, kind, false)
			if err := reconcileOperationAPI(ctx, kube, op); err != nil {
				t.Fatal(err)
			}
			child := &api.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "op-work-snap", Namespace: op.Namespace}, Spec: api.HankoSnapshotSpec{InstanceRef: source.Name}}
			if kind == "foreign" {
				if err := kube.Create(ctx, child); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(child), child); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "replacement", "missing":
				if err := kube.Delete(ctx, child); err != nil {
					t.Fatal(err)
				}
				if kind == "replacement" {
					child.ResourceVersion = ""
					child.UID = ""
					if err := kube.Create(ctx, child); err != nil {
						t.Fatal(err)
					}
				}
			case "edited":
				child.Spec.InstanceRef = "different-source"
				if err := kube.Update(ctx, child); err != nil {
					t.Fatal(err)
				}
			case "intent-changed":
				if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
					t.Fatal(err)
				}
				op.Spec.DryRun = true
				if err := kube.Update(ctx, op); err != nil {
					t.Fatal(err)
				}
			case "source-replaced":
				if err := kube.Delete(ctx, source); err != nil {
					t.Fatal(err)
				}
				source.ResourceVersion = ""
				source.UID = ""
				if err := kube.Create(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			if err := reconcileOperationAPI(ctx, kube, op); err == nil {
				t.Fatal("changed/foreign authority accepted")
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
				t.Fatal(err)
			}
			if op.Status.Phase != "Failed" {
				t.Fatal("unsafe operation not stopped")
			}
		})
	}
}

func checkOperationCloneRecovery(t *testing.T, ctx context.Context, kube client.Client) {
	for _, variant := range []string{"complete", "partial", "failed"} {
		t.Run(variant, func(t *testing.T) {
			op, source := operationAPIFixture(t, ctx, kube, "clone-"+variant, true)
			for range 4 {
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
			}
			target := &api.HankoKeycloakInstance{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: op.Namespace, Name: "target"}, target); err != nil {
				t.Fatal(err)
			}
			if target.Spec.TLSCARef != source.Spec.TLSCARef || target.Spec.RotateAdminCredentials || target.Spec.HardenMasterRealm {
				t.Fatal("clone lost TLS trust or acquired extra authority")
			}
			imported := &api.HankoImport{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: op.Namespace, Name: "op-work-import"}, imported); err != nil {
				t.Fatal(err)
			}
			imported.Status.Phase = "Done"
			imported.Status.Coverage.Complete = variant == "complete"
			imported.Status.Conditions = []metav1.Condition{{Type: "ImportReady", Status: metav1.ConditionTrue, Reason: "Completed", LastTransitionTime: metav1.Now()}}
			if variant == "failed" {
				imported.Status.Phase = "Failed"
			}
			if err := kube.Status().Update(ctx, imported); err != nil {
				t.Fatal(err)
			}
			err := reconcileOperationAPI(ctx, kube, op)
			if variant != "complete" {
				if err == nil {
					t.Fatal("incomplete import accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A Ready source must not substitute for the target's own observation.
			source.Status.Phase = "Ready"
			source.Status.Conditions = []metav1.Condition{{Type: "AdminAPIReachable", Status: metav1.ConditionTrue, Reason: "ProbeSucceeded", ObservedGeneration: source.Generation, LastTransitionTime: metav1.Now()}}
			if err := kube.Status().Update(ctx, source); err != nil {
				t.Fatal(err)
			}
			for _, generation := range []int64{0, target.Generation} {
				target.Status.Phase = "Ready"
				target.Status.Conditions = []metav1.Condition{{Type: "AdminAPIReachable", Status: metav1.ConditionTrue, Reason: "ProbeSucceeded", ObservedGeneration: generation, LastTransitionTime: metav1.Now()}}
				if err := kube.Status().Update(ctx, target); err != nil {
					t.Fatal(err)
				}
				if err := reconcileOperationAPI(ctx, kube, op); err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
					t.Fatal(err)
				}
				if (op.Status.Phase == "Done") != (generation == target.Generation) {
					t.Fatal("completion did not track current target evidence")
				}
			}
		})
	}
}
