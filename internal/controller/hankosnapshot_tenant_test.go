package controller

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSnapshotCaptureIsTenantScoped(t *testing.T) {
	for _, scope := range []string{"unlabelled", "empty", "tenant-a", "tenant-b"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			snapshot := snapshotDataFixture()
			snapshot.Spec.IncludeData = false
			snapshot.Labels = snapshotScopeLabels(scope)
			source := managedTestInstance(snapshot.Namespace, snapshot.Spec.InstanceRef)
			source.Labels = snapshotScopeLabels(scope)
			objects := []client.Object{snapshot, source}
			for _, candidate := range []string{"unlabelled", "empty", "tenant-a", "tenant-b"} {
				objects = append(objects, snapshotScopeObjects(snapshot.Namespace, candidate)...)
			}
			objects = append(objects, snapshotScopeObjects("another-namespace", scope)...)
			kube := snapshotTestClient(t, objects...)
			r := &HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Status.Phase != "Done" {
				t.Fatalf("capture did not complete: %+v", snapshot.Status)
			}
			cm := &corev1.ConfigMap{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: snapshot.Namespace, Name: snapshot.Status.ConfigMapRef}, cm); err != nil {
				t.Fatal(err)
			}
			var payload snapshotData
			if err := json.Unmarshal([]byte(cm.Data["snapshot.json"]), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Realms) != 1 || len(payload.Applications) != 1 || len(payload.ServiceAccounts) != 1 || len(payload.Issuers) != 1 {
				t.Fatalf("snapshot captured another tenant's configuration: realms=%d applications=%d serviceAccounts=%d issuers=%d",
					len(payload.Realms), len(payload.Applications), len(payload.ServiceAccounts), len(payload.Issuers))
			}
			for _, obj := range []client.Object{&payload.Realms[0], &payload.Applications[0], &payload.ServiceAccounts[0], &payload.Issuers[0]} {
				if obj.GetName() != scope || obj.GetNamespace() != snapshot.Namespace {
					t.Fatal("snapshot contains a foreign resource")
				}
			}
		})
	}
}

func snapshotScopeLabels(scope string) map[string]string {
	if scope == "unlabelled" {
		return nil
	}
	if scope == "empty" {
		scope = ""
	}
	return map[string]string{"hanko.sh/tenant": scope}
}

func snapshotScopeObjects(namespace, scope string) []client.Object {
	metadata := metav1.ObjectMeta{Name: scope, Namespace: namespace, Labels: snapshotScopeLabels(scope)}
	return []client.Object{
		&api.HankoRealm{ObjectMeta: metadata},
		&api.HankoApplication{ObjectMeta: metadata},
		&api.HankoServiceAccount{ObjectMeta: metadata},
		&api.HankoIssuer{ObjectMeta: metadata},
	}
}

func TestOperationSnapshotRetainsExactTenantScope(t *testing.T) {
	for _, scope := range []string{"unlabelled", "empty", "tenant-a", "tenant-b"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			source := managedTestInstance("test", "keycloak")
			source.Labels = snapshotScopeLabels(scope)
			op := &api.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "scope", Namespace: "test", Labels: snapshotScopeLabels(scope)},
				Spec: api.HankoOperationSpec{Type: api.OperationClone, InstanceRef: source.Name, Clone: &api.CloneSpec{TargetName: "alias"}}}
			kube := snapshotTestClient(t, source, op)
			for range 2 {
				if _, err := (&HankoOperationReconciler{Client: kube}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := &api.HankoSnapshot{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: op.Namespace, Name: "op-scope-snap"}, snapshot); err != nil {
				t.Fatal(err)
			}
			parentTenant, parentPresent := op.Labels["hanko.sh/tenant"]
			childTenant, childPresent := snapshot.Labels["hanko.sh/tenant"]
			if parentTenant != childTenant || parentPresent != childPresent {
				t.Fatal("operation changed its snapshot's tenant-label identity")
			}
			if _, err := (&HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Status.Phase != "Done" {
				t.Fatalf("composed controllers failed capture: %+v", snapshot.Status)
			}
			if _, err := (&HankoOperationReconciler{Client: kube}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
				t.Fatal(err)
			}
			if op.Status.Steps[0].Status != "Done" || op.Status.Steps[0].ChildUID != string(snapshot.UID) {
				t.Fatal("operation did not accept its exact completed snapshot")
			}
		})
	}
}

func TestLifecycleIntentBindsEmptyTenantLabelPresence(t *testing.T) {
	snapshot := snapshotDataFixture()
	unlabelledSnapshot := snapshotIntentHash(snapshot)
	snapshot.Labels = snapshotScopeLabels("empty")
	if unlabelledSnapshot == snapshotIntentHash(snapshot) {
		t.Fatal("snapshot checkpoint does not bind tenant-label presence")
	}
	op := &api.HankoOperation{Spec: api.HankoOperationSpec{Type: api.OperationClone, InstanceRef: "source", Clone: &api.CloneSpec{TargetName: "alias"}}}
	unlabelledOperation := operationIntentHash(op)
	op.Labels = snapshotScopeLabels("empty")
	if unlabelledOperation == operationIntentHash(op) {
		t.Fatal("operation checkpoint does not bind tenant-label presence")
	}
}

func TestSnapshotRecoveryRejectsCrossScopeStoredCapture(t *testing.T) {
	for _, kind := range []string{"realm", "application", "service-account", "issuer"} {
		for _, scope := range []string{"unlabelled", "empty", "tenant-a"} {
			for _, foreign := range []string{"unlabelled", "empty", "tenant-b", "another-namespace"} {
				if scope == foreign {
					continue
				}
				t.Run(kind+"/"+scope+"/"+foreign, func(t *testing.T) {
					snapshot := snapshotDataFixture()
					snapshot.Labels = snapshotScopeLabels(scope)
					snapshot.Generation = 1
					snapshot.Status.IntentHash = snapshotIntentHash(snapshot)
					metadata := metav1.ObjectMeta{Name: "foreign", Namespace: snapshot.Namespace, Labels: snapshotScopeLabels(foreign)}
					if foreign == "another-namespace" {
						metadata.Namespace, metadata.Labels = foreign, snapshotScopeLabels(scope)
					}
					var payload snapshotData
					switch kind {
					case "realm":
						payload.Realms = []api.HankoRealm{{ObjectMeta: metadata}}
					case "application":
						payload.Applications = []api.HankoApplication{{ObjectMeta: metadata}}
					case "service-account":
						payload.ServiceAccounts = []api.HankoServiceAccount{{ObjectMeta: metadata}}
					case "issuer":
						payload.Issuers = []api.HankoIssuer{{ObjectMeta: metadata}}
					}
					raw, err := json.Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					// Model an immutable capture produced by the older namespace-wide
					// implementation, accepted just before a lost status checkpoint.
					cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "snap-" + snapshot.Name + "-config", Namespace: snapshot.Namespace,
						Labels:          map[string]string{"hanko.sh/tenant": snapshot.Labels["hanko.sh/tenant"]},
						Annotations:     map[string]string{snapshotIntentAnnotation: snapshot.Status.IntentHash, snapshotHashAnnotation: snapshotHash(raw)},
						OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoSnapshot", Name: snapshot.Name, UID: snapshot.UID, Controller: boolPtr(true)}}},
						Immutable: boolPtr(true), Data: map[string]string{"snapshot.json": string(raw)}}
					kube := snapshotTestClient(t, snapshot, cm)
					r := &HankoSnapshotReconciler{Client: kube, Scheme: kube.Scheme()}
					if handled, err := r.ensureSnapshotConfig(context.Background(), snapshot, snapshotPatch(snapshot)); !handled || err != nil {
						t.Fatalf("stored foreign capture accepted: handled=%v err=%v", handled, err)
					}
					if snapshot.Status.Phase != "Failed" || snapshot.Status.ConfigMapUID != "" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "ConfigMapContractMismatch" {
						t.Fatalf("foreign capture gained a checkpoint: %+v", snapshot.Status)
					}
					stored := &corev1.ConfigMap{}
					if err := kube.Get(context.Background(), client.ObjectKeyFromObject(cm), stored); err != nil {
						t.Fatal(err)
					}
					if stored.Data["snapshot.json"] != string(raw) {
						t.Fatal("recovery rewrote the immutable capture")
					}
				})
			}
		}
	}
}
