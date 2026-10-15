//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkSnapshotTenantCapture(t *testing.T, ctx context.Context, kube client.Client) {
	const namespace = "snapshot-tenant-inventory"
	for _, ns := range []string{namespace, namespace + "-foreign"} {
		if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			t.Fatal(err)
		}
		for _, scope := range []string{"unlabelled", "empty", "tenant-a", "tenant-b"} {
			metadata := snapshotTenantMetadata(ns, scope)
			for _, obj := range []client.Object{
				&api.HankoRealm{ObjectMeta: metadata},
				&api.HankoApplication{ObjectMeta: metadata, Spec: api.HankoApplicationSpec{RealmRef: scope, ClientID: scope, Type: "spa"}},
				&api.HankoServiceAccount{ObjectMeta: metadata, Spec: api.HankoServiceAccountSpec{RealmRef: scope, ClientID: scope}},
				&api.HankoIssuer{ObjectMeta: metadata, Spec: api.HankoIssuerSpec{RealmRef: scope, Host: scope + ".example.test"}},
			} {
				if err := kube.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, scope := range []string{"unlabelled", "empty", "tenant-a", "tenant-b"} {
		t.Run(scope, func(t *testing.T) {
			metadata := snapshotTenantMetadata(namespace, scope)
			source := &api.HankoKeycloakInstance{ObjectMeta: metadata, Spec: api.HankoKeycloakInstanceSpec{
				Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "admin"},
			}}
			snapshot := &api.HankoSnapshot{ObjectMeta: metadata, Spec: api.HankoSnapshotSpec{InstanceRef: scope}}
			for _, obj := range []client.Object{source, snapshot} {
				if err := kube.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
			}
			r := &controller.HankoSnapshotReconciler{Client: kube, APIReader: kube, Scheme: kube.Scheme()}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Status.Phase != "Done" || snapshot.Status.ConfigMapUID == "" || snapshot.Status.ConfigHash == "" {
				t.Fatalf("scoped capture incomplete: %+v", snapshot.Status)
			}
			capture := &corev1.ConfigMap{}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: snapshot.Status.ConfigMapRef}, capture); err != nil {
				t.Fatal(err)
			}
			var payload map[string][]json.RawMessage
			if err := json.Unmarshal([]byte(capture.Data["snapshot.json"]), &payload); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"realms", "applications", "serviceAccounts", "issuers"} {
				items := payload[kind]
				if len(items) != 1 {
					t.Fatalf("%s captured %d resources, want the one matching tenant", kind, len(items))
				}
				var object struct {
					Metadata metav1.ObjectMeta `json:"metadata"`
				}
				if err := json.Unmarshal(items[0], &object); err != nil {
					t.Fatal(err)
				}
				if object.Metadata.Name != scope || object.Metadata.Namespace != namespace {
					t.Fatal("capture crossed tenant or namespace boundary")
				}
			}
			// A fresh reconciler must keep the exact immutable point-in-time capture.
			r = &controller.HankoSnapshotReconciler{Client: kube, APIReader: kube, Scheme: kube.Scheme()}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
				t.Fatal(err)
			}
			stored := &corev1.ConfigMap{}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(capture), stored); err != nil {
				t.Fatal(err)
			}
			if stored.UID != capture.UID || stored.Data["snapshot.json"] != capture.Data["snapshot.json"] {
				t.Fatal("restart replaced or rewrote the capture")
			}
			checkOperationSnapshotTenantScope(t, ctx, kube, source, scope)
		})
	}
}

func checkOperationSnapshotTenantScope(t *testing.T, ctx context.Context, kube client.Client, source *api.HankoKeycloakInstance, scope string) {
	t.Helper()
	op := &api.HankoOperation{ObjectMeta: snapshotTenantMetadata(source.Namespace, scope),
		Spec: api.HankoOperationSpec{Type: api.OperationClone, InstanceRef: source.Name, Clone: &api.CloneSpec{TargetName: "alias-" + scope}}}
	op.Name = "chain-" + scope
	if err := kube.Create(ctx, op); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := reconcileOperationAPI(ctx, kube, op); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := &api.HankoSnapshot{}
	if err := kube.Get(ctx, client.ObjectKey{Namespace: op.Namespace, Name: "op-" + op.Name + "-snap"}, snapshot); err != nil {
		t.Fatal(err)
	}
	parentTenant, parentPresent := op.Labels["hanko.sh/tenant"]
	childTenant, childPresent := snapshot.Labels["hanko.sh/tenant"]
	if parentTenant != childTenant || parentPresent != childPresent {
		t.Fatal("operation changed its child tenant-label identity")
	}
	if err := snapshotAPIReconcile(t, ctx, kube, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.Phase != "Done" {
		t.Fatalf("composed operation/snapshot capture failed: %+v", snapshot.Status)
	}
	if err := reconcileOperationAPI(ctx, kube, op); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
		t.Fatal(err)
	}
	if op.Status.Steps[0].Status != "Done" || op.Status.Steps[0].ChildUID != string(snapshot.UID) {
		t.Fatal("operation lost its completed snapshot identity")
	}
}

func snapshotTenantMetadata(namespace, scope string) metav1.ObjectMeta {
	metadata := metav1.ObjectMeta{Name: scope, Namespace: namespace}
	if scope != "unlabelled" {
		tenant := scope
		if scope == "empty" {
			tenant = ""
		}
		metadata.Labels = map[string]string{"hanko.sh/tenant": tenant}
	}
	return metadata
}
