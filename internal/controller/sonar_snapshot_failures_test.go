package controller

import (
	"context"
	"errors"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

type snapshotFaultClient struct {
	client.Client
	failList   string
	failGet    string
	failCreate string
}

func (c snapshotFaultClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	kind := ""
	switch list.(type) {
	case *hankoshv1alpha1.HankoRealmList:
		kind = "realms"
	case *hankoshv1alpha1.HankoApplicationList:
		kind = "applications"
	case *hankoshv1alpha1.HankoServiceAccountList:
		kind = "service-accounts"
	case *hankoshv1alpha1.HankoIssuerList:
		kind = "issuers"
	}
	if kind == c.failList {
		return errors.New("injected list failure")
	}
	return c.Client.List(ctx, list, options...)
}

func (c snapshotFaultClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	kind := ""
	switch object.(type) {
	case *hankoshv1alpha1.HankoKeycloakInstance:
		kind = "instance"
	case *corev1.ConfigMap:
		kind = "config-map"
	case *batchv1.Job:
		kind = "job"
	}
	if c.failGet != "" && kind == c.failGet {
		return errors.New("injected get failure")
	}
	return c.Client.Get(ctx, key, object, options...)
}

func (c snapshotFaultClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	kind := ""
	switch object.(type) {
	case *corev1.ConfigMap:
		kind = "config-map"
	case *batchv1.Job:
		kind = "job"
	}
	if kind == c.failCreate {
		return errors.New("injected create failure")
	}
	return c.Client.Create(ctx, object, options...)
}

func TestSnapshotPayloadFailsClosedForEveryInventoryKind(t *testing.T) {
	base := controllerTestClient(controllerTestScheme(t))
	for _, test := range []struct {
		kind, reason string
	}{
		{kind: "realms", reason: "ListRealmsError"},
		{kind: "applications", reason: "ListAppsError"},
		{kind: "service-accounts", reason: "ListSAsError"},
		{kind: "issuers", reason: "ListIssuersError"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			reconciler := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: base, failList: test.kind}}
			raw, failure := reconciler.snapshotPayload(context.Background(), "test")
			if raw != nil || failure == nil || failure.reason != test.reason {
				t.Fatalf("snapshot list failure raw=%q failure=%#v", raw, failure)
			}
		})
	}
}

func TestSnapshotInfrastructureFailuresAreCheckpointed(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")

	t.Run("instance lookup", func(t *testing.T) {
		snapshot := &hankoshv1alpha1.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "instance-failure", Namespace: "test"}}
		reconciler := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: controllerTestClient(scheme, snapshot), failGet: "instance"}}
		if _, handled := reconciler.snapshotInstance(ctx, snapshot, client.MergeFrom(snapshot.DeepCopy())); !handled || snapshot.Status.Phase != "Failed" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "InstanceError" {
			t.Fatalf("instance failure status = %#v", snapshot.Status)
		}
	})

	t.Run("existing config map", func(t *testing.T) {
		configMap := &corev1.ConfigMap{}
		configMap.Name, configMap.Namespace = "snapshot", "test"
		reconciler := &HankoSnapshotReconciler{Client: controllerTestClient(scheme, configMap)}
		if failure := reconciler.createSnapshotConfigMap(ctx, configMap.DeepCopy(), []byte(`{"safe":true}`)); failure != nil {
			t.Fatalf("existing config map must be idempotent: %#v", failure)
		}
	})

	for _, test := range []struct {
		name, failGet, failCreate, reason string
	}{
		{name: "config map get", failGet: "config-map", reason: "ConfigMapGetError"},
		{name: "config map create", failCreate: "config-map", reason: "ConfigMapCreateError"},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := controllerTestClient(scheme)
			reconciler := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: base, failGet: test.failGet, failCreate: test.failCreate}}
			failure := reconciler.createSnapshotConfigMap(ctx, &corev1.ConfigMap{}, []byte(`{"safe":true}`))
			if failure == nil || failure.reason != test.reason {
				t.Fatalf("config map failure = %#v", failure)
			}
		})
	}

	t.Run("owner reference", func(t *testing.T) {
		snapshot := &hankoshv1alpha1.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "owner-failure", Namespace: "test"}}
		reconciler := &HankoSnapshotReconciler{Client: controllerTestClient(scheme, snapshot), Scheme: runtime.NewScheme()}
		if !reconciler.ensureSnapshotConfig(ctx, snapshot, client.MergeFrom(snapshot.DeepCopy())) || snapshot.Status.Phase != "Failed" || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "OwnerRefError" {
			t.Fatalf("owner reference failure = %#v", snapshot.Status)
		}
	})

	t.Run("job lookup", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		reconciler := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: controllerTestClient(scheme, snapshot, snapshotBackupSecret(snapshot)), failGet: "job"}, ImageValidator: approvedFixtureValidator(t)}
		if _, handled := reconciler.reconcileSnapshotData(ctx, snapshot, instance, client.MergeFrom(snapshot.DeepCopy())); !handled || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "JobGetError" {
			t.Fatalf("job lookup failure = %#v", snapshot.Status)
		}
	})

	t.Run("job create", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		base := controllerTestClient(scheme, snapshot, snapshotBackupSecret(snapshot))
		reconciler := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: base, failCreate: "job"}, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
		result := reconciler.createSnapshotJob(ctx, snapshot, instance, client.MergeFrom(snapshot.DeepCopy()), "snapshot-job")
		if !result.IsZero() || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "JobCreateError" {
			t.Fatalf("job create failure result=%v status=%#v", result, snapshot.Status)
		}
	})
}
