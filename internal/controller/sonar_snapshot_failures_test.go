package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
			if raw != nil || failure == nil || !strings.Contains(failure.Error(), test.reason) {
				t.Fatalf("snapshot list failure raw=%q failure=%#v", raw, failure)
			}
		})
	}
}

func TestSnapshotInfrastructureFailuresAreRetried(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	t.Run("instance lookup", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		r := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: snapshotTestClient(t, snapshot), failGet: "instance"}}
		if _, handled, err := r.snapshotInstance(ctx, snapshot, snapshotPatch(snapshot)); !handled || err == nil || snapshot.Status.Phase == "Failed" {
			t.Fatalf("instance read must retry without terminal failure: handled=%v err=%v", handled, err)
		}
	})
	for _, test := range []struct{ name, failGet, failCreate string }{
		{name: "config map get", failGet: "config-map"},
		{name: "config map create", failCreate: "config-map"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := snapshotDataFixture()
			r := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: snapshotTestClient(t, snapshot), failGet: test.failGet, failCreate: test.failCreate}, Scheme: scheme}
			handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot))
			if !handled || err == nil || snapshot.Status.Phase == "Failed" {
				t.Fatalf("configuration must retry: handled=%v err=%v", handled, err)
			}
		})
	}
	t.Run("owner reference", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		r := &HankoSnapshotReconciler{Client: snapshotTestClient(t, snapshot), Scheme: runtime.NewScheme()}
		handled, err := r.ensureSnapshotConfig(ctx, snapshot, snapshotPatch(snapshot))
		if !handled || err != nil || conditionReason(snapshot.Status.Conditions, "SnapshotReady") != "OwnerRefError" {
			t.Fatalf("owner reference failure: handled=%v err=%v", handled, err)
		}
	})
	t.Run("job lookup", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		r := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: snapshotTestClient(t, snapshot, snapshotBackupSecret(snapshot)), failGet: "job"}, ImageValidator: approvedFixtureValidator(t)}
		if _, handled, err := r.reconcileSnapshotData(ctx, snapshot, instance, snapshotPatch(snapshot)); !handled || err == nil || snapshot.Status.Phase == "Failed" {
			t.Fatalf("job read must retry: handled=%v err=%v", handled, err)
		}
	})
	t.Run("job create", func(t *testing.T) {
		snapshot := snapshotDataFixture()
		r := &HankoSnapshotReconciler{Client: snapshotFaultClient{Client: snapshotTestClient(t, snapshot, snapshotBackupSecret(snapshot)), failCreate: "job"}, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
		if _, err := r.createSnapshotJob(ctx, snapshot, instance, snapshotPatch(snapshot), "snapshot-job"); err == nil || snapshot.Status.Phase == "Failed" {
			t.Fatalf("job create must retry: %v", err)
		}
	})
}
