package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func lifecycleGuardFixture(t *testing.T) (*lifecycleApprovalGuard, *api.HankoOperation, *api.HankoKeycloakInstance) {
	t.Helper()
	op, instance := operationRecoveryFixture()
	op.Spec.Type, op.Spec.DBSwitch = api.OperationUpgrade, nil
	op.Spec.Upgrade = &api.UpgradeSpec{ToImage: "registry.example/keycloak@sha256:" + strings.Repeat("b", 64)}
	kube := controllerTestClient(controllerTestScheme(t), op, instance)
	r := &HankoOperationReconciler{Client: kube, APIReader: kube, Scheme: kube.Scheme()}
	return &lifecycleApprovalGuard{Client: kube, reader: kube, inner: r}, op, instance
}

func TestLifecycleGuardRequiresExactApprovalBeforeAnyEffect(t *testing.T) {
	ctx := context.Background()
	g, op, instance := lifecycleGuardFixture(t)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}
	if _, err := g.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := g.Get(ctx, request.NamespacedName, op); err != nil {
		t.Fatal(err)
	}
	if len(op.Status.Steps) != 0 || op.Status.IntentHash != "" || len(op.Status.Conditions) != 1 || op.Status.Conditions[0].Reason != "ApprovalRequired" {
		t.Fatalf("unapproved request executed: %#v", op.Status)
	}
	op.Annotations = map[string]string{lifecycleApprovalAnnotation: lifecycleApprovalValue(op, operationIntentHash(op), string(instance.UID))}
	if err := g.Update(ctx, op); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := g.Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
		t.Fatal(err)
	}
	if instance.Spec.Managed.Image != op.Spec.Upgrade.ToImage {
		t.Fatal("approved exact image was not applied")
	}
}

func TestLifecycleApprovalCannotSurviveChangedIntentOrRecreation(t *testing.T) {
	for _, change := range []string{"uid", "generation", "intent", "instance", "tenant", "revocation"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			g, op, instance := lifecycleGuardFixture(t)
			op.Annotations = map[string]string{lifecycleApprovalAnnotation: lifecycleApprovalValue(op, operationIntentHash(op), string(instance.UID))}
			switch change {
			case "uid":
				op.Annotations[lifecycleApprovalAnnotation] = strings.ReplaceAll(op.Annotations[lifecycleApprovalAnnotation], string(op.UID), "old-uid")
			case "generation":
				op.Generation++
			case "intent":
				op.Spec.Upgrade.ToImage = "changed"
			case "instance":
				op.Annotations[lifecycleApprovalAnnotation] = strings.ReplaceAll(op.Annotations[lifecycleApprovalAnnotation], string(instance.UID), "old-instance")
			case "tenant":
				op.Labels = map[string]string{"hanko.sh/tenant": "foreign"}
			case "revocation":
				delete(op.Annotations, lifecycleApprovalAnnotation)
			}
			if err := g.Update(ctx, op); err != nil {
				t.Fatal(err)
			}
			_, _, allowed, err := g.authority(ctx, client.ObjectKeyFromObject(op))
			if allowed || (err != nil && !errors.Is(err, errLifecycleApproval)) {
				t.Fatalf("changed authority accepted: %t %v", allowed, err)
			}
		})
	}
}

func TestLifecycleRevocationIsRecheckedAtTheInstanceMutation(t *testing.T) {
	ctx := context.Background()
	g, op, instance := lifecycleGuardFixture(t)
	op.Annotations = map[string]string{lifecycleApprovalAnnotation: lifecycleApprovalValue(op, operationIntentHash(op), string(instance.UID))}
	if err := g.Update(ctx, op); err != nil {
		t.Fatal(err)
	}
	g.inner = reconcile.Func(func(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
		if err := g.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
			return ctrl.Result{}, err
		}
		delete(op.Annotations, lifecycleApprovalAnnotation)
		if err := g.Update(ctx, op); err != nil {
			return ctrl.Result{}, err
		}
		r := &HankoOperationReconciler{Client: g.Client}
		_, _, err := r.advanceImageStep(ctx, op, instance, &api.OperationStep{Name: "UpdateImage", Status: "Pending"}, &metav1.Time{})
		return ctrl.Result{}, err
	})
	if _, err := g.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}); !errors.Is(err, errLifecycleApproval) {
		t.Fatalf("revoked approval reached mutation: %v", err)
	}
	var actual api.HankoKeycloakInstance
	if err := g.Get(ctx, client.ObjectKeyFromObject(instance), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Spec.Managed.Image == op.Spec.Upgrade.ToImage {
		t.Fatal("revoked operation changed the image")
	}
}

func TestLifecycleDatabaseReferenceValidationIsBounded(t *testing.T) {
	for _, change := range []string{"valid", "missing", "extra env", "password", "engine", "url", "admin", "tenant"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			g, op, instance := lifecycleGuardFixture(t)
			op.Spec.Type, op.Spec.Upgrade = api.OperationDBSwitch, nil
			op.Spec.DBSwitch = &api.DBSwitchSpec{NewDatabaseSecretRef: "next-db"}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "next-db", Namespace: op.Namespace}, Data: map[string][]byte{
				"KC_DB": []byte("postgres"), "KC_DB_URL": []byte("jdbc:postgresql://database/keycloak"), "KC_DB_USERNAME": []byte("operator"), "KC_DB_PASSWORD": []byte("private-database-sentinel"),
			}}
			switch change {
			case "extra env":
				secret.Data["KC_SPI_UNREVIEWED"] = []byte("unsafe")
			case "password":
				delete(secret.Data, "KC_DB_PASSWORD")
			case "engine":
				secret.Data["KC_DB"] = []byte("dev-file")
			case "url":
				secret.Data["KC_DB_URL"] = []byte("private-database-sentinel")
			case "admin":
				instance.Spec.AdminRef.Name = secret.Name
			case "tenant":
				secret.Labels = map[string]string{"hanko.sh/tenant": "foreign"}
			}
			if change != "missing" {
				if err := g.Create(ctx, secret); err != nil {
					t.Fatal(err)
				}
			}
			err := g.databaseReference(ctx, op, instance)
			if (err == nil) != (change == "valid") || (err != nil && strings.Contains(err.Error(), "private-database-sentinel")) {
				t.Fatalf("database authority: %v", err)
			}
		})
	}
}

func TestLifecycleSnapshotDelegationRequiresTheExactCurrentParentStep(t *testing.T) {
	for _, change := range []string{"valid", "revoked", "parent uid", "parent intent", "child intent", "child spec", "child generation", "step completed"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			g, op, instance := lifecycleGuardFixture(t)
			op.Spec.SnapshotBefore = nil
			op.Status = api.HankoOperationStatus{Phase: "Pending", InstanceUID: string(instance.UID), StartedGeneration: op.Generation, IntentHash: operationIntentHash(op), Steps: initSteps(op.Spec.Type)}
			op.Annotations = map[string]string{lifecycleApprovalAnnotation: lifecycleApprovalValue(op, operationIntentHash(op), string(instance.UID))}
			controller := true
			snapshot := &api.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "op-" + op.Name + "-snap", Namespace: op.Namespace, UID: "snapshot-uid", Generation: 1,
				Annotations: map[string]string{operationIntentAnnotation: op.Status.IntentHash}, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoOperation", Name: op.Name, UID: op.UID, Controller: &controller}}}, Spec: api.HankoSnapshotSpec{InstanceRef: instance.Name}}
			switch change {
			case "revoked":
				delete(op.Annotations, lifecycleApprovalAnnotation)
			case "parent uid":
				snapshot.OwnerReferences[0].UID = "old-parent"
			case "parent intent":
				op.Spec.Upgrade.ToImage = "changed"
			case "child intent":
				snapshot.Annotations[operationIntentAnnotation] = "changed"
			case "child spec":
				snapshot.Spec.IncludeData = true
			case "child generation":
				snapshot.Generation++
			case "step completed":
				op.Status.Steps[0].Status = "Done"
			}
			// Fake storage preserves explicit checkpoints; real generation/admission
			// authority is independently exercised by the API/installed gates.
			kube := controllerTestClient(controllerTestScheme(t), op, instance, snapshot)
			g.reader, g.Client, g.snapshot = kube, kube, true
			_, _, allowed, err := g.authority(ctx, client.ObjectKeyFromObject(snapshot))
			if err != nil || allowed != (change == "valid") {
				t.Fatalf("snapshot parent delegation: %t %v", allowed, err)
			}
		})
	}
}
