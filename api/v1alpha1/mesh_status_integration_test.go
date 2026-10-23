//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkMeshReceiverRevocation(t *testing.T, ctx context.Context, kube client.Client) {
	raw, err := json.Marshal(conditionAPISpecs()["HankoMeshService"])
	if err != nil {
		t.Fatal(err)
	}
	registration := &api.HankoMeshService{ObjectMeta: metav1.ObjectMeta{Name: "mesh-revocation", Namespace: "condition-fixtures"}}
	if err := json.Unmarshal(raw, &registration.Spec); err != nil {
		t.Fatal(err)
	}
	if err := kube.Create(ctx, registration); err != nil {
		t.Fatal(err)
	}
	registration.Status = api.HankoMeshServiceStatus{Phase: "Ready", ObservedGeneration: registration.Generation, ReceiverNodeUIDs: []string{"44444444-4444-4444-4444-444444444444"}}
	if err := kube.Status().Update(ctx, registration); err != nil {
		t.Fatal(err)
	}
	r := &controller.HankoMeshServiceReconciler{Client: kube, APIReader: kube}
	// The referenced tenant is absent. Reconciliation must revoke the old
	// receiver binding even though receiverNodeUIDs is a required array.
	_, _ = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(registration)})
	if err := kube.Get(ctx, client.ObjectKeyFromObject(registration), registration); err != nil {
		t.Fatal(err)
	}
	if registration.Status.Phase != "Error" || registration.Status.ReceiverNodeUIDs == nil || len(registration.Status.ReceiverNodeUIDs) != 0 || len(registration.Status.Conditions) != 1 || registration.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("failed binding retained receiver authority: %+v", registration.Status)
	}
}
