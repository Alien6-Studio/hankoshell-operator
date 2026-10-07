package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestImportedRealmIsReadOnly(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addRealm(keycloak.Realm{ID: "realm-uuid", RealmName: "gifen", DisplayName: "GIFEN", Enabled: true})
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gifen",
			Namespace: "default",
			Labels:    map[string]string{controller.ImportedByLabel: "import-all"},
		},
		Spec: hankoshv1alpha1.HankoRealmSpec{DisplayName: "GIFEN"},
	}
	c := newFakeClient(t, realm)
	r := &controller.HankoRealmReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc.client()),
		Recorder: events.NewFakeRecorder(10),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: realm.Name, Namespace: realm.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, counter := range []string{"createRealm", "updateRealm", "deleteRealm"} {
		if got := kc.count(counter); got != 0 {
			t.Errorf("%s calls = %d, want 0", counter, got)
		}
	}

	var reconciled hankoshv1alpha1.HankoRealm
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatalf("get reconciled realm: %v", err)
	}
	if reconciled.Status.Phase != "Ready" || reconciled.Status.KeycloakRealmID != "realm-uuid" {
		t.Fatalf("observed status = %+v", reconciled.Status)
	}
	if len(reconciled.Finalizers) != 0 {
		t.Fatalf("imported realm gained finalizers: %v", reconciled.Finalizers)
	}
	foundObserved := false
	for _, condition := range reconciled.Status.Conditions {
		if condition.Type == "Synced" && condition.Reason == "Observed" {
			foundObserved = true
		}
	}
	if !foundObserved {
		t.Fatalf("conditions = %+v, want Synced/Observed", reconciled.Status.Conditions)
	}
}

func TestImportedRealmDeletionDoesNotDeleteKeycloakRealm(t *testing.T) {
	kc := newMockKeycloak(t)
	now := metav1.Now()
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gifen",
			Namespace:         "default",
			Labels:            map[string]string{controller.ImportedByLabel: "import-all"},
			Finalizers:        []string{controller.RealmFinalizerName},
			DeletionTimestamp: &now,
		},
	}
	c := newFakeClient(t, realm)
	r := &controller.HankoRealmReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc.client()),
		Recorder: events.NewFakeRecorder(10),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: realm.Name, Namespace: realm.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("deleteRealm"); got != 0 {
		t.Fatalf("DeleteRealm calls = %d, want 0", got)
	}
}
