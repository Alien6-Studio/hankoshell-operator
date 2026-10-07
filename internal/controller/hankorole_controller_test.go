package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func newRoleFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&hankoshv1alpha1.HankoRole{}).
		Build()
}

func newRoleReconciler(t *testing.T, c client.Client, kc *keycloak.Client) *controller.HankoRoleReconciler {
	t.Helper()
	return &controller.HankoRoleReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc),
		Recorder: events.NewFakeRecorder(10),
	}
}

func getRole(t *testing.T, c client.Client, name string) *hankoshv1alpha1.HankoRole {
	t.Helper()
	var role hankoshv1alpha1.HankoRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &role); err != nil {
		t.Fatalf("get HankoRole %q: %v", name, err)
	}
	return &role
}

func roleCondition(role *hankoshv1alpha1.HankoRole, condType string) *metav1.Condition {
	for i := range role.Status.Conditions {
		if role.Status.Conditions[i].Type == condType {
			return &role.Status.Conditions[i]
		}
	}
	return nil
}

func TestHankoRoleReconcile_Create(t *testing.T) {
	kc := newMockKeycloak(t)

	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "editor-role", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRoleSpec{
			RealmRef:    "myrealm",
			Name:        "editor",
			Description: "can edit things",
			Attributes:  map[string][]string{"team": {"platform"}},
		},
	}

	c := newRoleFakeClient(t, role)
	r := newRoleReconciler(t, c, kc.client())

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "editor-role", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile (add finalizer): %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "editor-role", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile (sync): %v", err)
	}

	kcRole, ok := kc.getRealmRole("myrealm", "editor")
	if !ok {
		t.Fatalf("realm role %q was not created in Keycloak", "editor")
	}
	if kcRole.Description != "can edit things" {
		t.Errorf("Description: got %q, want %q", kcRole.Description, "can edit things")
	}
	if len(kcRole.Attributes["team"]) != 1 || kcRole.Attributes["team"][0] != "platform" {
		t.Errorf("Attributes[team]: got %v, want [platform]", kcRole.Attributes["team"])
	}

	got := getRole(t, c, "editor-role")
	if got.Status.Phase != "Ready" {
		t.Errorf("Phase: got %q, want Ready", got.Status.Phase)
	}
	if synced := roleCondition(got, "Synced"); synced == nil || synced.Status != metav1.ConditionTrue {
		t.Errorf("Synced condition: got %+v, want True", synced)
	}
}

func TestHankoRoleReconcile_UpdatesDrift(t *testing.T) {
	kc := newMockKeycloak(t)

	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "editor-role", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRoleSpec{
			RealmRef:    "myrealm",
			Name:        "editor",
			Description: "v1 description",
		},
	}
	c := newRoleFakeClient(t, role)
	r := newRoleReconciler(t, c, kc.client())
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "editor-role", Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (add finalizer): %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (create): %v", err)
	}

	updated := getRole(t, c, "editor-role")
	updated.Spec.Description = "v2 description"
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (update): %v", err)
	}

	kcRole, ok := kc.getRealmRole("myrealm", "editor")
	if !ok {
		t.Fatalf("realm role %q missing after update", "editor")
	}
	if kcRole.Description != "v2 description" {
		t.Errorf("Description after drift correction: got %q, want %q", kcRole.Description, "v2 description")
	}
}

func TestHankoRoleReconcile_Composites(t *testing.T) {
	kc := newMockKeycloak(t)

	child := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "child-role", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRoleSpec{RealmRef: "myrealm", Name: "child"},
	}
	parent := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "parent-role", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRoleSpec{
			RealmRef:   "myrealm",
			Name:       "parent",
			Composite:  true,
			Composites: []string{"child"},
		},
	}

	c := newRoleFakeClient(t, child, parent)
	r := newRoleReconciler(t, c, kc.client())

	childReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: "child-role", Namespace: "default"}}
	parentReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: "parent-role", Namespace: "default"}}

	for _, req := range []ctrl.Request{childReq, childReq} {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile child: %v", err)
		}
	}
	for _, req := range []ctrl.Request{parentReq, parentReq} {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile parent: %v", err)
		}
	}

	children := kc.realmRoleComposites("myrealm", "parent")
	if len(children) != 1 || children[0] != "child" {
		t.Errorf("composites for parent: got %v, want [child]", children)
	}
}

func TestHankoRoleReconcile_Delete(t *testing.T) {
	kc := newMockKeycloak(t)

	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "editor-role", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRoleSpec{RealmRef: "myrealm", Name: "editor"},
	}
	c := newRoleFakeClient(t, role)
	r := newRoleReconciler(t, c, kc.client())
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "editor-role", Namespace: "default"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (add finalizer): %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (create): %v", err)
	}
	if _, ok := kc.getRealmRole("myrealm", "editor"); !ok {
		t.Fatalf("precondition: role should exist in Keycloak before deletion")
	}

	current := getRole(t, c, "editor-role")
	if err := c.Delete(context.Background(), current); err != nil {
		t.Fatalf("delete HankoRole: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile (delete): %v", err)
	}

	if _, ok := kc.getRealmRole("myrealm", "editor"); ok {
		t.Errorf("realm role %q still present in Keycloak after deletion", "editor")
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "editor-role", Namespace: "default"}, &hankoshv1alpha1.HankoRole{}); err == nil {
		t.Error("HankoRole object still present after finalizer removal")
	}
}
