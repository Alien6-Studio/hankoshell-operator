package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestServiceAccountRoleCleanupPendingTracksRemovedGrants(t *testing.T) {
	app := &hankoshv1alpha1.HankoApplication{}
	app.Spec.Type = "m2m"
	app.Spec.ServiceAccountRealmRoles = []string{"ADMIN"}
	app.Status.ManagedServiceAccountRealmRoles = []string{"ADMIN"}
	if serviceAccountRoleCleanupPending(app) {
		t.Fatal("a current grant was treated as cleanup")
	}
	app.Spec.ServiceAccountRealmRoles = nil
	if !serviceAccountRoleCleanupPending(app) {
		t.Fatal("a removed grant was not revoked")
	}
	app.Spec.ServiceAccountRealmRoles, app.Spec.Type = []string{"ADMIN"}, "web"
	if !serviceAccountRoleCleanupPending(app) {
		t.Fatal("a grant left on a non-m2m client was not revoked")
	}
}

func TestServiceAccountRealmRolesWithoutGrantsMakeNoKeycloakCall(t *testing.T) {
	app := &hankoshv1alpha1.HankoApplication{}
	app.Spec.Type = "web"
	app.Spec.ServiceAccountRealmRoles = []string{"ADMIN"}
	meta.SetStatusCondition(&app.Status.Conditions, metav1.Condition{Type: "ServiceAccountRoles", Status: metav1.ConditionTrue, Reason: "Synced"})
	if err := (&HankoApplicationReconciler{}).reconcileServiceAccountRealmRoles(context.Background(), app, nil); err != nil {
		t.Fatal(err)
	}
	if meta.FindStatusCondition(app.Status.Conditions, "ServiceAccountRoles") != nil {
		t.Fatal("stale service-account condition survived without grants")
	}
}

func TestServiceAccountRealmRolesRejectReservedAuthority(t *testing.T) {
	app := &hankoshv1alpha1.HankoApplication{}
	app.Name, app.Spec.RealmRef = "robot", "tenant"
	app.Spec.ServiceAccountRealmRoles = []string{"HANKO_PLATFORM_ADMIN"}
	if err := validateApplicationAuthorityRoles(app, "platform"); !isReservedAuthorityRoleViolation(err) {
		t.Fatalf("reserved service-account role was accepted: %v", err)
	}
}
