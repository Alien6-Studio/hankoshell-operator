package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func assertNoAuthorityKeycloakCalls(t *testing.T, kc *mockKeycloak) {
	t.Helper()
	for _, call := range []string{
		"lookup", "create", "update", "delete", "getSecret", "rotateSecret",
		"createRealm", "getRealm", "updateRealm", "deleteRealm",
		"createRealmRole", "getRealmRole", "getRealmRoleNotFound", "updateRealmRole", "deleteRealmRole", "addRealmRoleComposites",
		"createIDP", "updateIDP", "deleteIDP", "createIDPMapper", "updateIDPMapper", "deleteIDPMapper",
	} {
		if got := kc.count(call); got != 0 {
			t.Fatalf("reserved authority role caused %d %s Keycloak call(s)", got, call)
		}
	}
}

func assertNoAuthorityProviderMutations(t *testing.T, kc *mockKeycloak) {
	t.Helper()
	for _, call := range []string{
		"create", "update", "delete", "getSecret", "rotateSecret",
		"createRealm", "updateRealm", "deleteRealm",
		"createRealmRole", "updateRealmRole", "deleteRealmRole", "addRealmRoleComposites",
		"createIDP", "updateIDP", "deleteIDP", "createIDPMapper", "updateIDPMapper", "deleteIDPMapper",
		"createRole", "createProtocolMapper", "updateProtocolMapper", "deleteProtocolMapper",
		"createGroup", "deleteGroup",
		"createOrganization", "updateOrganization", "deleteOrganization",
	} {
		if got := kc.count(call); got != 0 {
			t.Fatalf("authority preflight allowed %d %s provider mutation(s)", got, call)
		}
	}
}

func seedTransitiveRealmAuthorityWrapper(kc *mockKeycloak, realm, root string) {
	kc.addRealmRole(realm, keycloak.RealmRole{Name: root, Composite: true})
	kc.addRealmRoleComposite(realm, root, keycloak.RealmRole{Name: "nested-wrapper", Composite: true})
	kc.addRealmRoleComposite(realm, "nested-wrapper", keycloak.RealmRole{Name: "HANKO_PLATFORM"})
}

func seedTransitiveClientAuthorityWrapper(kc *mockKeycloak, realm, clientID, uuid, root string) {
	kc.addClient(realm, clientID, uuid)
	kc.addClientRole(realm, uuid, keycloak.RealmRole{Name: root, Composite: true})
	kc.addClientRoleComposite(realm, uuid, root, keycloak.RealmRole{
		Name: "nested-client-wrapper", Composite: true, ClientRole: true, ContainerID: uuid,
	})
	kc.addClientRoleComposite(realm, uuid, "nested-client-wrapper", keycloak.RealmRole{Name: "HANKO_FLEET_ADMIN"})
}

func TestApplicationAuthorityRoleMappingFailsBeforeKeycloak(t *testing.T) {
	kc := newMockKeycloak(t)
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "unsafe-mapper", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "workload", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "fleet", IdentityProvider: "entra", Claim: "groups", MatchValue: "fleet-admins",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "HANKO_FLEET_ADMIN"},
			}},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	r.ProtectedRealm = "alien6"

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityKeycloakCalls(t, kc)
	got := getApp(t, c, app.Name)
	if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
		t.Fatalf("unsafe application = %+v, want Conflict without finalizer", got)
	}
	if conflict := condition(got, "Conflict"); conflict == nil || conflict.Reason != "ReservedAuthorityRole" {
		t.Fatalf("Conflict condition = %+v, want ReservedAuthorityRole", conflict)
	}
}

func TestOrganizationAuthorityRoleAssignmentFailsBeforeProviders(t *testing.T) {
	kc := newMockKeycloak(t)
	org := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet-admins", Namespace: "default", Generation: 3},
		Spec: hankoshv1alpha1.HankoOrganizationSpec{
			RealmRef: "alien6", Name: "Fleet administrators", Roles: []string{"HANKO_FLEET_ADMIN"},
		},
	}
	c := newFakeClient(t, org)
	r := &controller.HankoOrganizationReconciler{
		Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityKeycloakCalls(t, kc)
	var got hankoshv1alpha1.HankoOrganization
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(org), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Error" || got.Status.ObservedGeneration != 3 || len(got.Finalizers) != 0 {
		t.Fatalf("unsafe organization = %+v, want current-generation Error without finalizer", got)
	}
}

func TestStandaloneAuthorityRoleFailsBeforeKeycloak(t *testing.T) {
	tests := []hankoshv1alpha1.HankoRoleSpec{
		{RealmRef: "alien6", Name: "HANKO_CLUSTER_ADMIN"},
		{RealmRef: "alien6", Name: "innocent", Composite: true, Composites: []string{"HANKO_PLATFORM"}},
		{RealmRef: "tenant-a", Name: "HANKO_FLEET_CUSTOM"},
	}
	for i, spec := range tests {
		kc := newMockKeycloak(t)
		role := &hankoshv1alpha1.HankoRole{
			ObjectMeta: metav1.ObjectMeta{Name: "unsafe-role-" + string(rune('a'+i)), Namespace: "default"},
			Spec:       spec,
		}
		c := newRoleFakeClient(t, role)
		r := newRoleReconciler(t, c, kc.client())
		r.ProtectedRealm = "alien6"

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(role)}); err != nil {
			t.Fatalf("case %d Reconcile: %v", i, err)
		}
		assertNoAuthorityKeycloakCalls(t, kc)
		got := getRole(t, c, role.Name)
		if got.Status.Phase != "Error" || len(got.Finalizers) != 0 {
			t.Fatalf("case %d unsafe role = %+v, want Error without finalizer", i, got)
		}
	}
}

func TestRealmAuthorityRolePathsFailBeforeKeycloak(t *testing.T) {
	tests := []struct {
		name  string
		realm *hankoshv1alpha1.HankoRealm
	}{
		{
			name: "homonymous fleet role in tenant",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Namespace: "default", Generation: 2},
				Spec:       hankoshv1alpha1.HankoRealmSpec{Roles: []hankoshv1alpha1.RealmRole{{Name: "HANKO_FLEET_ADMIN"}}},
			},
		},
		{
			name: "authority wrapper composite",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 2},
				Spec: hankoshv1alpha1.HankoRealmSpec{Roles: []hankoshv1alpha1.RealmRole{{
					Name: "wrapper", Composites: []string{"HANKO_CLUSTER_OPERATOR"},
				}}},
			},
		},
		{
			name: "provider-native mapper",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 2},
				Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
					Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
						Name: "platform", IdentityProviderMapper: "oidc-hardcoded-role-idp-mapper",
						Config: map[string]string{"role": "HANKO_PLATFORM"},
					}},
				}}},
			},
		},
		{
			name: "reserved marker in provider mapper config key",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 2},
				Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
					Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
						Name: "custom", IdentityProviderMapper: "custom-entitlement-mapper",
						Config: map[string]string{"custom.HANKO_FLEET_binding": "ordinary-role"},
					}},
				}}},
			},
		},
		{
			name: "group mapper implementation",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 2},
				Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
					Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
						Name: "groups", IdentityProviderMapper: "oidc-advanced-group-idp-mapper",
						Config: map[string]string{"claim": "groups"},
					}},
				}}},
			},
		},
		{
			name: "neutral mapper with normalized group config",
			realm: &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 2},
				Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
					Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
						Name: "custom", IdentityProviderMapper: "custom-entitlement-mapper",
						Config: map[string]string{"Group.Path": "/fleet-admins"},
					}},
				}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			c := newFakeClient(t, tt.realm)
			r := &controller.HankoRealmReconciler{
				Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
			}

			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tt.realm)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			assertNoAuthorityKeycloakCalls(t, kc)
			var got hankoshv1alpha1.HankoRealm
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(tt.realm), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Phase != "Error" || got.Status.ObservedGeneration != 2 || len(got.Finalizers) != 0 {
				t.Fatalf("unsafe realm = %+v, want current-generation Error without finalizer", got)
			}
		})
	}
}

func TestDeletingStandaloneAuthorityRoleDropsFinalizerWithoutKeycloakDelete(t *testing.T) {
	kc := newMockKeycloak(t)
	deletingAt := metav1.Now()
	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unsafe-role", Namespace: "default", DeletionTimestamp: &deletingAt,
			Finalizers: []string{"hanko.sh/role-cleanup"}, UID: types.UID("unsafe-role"),
		},
		Spec: hankoshv1alpha1.HankoRoleSpec{RealmRef: "alien6", Name: "HANKO_FLEET_ADMIN"},
	}
	c := newRoleFakeClient(t, role)
	r := newRoleReconciler(t, c, kc.client())
	r.ProtectedRealm = "alien6"

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(role)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityKeycloakCalls(t, kc)
}

func TestTransitiveRealmRoleWrappersFailBeforeProviderMutation(t *testing.T) {
	t.Run("organization group", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveRealmAuthorityWrapper(kc, "alien6", "innocent-wrapper")
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default", Generation: 4},
			Spec: hankoshv1alpha1.HankoOrganizationSpec{
				RealmRef: "alien6", Name: "Operators", Roles: []string{"innocent-wrapper"},
			},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		var got hankoshv1alpha1.HankoOrganization
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(org), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.Phase != "Error" || len(got.Finalizers) != 0 {
			t.Fatalf("organization = %+v, want Error without finalizer", got)
		}
	})

	t.Run("application identity mapper", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveRealmAuthorityWrapper(kc, "alien6", "innocent-wrapper")
		app := &hankoshv1alpha1.HankoApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "unsafe-wrapper", Namespace: "default"},
			Spec: hankoshv1alpha1.HankoApplicationSpec{
				RealmRef: "alien6", ClientID: "workload", Type: "spa", Mode: controller.ExportModeManage,
				IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
					Name: "operators", IdentityProvider: "entra", Claim: "groups", MatchValue: "operators",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "innocent-wrapper"},
				}},
			},
		}
		c := newFakeClient(t, app)
		r := newReconciler(t, c, kc.client())
		r.ProtectedRealm = "alien6"

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		got := getApp(t, c, app.Name)
		if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
			t.Fatalf("application = %+v, want Conflict without finalizer", got)
		}
	})

	t.Run("standalone role sync", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveRealmAuthorityWrapper(kc, "alien6", "innocent-wrapper")
		role := &hankoshv1alpha1.HankoRole{
			ObjectMeta: metav1.ObjectMeta{Name: "wrapper", Namespace: "default"},
			Spec:       hankoshv1alpha1.HankoRoleSpec{RealmRef: "alien6", Name: "innocent-wrapper"},
		}
		c := newRoleFakeClient(t, role)
		r := newRoleReconciler(t, c, kc.client())
		r.ProtectedRealm = "alien6"

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(role)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		got := getRole(t, c, role.Name)
		if got.Status.Phase != "Error" || len(got.Finalizers) != 0 {
			t.Fatalf("role = %+v, want Error without finalizer", got)
		}
	})

	t.Run("realm identity-provider mapper", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveRealmAuthorityWrapper(kc, "alien6", "innocent-wrapper")
		realm := &hankoshv1alpha1.HankoRealm{
			ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 7},
			Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
				Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
					Name: "operators", IdentityProviderMapper: "custom-entitlement-mapper",
					Config: map[string]string{"role": "innocent-wrapper"},
				}},
			}}},
		}
		c := newFakeClient(t, realm)
		r := &controller.HankoRealmReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		var got hankoshv1alpha1.HankoRealm
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(realm), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.Phase != "Error" || len(got.Finalizers) != 0 {
			t.Fatalf("realm = %+v, want Error without finalizer", got)
		}
	})
}

func TestTransitiveClientRoleWrappersFailBeforeProviderMutation(t *testing.T) {
	t.Run("organization client role", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveClientAuthorityWrapper(kc, "alien6", "workload", "workload-uuid", "innocent-client-role")
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default", Generation: 2},
			Spec: hankoshv1alpha1.HankoOrganizationSpec{
				RealmRef: "alien6", Name: "Operators",
				ClientRoles: []hankoshv1alpha1.OrganizationClientRoles{{Client: "workload", Roles: []string{"innocent-client-role"}}},
			},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
	})

	t.Run("application adopted client role", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveClientAuthorityWrapper(kc, "alien6", "workload", "workload-uuid", "innocent-client-role")
		app := &hankoshv1alpha1.HankoApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"},
			Spec: hankoshv1alpha1.HankoApplicationSpec{
				RealmRef: "alien6", ClientID: "workload", Type: "spa", Mode: controller.ExportModeManage,
				Roles: []hankoshv1alpha1.ApplicationRole{{Name: "innocent-client-role"}},
				IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
					Name: "operators", IdentityProvider: "entra", Claim: "groups", MatchValue: "operators",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{ClientRole: "innocent-client-role"},
				}},
			},
		}
		c := newFakeClient(t, app)
		r := newReconciler(t, c, kc.client())
		r.ProtectedRealm = "alien6"

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		got := getApp(t, c, app.Name)
		if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
			t.Fatalf("application = %+v, want Conflict without finalizer", got)
		}
	})
}

func TestAuthorityRoleLookupFailureFailsClosedBeforeProviderMutation(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.roleLookupStatus = 500
	org := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default", Generation: 5},
		Spec: hankoshv1alpha1.HankoOrganizationSpec{
			RealmRef: "alien6", Name: "Operators", Roles: []string{"ordinary-role"},
		},
	}
	c := newFakeClient(t, org)
	r := &controller.HankoOrganizationReconciler{
		Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err == nil {
		t.Fatal("Reconcile succeeded despite authority-role lookup failure")
	}
	assertNoAuthorityProviderMutations(t, kc)
	var got hankoshv1alpha1.HankoOrganization
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(org), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Error" || len(got.Finalizers) != 0 {
		t.Fatalf("organization = %+v, want Error without finalizer", got)
	}
}

func TestReservedRealmProviderCompositePreventsReady(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addRealmRole("alien6", keycloak.RealmRole{Name: "HANKO_CLUSTER_ADMIN", Composite: true})
	kc.addRealmRoleComposite("alien6", "HANKO_CLUSTER_ADMIN", keycloak.RealmRole{Name: "ordinary-role"})
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default", Generation: 3},
		Spec:       hankoshv1alpha1.HankoRealmSpec{Roles: []hankoshv1alpha1.RealmRole{{Name: "HANKO_CLUSTER_ADMIN"}}},
	}
	c := newFakeClient(t, realm)
	r := &controller.HankoRealmReconciler{
		Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityProviderMutations(t, kc)
	var got hankoshv1alpha1.HankoRealm
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(realm), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Error" {
		t.Fatalf("realm phase = %q, want Error", got.Status.Phase)
	}
}

func TestProtectedAuthorityRealmDeletionNeverDeletesProviderRealm(t *testing.T) {
	kc := newMockKeycloak(t)
	deletingAt := metav1.Now()
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alien6", Namespace: "default", DeletionTimestamp: &deletingAt,
			Finalizers: []string{"hanko.sh/realm-cleanup"}, UID: types.UID("authority-realm"),
		},
	}
	c := newFakeClient(t, realm)
	r := &controller.HankoRealmReconciler{
		Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityProviderMutations(t, kc)
}

func TestProtectedControlPlaneApplicationRequiresCanonicalOwner(t *testing.T) {
	kc := newMockKeycloak(t)
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "dashboard-lookalike", Namespace: "default", Generation: 4},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "hanko-dashboard", Type: "web", Mode: controller.ExportModeManage,
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	r.ProtectedRealm = "alien6"
	r.ProtectedClientIDs = []string{"hanko-dashboard"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityProviderMutations(t, kc)
	got := getApp(t, c, app.Name)
	if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
		t.Fatalf("non-canonical protected app = %+v, want Conflict without finalizer", got)
	}
	if conflict := condition(got, "Conflict"); conflict == nil || conflict.Reason != "ProtectedClientOwner" {
		t.Fatalf("Conflict condition = %+v, want ProtectedClientOwner", conflict)
	}
}

func TestProtectedControlPlaneApplicationDeletionNeverDeletesProviderClient(t *testing.T) {
	kc := newMockKeycloak(t)
	deletingAt := metav1.Now()
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hanko-dashboard", Namespace: "default", Generation: 5,
			DeletionTimestamp: &deletingAt, Finalizers: []string{"hanko.sh/client-cleanup"}, UID: types.UID("dashboard-app"),
		},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "hanko-dashboard", Type: "web", Mode: controller.ExportModeManage,
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	r.ProtectedRealm = "alien6"
	r.ProtectedClientIDs = []string{"hanko-dashboard"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityProviderMutations(t, kc)
}

func TestOrganizationExistingGroupFailsClosedBeforeProviderMutation(t *testing.T) {
	t.Run("unowned group cannot be adopted", func(t *testing.T) {
		kc := newMockKeycloak(t)
		kc.addGroup("alien6", keycloak.Group{
			ID: "privileged-group", Name: "Administrators", Path: "/Administrators",
			Attributes: map[string][]string{"trunx_slug": {"administrators"}},
		}, "HANKO_PLATFORM")
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-org", Namespace: "default", UID: types.UID("attacker-org"), Generation: 3},
			Spec:       hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Name: "Administrators"},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		var got hankoshv1alpha1.HankoOrganization
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(org), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.Phase != "Error" {
			t.Fatalf("phase = %q, want Error", got.Status.Phase)
		}
	})

	t.Run("owned group with reserved effective role cannot be reused", func(t *testing.T) {
		kc := newMockKeycloak(t)
		kc.addRealmRole("alien6", keycloak.RealmRole{Name: "HANKO_FLEET_ADMIN"})
		kc.addGroup("alien6", keycloak.Group{
			ID: "owned-group", Name: "Operators", Path: "/Operators",
			Attributes: map[string][]string{
				"hanko.sh/organization-name":      {"operators"},
				"hanko.sh/organization-namespace": {"default"},
				"hanko.sh/organization-uid":       {"operators-uid"},
			},
		}, "HANKO_FLEET_ADMIN")
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default", UID: types.UID("operators-uid"), Generation: 4},
			Spec:       hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Name: "Operators"},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
	})

	t.Run("owned group with reserved role behind client composite cannot be reused", func(t *testing.T) {
		kc := newMockKeycloak(t)
		seedTransitiveClientAuthorityWrapper(kc, "alien6", "workload", "workload-uuid", "innocent-client-role")
		kc.addGroup("alien6", keycloak.Group{
			ID: "owned-client-role-group", Name: "Developers", Path: "/Developers",
			Attributes: map[string][]string{
				"hanko.sh/organization-name":      {"developers"},
				"hanko.sh/organization-namespace": {"default"},
				"hanko.sh/organization-uid":       {"developers-uid"},
			},
		})
		kc.addGroupClientRoles("alien6", "owned-client-role-group", "workload", "workload-uuid", "innocent-client-role")
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "developers", Namespace: "default", UID: types.UID("developers-uid"), Generation: 4},
			Spec:       hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Name: "Developers"},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
	})

	t.Run("group lookup error", func(t *testing.T) {
		kc := newMockKeycloak(t)
		kc.groupLookupStatus = 500
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default", UID: types.UID("operators-uid"), Generation: 2},
			Spec:       hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Name: "Operators"},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err == nil {
			t.Fatal("Reconcile succeeded despite group lookup failure")
		}
		assertNoAuthorityProviderMutations(t, kc)
	})
}

func TestDeletingUnownedOrganizationNeverDeletesProviderGroup(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addGroup("alien6", keycloak.Group{
		ID: "privileged-group", Name: "Administrators", Path: "/Administrators",
		Attributes: map[string][]string{
			"hanko.sh/organization-name":      {"different-owner"},
			"hanko.sh/organization-namespace": {"default"},
			"hanko.sh/organization-uid":       {"different-uid"},
		},
	}, "HANKO_PLATFORM")
	deletingAt := metav1.Now()
	org := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-org", Namespace: "default", UID: types.UID("attacker-org"),
			DeletionTimestamp: &deletingAt, Finalizers: []string{"hanko.sh/organization-cleanup"},
		},
		Spec: hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Name: "Administrators"},
		Status: hankoshv1alpha1.HankoOrganizationStatus{
			GroupID: "privileged-group", GroupPath: "/Administrators", ObservedGeneration: 1,
		},
	}
	c := newFakeClient(t, org)
	r := &controller.HankoOrganizationReconciler{
		Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertNoAuthorityProviderMutations(t, kc)
}

func TestRootOrganizationAliasCannotAdoptOrDeleteUnownedProviderOrganization(t *testing.T) {
	t.Run("alias collision fails before provider mutation", func(t *testing.T) {
		kc := newMockKeycloak(t)
		kc.addOrganization("alien6", keycloak.Organization{
			ID: "authority-admins", Alias: "authority-admins", Name: "Authority administrators", Enabled: true,
		})
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "attacker-org", Namespace: "default", UID: types.UID("attacker-uid"), Generation: 2},
			Spec: hankoshv1alpha1.HankoOrganizationSpec{
				RealmRef: "alien6", Name: "Attacker organization", Slug: "authority-admins",
			},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
		if got := kc.count("getGroupByPath"); got != 0 {
			t.Fatalf("organization collision reached group reconciliation: %d lookup(s)", got)
		}
	})

	t.Run("unowned organization is not deleted", func(t *testing.T) {
		kc := newMockKeycloak(t)
		kc.addOrganization("alien6", keycloak.Organization{
			ID: "authority-admins", Alias: "authority-admins", Name: "Authority administrators", Enabled: true,
			Attributes: map[string][]string{
				"hanko.sh/organization-name":      {"real-owner"},
				"hanko.sh/organization-namespace": {"default"},
				"hanko.sh/organization-uid":       {"real-owner-uid"},
			},
		})
		deletingAt := metav1.Now()
		org := &hankoshv1alpha1.HankoOrganization{
			ObjectMeta: metav1.ObjectMeta{
				Name: "attacker-org", Namespace: "default", UID: types.UID("attacker-uid"),
				DeletionTimestamp: &deletingAt, Finalizers: []string{"hanko.sh/organization-cleanup"},
			},
			Spec: hankoshv1alpha1.HankoOrganizationSpec{
				RealmRef: "alien6", Name: "Attacker organization", Slug: "authority-admins",
			},
			Status: hankoshv1alpha1.HankoOrganizationStatus{OrgID: "authority-admins", ObservedGeneration: 1},
		}
		c := newFakeClient(t, org)
		r := &controller.HankoOrganizationReconciler{
			Client: c, ProtectedRealm: "alien6", Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
		}

		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNoAuthorityProviderMutations(t, kc)
	})
}
