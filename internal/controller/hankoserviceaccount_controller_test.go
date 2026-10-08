package controller_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

type failingOwnershipReader struct{}

func (failingOwnershipReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("ownership API unavailable")
}

func (failingOwnershipReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("ownership API unavailable")
}

func TestServiceAccountReconcileLeavesOmittedAttributesUnmanaged(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("master", "keycloak-ops", "client-uuid")
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "master--keycloak-ops", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: "master",
			ClientID: "keycloak-ops",
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-keycloak-ops", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, sa, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc.client()),
		Recorder: events.NewFakeRecorder(10),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("update"); got != 0 {
		t.Fatalf("existing service account with omitted attributes triggered %d client update(s)", got)
	}

	var reconciled hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatalf("get reconciled service account: %v", err)
	}
	if reconciled.Status.Phase != "Ready" {
		t.Fatalf("phase = %q, want Ready", reconciled.Status.Phase)
	}
}

func TestServiceAccountReconcilesTokenClaimsWithPerMapperStatus(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("acme", "worker", "client-uuid")
	fixed := "worker-api"
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "default", Generation: 3},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: "acme", ClientID: "worker",
			TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{{Name: "audience", Claim: "aud", Value: &fixed}},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-worker", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, sa, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("createProtocolMapper"); got != 1 {
		t.Fatalf("protocol mapper creates = %d, want 1", got)
	}
	var reconciled hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatal(err)
	}
	if len(reconciled.Status.ManagedTokenClaims) != 1 {
		t.Fatalf("managed token claims = %+v", reconciled.Status.ManagedTokenClaims)
	}
	synced := mapperCondition(reconciled.Status.ManagedTokenClaims[0].Conditions, "Synced")
	if synced == nil || synced.Status != metav1.ConditionTrue || synced.ObservedGeneration != 3 {
		t.Fatalf("mapper condition = %+v", synced)
	}
	reconciled.Spec.TokenClaims = nil
	if err := c.Update(context.Background(), &reconciled); err != nil {
		t.Fatalf("remove token claim: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("cleanup Reconcile: %v", err)
	}
	if got := kc.count("deleteProtocolMapper"); got != 1 {
		t.Fatalf("protocol mapper deletes = %d, want 1", got)
	}
}

func TestServiceAccountRejectsReservedTokenClaim(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("acme", "worker", "client-uuid")
	fixed := "spoofed"
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-reserved", Namespace: "default", Generation: 4},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: "acme", ClientID: "worker",
			TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{{Name: "permissions", Claim: "permissions", Value: &fixed}},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-worker", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, sa, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}}
	_, err := r.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "reserved claim") {
		t.Fatalf("Reconcile error = %v, want reserved claim rejection", err)
	}
	for _, mutation := range []string{"create", "update", "createProtocolMapper", "updateProtocolMapper", "deleteProtocolMapper"} {
		if got := kc.count(mutation); got != 0 {
			t.Fatalf("reserved claim caused %d %s provider mutation(s)", got, mutation)
		}
	}
	var got hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), request.NamespacedName, &got); err != nil {
		t.Fatalf("get reconciled service account: %v", err)
	}
	if got.Status.Phase != "Error" || len(got.Status.ManagedTokenClaims) != 1 {
		t.Fatalf("reserved mapper status = %+v", got.Status)
	}
	synced := mapperCondition(got.Status.ManagedTokenClaims[0].Conditions, "Synced")
	if synced == nil || synced.Status != metav1.ConditionFalse || synced.Reason != "Invalid" || synced.ObservedGeneration != 4 {
		t.Fatalf("reserved mapper condition = %+v", synced)
	}
}

func TestServiceAccountRejectsProtectedAndCrossKindClientOwnership(t *testing.T) {
	tests := []struct {
		name               string
		clientID           string
		protectedClientIDs []string
		application        *hankoshv1alpha1.HankoApplication
	}{
		{name: "canonical control-plane client", clientID: "hanko-dashboard", protectedClientIDs: []string{"hanko-dashboard"}},
		{name: "normalized canonical control-plane client", clientID: " hanko-dashboard ", protectedClientIDs: []string{"hanko-dashboard"}},
		{name: "Keycloak built-in client", clientID: "realm-management"},
		{name: "operator credential client", clientID: "test-client"},
		{name: "configured control-plane client", clientID: "support-dashboard", protectedClientIDs: []string{" support-dashboard "}},
		{
			name:     "HankoApplication owner",
			clientID: "shared-client",
			application: &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-application", Namespace: "default"},
				Spec: hankoshv1alpha1.HankoApplicationSpec{
					RealmRef: "alien6", ClientID: "shared-client", Type: "web", Mode: controller.ExportModeManage,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			kc.addClient("alien6", tt.clientID, "client-uuid")
			sa := &hankoshv1alpha1.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "unsafe-service-account", Namespace: "default", Generation: 5},
				Spec: hankoshv1alpha1.HankoServiceAccountSpec{
					RealmRef: "alien6", ClientID: tt.clientID,
					SecretRotationPolicy: &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 1},
				},
			}
			objects := []client.Object{sa}
			if tt.application != nil {
				objects = append(objects, tt.application)
			}
			c := newFakeClient(t, objects...)
			r := &controller.HankoServiceAccountReconciler{
				Client: c, OwnershipReader: c, ProtectedClientIDs: tt.protectedClientIDs,
				ProtectedRealm: "alien6",
				Scheme:         newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
			}

			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sa)})
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if result.RequeueAfter <= 0 {
				t.Fatalf("result = %+v, want a bounded conflict requeue", result)
			}
			for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret"} {
				if got := kc.count(providerCall); got != 0 {
					t.Fatalf("ownership conflict caused %d %s provider call(s)", got, providerCall)
				}
			}
			var got hankoshv1alpha1.HankoServiceAccount
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(sa), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Phase != "Error" || got.Status.ObservedGeneration != 5 {
				t.Fatalf("status = %+v, want current-generation Error", got.Status)
			}
			if synced := mapperCondition(got.Status.Conditions, "Synced"); synced == nil || synced.Status != metav1.ConditionFalse || synced.Reason != "OwnershipConflict" {
				t.Fatalf("Synced condition = %+v, want OwnershipConflict", synced)
			}
			if len(got.Finalizers) != 0 {
				t.Fatalf("conflicting service account gained finalizer: %v", got.Finalizers)
			}
		})
	}
}

func TestConflictingServiceAccountDeletionNeverDeletesSharedClient(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		application *hankoshv1alpha1.HankoApplication
	}{
		{name: "control-plane client", clientID: "hanko-dashboard"},
		{
			name:     "HankoApplication owner",
			clientID: "shared-client",
			application: &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-application", Namespace: "default"},
				Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "alien6", ClientID: "shared-client", Type: "web"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			kc.addClient("alien6", tt.clientID, "client-uuid")
			now := metav1.Now()
			sa := &hankoshv1alpha1.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unsafe-service-account", Namespace: "default", Finalizers: []string{controller.SAFinalizerName}, DeletionTimestamp: &now,
				},
				Spec: hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "alien6", ClientID: tt.clientID},
			}
			objects := []client.Object{sa}
			if tt.application != nil {
				objects = append(objects, tt.application)
			}
			c := newFakeClient(t, objects...)
			r := &controller.HankoServiceAccountReconciler{
				Client: c, OwnershipReader: c, ProtectedClientIDs: []string{"hanko-dashboard"}, ProtectedRealm: "alien6",
				Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
			}

			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sa)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			for _, providerCall := range []string{"lookup", "delete", "getSecret", "rotateSecret"} {
				if got := kc.count(providerCall); got != 0 {
					t.Fatalf("conflicting deletion caused %d %s provider call(s)", got, providerCall)
				}
			}
		})
	}
}

func TestServiceAccountOwnershipLookupFailsClosed(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "workload", "client-uuid")
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "alien6", ClientID: "workload"},
	}
	c := newFakeClient(t, sa)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, OwnershipReader: failingOwnershipReader{}, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sa)})
	if err == nil || !strings.Contains(err.Error(), "ownership API unavailable") {
		t.Fatalf("Reconcile error = %v, want ownership lookup failure", err)
	}
	for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret"} {
		if got := kc.count(providerCall); got != 0 {
			t.Fatalf("ownership lookup failure caused %d %s provider call(s)", got, providerCall)
		}
	}
	var got hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(sa), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("ownership lookup failure added finalizer: %v", got.Finalizers)
	}
}

func TestServiceAccountControlPlaneProtectionIsScopedToAuthorityRealm(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("tenant-a", "hanko-dashboard", "client-uuid")
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-dashboard", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "tenant-a", ClientID: "hanko-dashboard"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-hanko-dashboard", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, sa, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, OwnershipReader: c, ProtectedClientIDs: []string{"hanko-dashboard"}, ProtectedRealm: "alien6",
		Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sa)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(sa), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Ready" {
		t.Fatalf("tenant homonym phase = %q, want Ready", got.Status.Phase)
	}
}

func TestServiceAccountSameKindOwnershipIsDeterministic(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("acme", "worker", "client-uuid")
	base := time.Now().Add(-time.Hour)
	owner := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: "default", UID: types.UID("owner-uid"), CreationTimestamp: metav1.NewTime(base)},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "worker"},
	}
	duplicate := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "duplicate", Namespace: "default", UID: types.UID("duplicate-uid"), CreationTimestamp: metav1.NewTime(base.Add(time.Minute))},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: " worker "},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-worker", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, owner, duplicate, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, OwnershipReader: c, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(duplicate)}); err != nil {
		t.Fatalf("duplicate Reconcile: %v", err)
	}
	if got := kc.count("lookup"); got != 0 {
		t.Fatalf("losing duplicate made %d provider lookup(s), want 0", got)
	}
	var losing hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(duplicate), &losing); err != nil {
		t.Fatal(err)
	}
	if losing.Status.Phase != "Error" || len(losing.Finalizers) != 0 {
		t.Fatalf("losing duplicate = %+v, want Error without finalizer", losing)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(owner)}); err != nil {
		t.Fatalf("owner Reconcile: %v", err)
	}
	var winning hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(owner), &winning); err != nil {
		t.Fatal(err)
	}
	if winning.Status.Phase != "Ready" {
		t.Fatalf("deterministic owner phase = %q, want Ready", winning.Status.Phase)
	}
}

func TestLosingServiceAccountDeletionDropsFinalizerWithoutProviderDelete(t *testing.T) {
	kc := newMockKeycloak(t)
	base := time.Now().Add(-time.Hour)
	owner := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: "default", CreationTimestamp: metav1.NewTime(base)},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "worker"},
	}
	deletingAt := metav1.Now()
	duplicate := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "duplicate", Namespace: "default", CreationTimestamp: metav1.NewTime(base.Add(time.Minute)),
			DeletionTimestamp: &deletingAt, Finalizers: []string{controller.SAFinalizerName},
		},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "worker"},
	}
	c := newFakeClient(t, owner, duplicate)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, OwnershipReader: c, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(duplicate)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("delete"); got != 0 {
		t.Fatalf("losing deletion made %d provider delete(s), want 0", got)
	}
}

func TestObserveApplicationDoesNotBlockManagedServiceAccount(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("acme", "worker", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "acme", ClientID: "worker", Type: "web", Mode: controller.ExportModeObserve,
		},
	}
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "worker"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-worker", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("existing")},
	}
	c := newFakeClient(t, app, sa, secret)
	r := &controller.HankoServiceAccountReconciler{
		Client: c, OwnershipReader: c, Scheme: newScheme(t), Pool: keycloak.NewPool(kc.client()), Recorder: events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sa)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(sa), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Ready" {
		t.Fatalf("service-account phase = %q, want Ready", got.Status.Phase)
	}
}

func TestImportedServiceAccountIsReadOnly(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("gifen", "gifen-app", "client-uuid")
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gifen--gifen-app",
			Namespace: "default",
			Labels:    map[string]string{controller.ImportedByLabel: "import-all"},
		},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: "gifen",
			ClientID: "gifen-app",
		},
		Status: hankoshv1alpha1.HankoServiceAccountStatus{
			SecretRef: &hankoshv1alpha1.SecretReference{
				SecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "legacy-secret"},
					Key:                  "client_secret",
				},
			},
		},
	}
	c := newFakeClient(t, sa)
	r := &controller.HankoServiceAccountReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc.client()),
		Recorder: events.NewFakeRecorder(10),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, counter := range []string{"create", "update", "delete", "getSecret", "rotateSecret"} {
		if got := kc.count(counter); got != 0 {
			t.Errorf("%s calls = %d, want 0", counter, got)
		}
	}

	var reconciled hankoshv1alpha1.HankoServiceAccount
	if err := c.Get(context.Background(), request.NamespacedName, &reconciled); err != nil {
		t.Fatalf("get reconciled service account: %v", err)
	}
	if reconciled.Status.Phase != "Ready" || reconciled.Status.SecretRef != nil {
		t.Fatalf("observed status = %+v", reconciled.Status)
	}
	if len(reconciled.Finalizers) != 0 {
		t.Fatalf("imported service account gained finalizers: %v", reconciled.Finalizers)
	}
	if synced := mapperCondition(reconciled.Status.Conditions, "Synced"); synced == nil || synced.Reason != "Observed" {
		t.Fatalf("conditions = %+v, want Synced/Observed", reconciled.Status.Conditions)
	}
}

func TestImportedServiceAccountDeletionDoesNotDeleteClient(t *testing.T) {
	kc := newMockKeycloak(t)
	now := metav1.Now()
	sa := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gifen--gifen-app",
			Namespace:         "default",
			Labels:            map[string]string{controller.ImportedByLabel: "import-all"},
			Finalizers:        []string{controller.SAFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "gifen", ClientID: "gifen-app"},
	}
	c := newFakeClient(t, sa)
	r := &controller.HankoServiceAccountReconciler{
		Client:   c,
		Scheme:   newScheme(t),
		Pool:     keycloak.NewPool(kc.client()),
		Recorder: events.NewFakeRecorder(10),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("delete"); got != 0 {
		t.Fatalf("DeleteApp calls = %d, want 0", got)
	}
}
