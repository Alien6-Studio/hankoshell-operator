package controller_test

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add hanko scheme: %v", err)
	}
	return scheme
}

// realmClientIndexer registers the same field index the real manager registers
// in HankoApplicationReconciler.SetupWithManager, so fake-client List calls with
// client.MatchingFields{RealmClientIndexKey: ...} behave like production.
func realmClientIndexer(obj client.Object) []string {
	app := obj.(*hankoshv1alpha1.HankoApplication)
	return []string{controller.RealmClientKey(app.Spec.RealmRef, app.Spec.ClientID)}
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithIndex(&hankoshv1alpha1.HankoApplication{}, controller.RealmClientIndexKey, realmClientIndexer).
		WithObjects(objs...).
		WithStatusSubresource(&hankoshv1alpha1.HankoApplication{}, &hankoshv1alpha1.HankoImport{}, &hankoshv1alpha1.HankoOrganization{}, &hankoshv1alpha1.HankoRealm{}, &hankoshv1alpha1.HankoServiceAccount{}, &hankoshv1alpha1.HankoTheme{}).
		Build()
}

func newReconciler(t *testing.T, c client.Client, kc *keycloak.Client) *controller.HankoApplicationReconciler {
	t.Helper()
	return &controller.HankoApplicationReconciler{
		Client:          c,
		OwnershipReader: c,
		Scheme:          newScheme(t),
		Pool:            keycloak.NewPool(kc),
		Recorder:        events.NewFakeRecorder(10),
	}
}

func getApp(t *testing.T, c client.Client, name string) *hankoshv1alpha1.HankoApplication {
	t.Helper()
	var app hankoshv1alpha1.HankoApplication
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &app); err != nil {
		t.Fatalf("get HankoApplication %q: %v", name, err)
	}
	return &app
}

func condition(app *hankoshv1alpha1.HankoApplication, condType string) *metav1.Condition {
	for i := range app.Status.Conditions {
		if app.Status.Conditions[i].Type == condType {
			return &app.Status.Conditions[i]
		}
	}
	return nil
}

func mapperCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// (c) Observe reconcile must never call CreateApp/UpdateApp/DeleteApp or fetch the secret.
func TestReconcile_Observe_NoMutatingKeycloakCalls(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("myrealm", "myclient", "uuid-1")

	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "imported-app",
			Namespace:  "default",
			Generation: 6,
			Labels:     map[string]string{controller.ImportedByLabel: "import-1"},
		},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
		},
	}

	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "imported-app", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := kc.count("create"); got != 0 {
		t.Errorf("CreateApp calls: got %d, want 0", got)
	}
	if got := kc.count("update"); got != 0 {
		t.Errorf("UpdateApp calls: got %d, want 0", got)
	}
	if got := kc.count("delete"); got != 0 {
		t.Errorf("DeleteApp calls: got %d, want 0", got)
	}
	if got := kc.count("getSecret"); got != 0 {
		t.Errorf("GetClientSecret calls: got %d, want 0", got)
	}

	got := getApp(t, c, "imported-app")
	if got.Status.Phase != "Ready" {
		t.Errorf("Phase: got %q, want Ready", got.Status.Phase)
	}
	if got.Status.ObservedGeneration != app.Generation {
		t.Errorf("ObservedGeneration: got %d, want %d", got.Status.ObservedGeneration, app.Generation)
	}
	synced := condition(got, "Synced")
	if synced == nil || synced.Status != metav1.ConditionTrue || synced.Reason != "Observed" {
		t.Errorf("Synced condition: got %+v, want True/Observed", synced)
	}
	if controllerutilContainsFinalizer(got) {
		t.Error("Observe-mode object must never gain the destructive finalizer")
	}
}

func TestReconcile_ManageRotatesConfidentialSecretDeclaratively(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("myrealm", "myclient", "uuid-1")
	requestedAt := metav1.NewTime(time.Now().Add(-time.Minute))
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "myclient", Namespace: "default", UID: types.UID("app-uid"), Generation: 7},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm", ClientID: "myclient", Type: "web",
			ClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{
				{Namespace: "workload", Name: "hanko-app-myclient"},
			},
			SecretRotationPolicy: &hankoshv1alpha1.SecretRotationPolicy{
				Enabled: true, IntervalDays: 90, ForceRotateAt: &requestedAt,
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko-app-myclient", Namespace: "default"},
		Data:       map[string][]byte{"client_secret": []byte("old-secret")},
	}
	projected := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "hanko-app-myclient", Namespace: "workload",
		Labels: map[string]string{"hanko.sh/client-secret-projection": "true"},
		Annotations: map[string]string{
			"hanko.sh/application-name": "myclient", "hanko.sh/application-namespace": "default",
			"hanko.sh/client-id": "myclient",
		},
	}}
	c := newFakeClient(t, app, secret, projected)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("rotateSecret"); got != 1 {
		t.Fatalf("secret rotation calls = %d, want 1", got)
	}
	var updatedSecret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, &updatedSecret); err != nil {
		t.Fatal(err)
	}
	if updatedSecret.StringData["client_secret"] != "rotated-secret" {
		t.Fatalf("secret StringData = %#v", updatedSecret.StringData)
	}
	var updatedProjection corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: projected.Name, Namespace: projected.Namespace}, &updatedProjection); err != nil {
		t.Fatal(err)
	}
	if got := string(updatedProjection.Data["client_secret"]); got != "rotated-secret" {
		t.Fatalf("projected client secret = %q, want rotated-secret", got)
	}
	updatedApp := getApp(t, c, app.Name)
	if updatedApp.Status.ObservedGeneration != app.Generation {
		t.Fatalf("ObservedGeneration = %d, want %d", updatedApp.Status.ObservedGeneration, app.Generation)
	}
	if updatedApp.Status.LastRotated == nil || !updatedApp.Status.LastRotated.After(requestedAt.Time) {
		t.Fatalf("lastRotated = %#v", updatedApp.Status.LastRotated)
	}
}

func controllerutilContainsFinalizer(app *hankoshv1alpha1.HankoApplication) bool {
	return slices.Contains(app.Finalizers, controller.FinalizerName)
}

// (d) Deleting a legacy imported object (imported-by label, old destructive finalizer
// still present) must remove the finalizer WITHOUT calling DeleteApp.
func TestReconcile_ObserveDeletion_NoDeleteApp(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("myrealm", "myclient", "uuid-1")

	now := metav1.Now()
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "legacy-imported-app",
			Namespace:         "default",
			Labels:            map[string]string{controller.ImportedByLabel: "import-1"},
			Finalizers:        []string{controller.FinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
		},
	}

	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "legacy-imported-app", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := kc.count("delete"); got != 0 {
		t.Errorf("DeleteApp calls: got %d, want 0 — Observe deletion must never delete the shared Keycloak client", got)
	}

	var got hankoshv1alpha1.HankoApplication
	err = c.Get(context.Background(), types.NamespacedName{Name: "legacy-imported-app", Namespace: "default"}, &got)
	if err == nil {
		t.Fatalf("expected object to be gone after finalizer removal, got %+v", got)
	}
}

// (e) Two Manage objects targeting the same (realmRef, clientID) must conflict —
// no Keycloak mutation call happens, and an explicit Conflict condition is set.
func TestReconcile_ManageConflict_NoKeycloakCalls(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("myrealm", "myclient", "uuid-1")
	created := time.Now().Add(-time.Hour)

	first := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-z", Namespace: "default", CreationTimestamp: metav1.NewTime(created)},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
			Mode:     controller.ExportModeManage,
		},
	}
	second := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-a", Namespace: "default", CreationTimestamp: metav1.NewTime(created.Add(time.Minute))},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
			Mode:     controller.ExportModeManage,
		},
	}

	c := newFakeClient(t, first, second)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "app-a", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := kc.count("create"); got != 0 {
		t.Errorf("CreateApp calls: got %d, want 0", got)
	}
	if got := kc.count("update"); got != 0 {
		t.Errorf("UpdateApp calls: got %d, want 0", got)
	}
	if got := kc.count("delete"); got != 0 {
		t.Errorf("DeleteApp calls: got %d, want 0", got)
	}

	got := getApp(t, c, "app-a")
	if got.Status.Phase != "Conflict" {
		t.Errorf("Phase: got %q, want Conflict", got.Status.Phase)
	}
	conflict := condition(got, "Conflict")
	if conflict == nil || conflict.Status != metav1.ConditionTrue || conflict.Reason != "DuplicateManager" {
		t.Errorf("Conflict condition: got %+v, want True/DuplicateManager", conflict)
	}
}

func TestReconcile_ReservedApplicationClientsNeverReachKeycloak(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
	}{
		{name: "built-in client", clientID: " realm-management "},
		{name: "operator credential client", clientID: "test-client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			app := &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "unsafe-app", Namespace: "default"},
				Spec: hankoshv1alpha1.HankoApplicationSpec{
					RealmRef: "acme", ClientID: tt.clientID, Type: "spa", Mode: controller.ExportModeManage,
				},
			}
			c := newFakeClient(t, app)
			r := newReconciler(t, c, kc.client())

			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret"} {
				if got := kc.count(providerCall); got != 0 {
					t.Fatalf("reserved client caused %d %s provider call(s)", got, providerCall)
				}
			}
			got := getApp(t, c, app.Name)
			if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
				t.Fatalf("reserved application = %+v, want Conflict without finalizer", got)
			}
			conflict := condition(got, "Conflict")
			if conflict == nil || conflict.Reason != "ReservedClient" {
				t.Fatalf("Conflict condition = %+v, want ReservedClient", conflict)
			}
		})
	}
}

func TestReconcile_ControlPlaneClientHomonymOutsideAuthorityRealmIsManageable(t *testing.T) {
	kc := newMockKeycloak(t)
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-dashboard", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "tenant-a", ClientID: "hanko-dashboard", Type: "spa", Mode: controller.ExportModeManage,
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	r.ProtectedRealm = "alien6"
	r.ProtectedClientIDs = []string{"hanko-dashboard"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("create"); got != 1 {
		t.Fatalf("tenant homonym create calls = %d, want 1", got)
	}
	got := getApp(t, c, app.Name)
	if got.Status.Phase != "Ready" || !slices.Contains(got.Finalizers, controller.FinalizerName) {
		t.Fatalf("tenant homonym = %+v, want Ready with finalizer", got)
	}
}

func TestReconcile_ApplicationCrossKindOwnershipAndAuthorityBoundary(t *testing.T) {
	tests := []struct {
		name             string
		applicationName  string
		realm            string
		importedHSA      bool
		protectedRealm   string
		protectedIDs     []string
		applicationFirst bool
		wantConflict     bool
	}{
		{name: "older managed service account owns ordinary client", realm: "tenant-a", wantConflict: true},
		{name: "older application retains ordinary client", realm: "tenant-a", applicationFirst: true},
		{name: "canonical fleet authority application displaces forbidden service account", applicationName: "shared-client", realm: "alien6", protectedRealm: "alien6", protectedIDs: []string{"shared-client"}},
		{name: "authority client homonym in tenant remains ordinary", realm: "tenant-a", protectedRealm: "alien6", protectedIDs: []string{"shared-client"}, wantConflict: true},
		{name: "imported service account is inventory only", realm: "tenant-a", importedHSA: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			kc.addClient(tt.realm, "shared-client", "uuid-1")
			created := time.Now().Add(-time.Hour)
			accountCreated := created
			applicationCreated := created.Add(time.Minute)
			if tt.applicationFirst {
				accountCreated, applicationCreated = applicationCreated, created
			}
			labels := map[string]string(nil)
			if tt.importedHSA {
				labels = map[string]string{controller.ImportedByLabel: "inventory"}
			}
			account := &hankoshv1alpha1.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-account", Namespace: "default", Labels: labels, CreationTimestamp: metav1.NewTime(accountCreated)},
				Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: tt.realm, ClientID: "shared-client"},
			}
			applicationName := tt.applicationName
			if applicationName == "" {
				applicationName = "new-application"
			}
			app := &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: applicationName, Namespace: "default", CreationTimestamp: metav1.NewTime(applicationCreated)},
				Spec: hankoshv1alpha1.HankoApplicationSpec{
					RealmRef: tt.realm, ClientID: "shared-client", Type: "spa", Mode: controller.ExportModeManage,
				},
			}
			c := newFakeClient(t, account, app)
			r := newReconciler(t, c, kc.client())
			r.ProtectedRealm = tt.protectedRealm
			r.ProtectedClientIDs = tt.protectedIDs

			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			got := getApp(t, c, app.Name)
			if tt.wantConflict {
				if got.Status.Phase != "Conflict" || len(got.Finalizers) != 0 {
					t.Fatalf("application = %+v, want Conflict without finalizer", got)
				}
				if conflict := condition(got, "Conflict"); conflict == nil || conflict.Reason != "CrossKindOwnershipConflict" {
					t.Fatalf("Conflict condition = %+v, want CrossKindOwnershipConflict", conflict)
				}
				for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret"} {
					if calls := kc.count(providerCall); calls != 0 {
						t.Fatalf("cross-kind conflict caused %d %s call(s)", calls, providerCall)
					}
				}
				return
			}
			if got.Status.Phase != "Ready" || !slices.Contains(got.Finalizers, controller.FinalizerName) {
				t.Fatalf("authoritative application = %+v, want Ready with finalizer", got)
			}
		})
	}
}

func TestReconcile_ConflictingApplicationDeletionNeverDeletesSharedClient(t *testing.T) {
	tests := []struct {
		name       string
		other      client.Object
		appCreated time.Time
	}{
		{
			name: "same-kind loser",
			other: &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: "default", CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour))},
				Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "shared-client", Type: "spa", Mode: controller.ExportModeManage},
			},
			appCreated: time.Now().Add(-time.Hour),
		},
		{
			name: "cross-kind loser",
			other: &hankoshv1alpha1.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: "default", CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour))},
				Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "shared-client"},
			},
			appCreated: time.Now().Add(-time.Hour),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newMockKeycloak(t)
			kc.addClient("acme", "shared-client", "uuid-1")
			deletingAt := metav1.Now()
			app := &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{
					Name: "loser", Namespace: "default", CreationTimestamp: metav1.NewTime(tt.appCreated),
					DeletionTimestamp: &deletingAt, Finalizers: []string{controller.FinalizerName},
				},
				Spec: hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "shared-client", Type: "spa", Mode: controller.ExportModeManage},
			}
			c := newFakeClient(t, tt.other, app)
			r := newReconciler(t, c, kc.client())

			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret", "deleteProtocolMapper"} {
				if got := kc.count(providerCall); got != 0 {
					t.Fatalf("conflicting deletion caused %d %s provider call(s)", got, providerCall)
				}
			}
		})
	}
}

func TestReconcile_ApplicationOwnershipLookupFailsClosed(t *testing.T) {
	kc := newMockKeycloak(t)
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "client", Type: "spa", Mode: controller.ExportModeManage},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	r.OwnershipReader = failingOwnershipReader{}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err == nil || !strings.Contains(err.Error(), "ownership API unavailable") {
		t.Fatalf("Reconcile error = %v, want ownership lookup failure", err)
	}
	for _, providerCall := range []string{"lookup", "create", "update", "delete", "getSecret", "rotateSecret"} {
		if got := kc.count(providerCall); got != 0 {
			t.Fatalf("ownership lookup failure caused %d %s provider call(s)", got, providerCall)
		}
	}
	got := getApp(t, c, app.Name)
	if len(got.Finalizers) != 0 {
		t.Fatalf("ownership lookup failure added finalizer: %v", got.Finalizers)
	}
}

// (f) Existing Manage behavior is unchanged: a Manage object with no logical
// duplicate creates the client normally.
func TestReconcile_Manage_CreatesClient(t *testing.T) {
	kc := newMockKeycloak(t)

	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "new-app", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "newclient",
			Type:     "spa",
			Mode:     controller.ExportModeManage,
		},
	}

	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "new-app", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := kc.count("create"); got != 1 {
		t.Errorf("CreateApp calls: got %d, want 1", got)
	}

	got := getApp(t, c, "new-app")
	if got.Status.Phase != "Ready" {
		t.Errorf("Phase: got %q, want Ready", got.Status.Phase)
	}
	if !slices.Contains(got.Finalizers, controller.FinalizerName) {
		t.Error("Manage object must gain the destructive finalizer")
	}
}

// (g) A non-200 OIDC discovery response must never be reported as Operational=True.
func TestReconcile_Discovery403_NotOperational(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.discoveryStatus = http.StatusForbidden
	kc.addClient("myrealm", "myclient", "uuid-1")

	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-403", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "myrealm",
			ClientID: "myclient",
			Type:     "web",
			Mode:     controller.ExportModeManage,
		},
	}

	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "app-403", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := getApp(t, c, "app-403")
	op := condition(got, "Operational")
	if op == nil {
		t.Fatal("Operational condition not set")
	}
	if op.Status != metav1.ConditionFalse {
		t.Errorf("Operational status: got %q, want False (HTTP 403 must never be Operational=True)", op.Status)
	}
	if op.Reason != "Unreachable" {
		t.Errorf("Operational reason: got %q, want Unreachable", op.Reason)
	}
}

func TestReconcile_Manage_ReconcilesIdentityMappingsAndTokenClaims(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "trunx", "client-uuid")
	fixedAudience := "trunx"
	controlPlaneAudience := "hanko-control-plane"
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "trunx", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6",
			ClientID: "trunx",
			Type:     "spa",
			Mode:     controller.ExportModeManage,
			Roles: []hankoshv1alpha1.ApplicationRole{
				{Name: "developer"},
			},
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{
				{
					Name: "platform-admins", IdentityProvider: "entra", Claim: "groups", MatchValue: "entra-admin-group",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "A6_TRUNX_PLATFORM"},
				},
				{
					Name: "developers", IdentityProvider: "entra", Claim: "groups", MatchValue: "entra-developer-group",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{ClientRole: "developer"},
				},
				{
					Name: "department", IdentityProvider: "entra", Claim: "department",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{UserAttribute: "department"},
				},
			},
			TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{
				{Name: "department", Claim: "profile.department", UserAttribute: "department"},
				{Name: "audience", Claim: "application", Value: &fixedAudience},
				{Name: "control-plane-audience", Claim: "aud", Value: &controlPlaneAudience},
			},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: "trunx", Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := kc.count("createIDPMapper"); got != 3 {
		t.Fatalf("identity mapper creates: got %d, want 3", got)
	}
	if got := kc.count("createProtocolMapper"); got != 3 {
		t.Fatalf("protocol mapper creates: got %d, want 3", got)
	}

	idpMappers := kc.identityMappers("alien6", "entra")
	assertIdentityMapper(t, idpMappers, "platform-admins", "oidc-role-idp-mapper", map[string]string{
		"syncMode": "FORCE", "claim": "groups", "claim.value": "entra-admin-group", "role": "A6_TRUNX_PLATFORM",
	})
	assertIdentityMapper(t, idpMappers, "developers", "oidc-role-idp-mapper", map[string]string{
		"syncMode": "FORCE", "claim": "groups", "claim.value": "entra-developer-group", "role": "trunx.developer",
	})
	assertIdentityMapper(t, idpMappers, "department", "oidc-user-attribute-idp-mapper", map[string]string{
		"syncMode": "FORCE", "claim": "department", "user.attribute": "department",
	})

	protocolMappers := kc.clientProtocolMappers("alien6", "client-uuid")
	assertProtocolMapper(t, protocolMappers, "department", "oidc-usermodel-attribute-mapper", "profile.department")
	assertProtocolMapper(t, protocolMappers, "audience", "oidc-hardcoded-claim-mapper", "application")
	assertAudienceProtocolMapper(t, protocolMappers, "control-plane-audience", controlPlaneAudience)

	got := getApp(t, c, "trunx")
	if len(got.Status.ManagedIdentityMappings) != 3 || len(got.Status.ManagedTokenClaims) != 3 {
		t.Fatalf("managed mapper status: identity=%+v token=%+v", got.Status.ManagedIdentityMappings, got.Status.ManagedTokenClaims)
	}
	for _, mapper := range got.Status.ManagedIdentityMappings {
		if synced := mapperCondition(mapper.Conditions, "Synced"); synced == nil || synced.Status != metav1.ConditionTrue {
			t.Fatalf("identity mapper %q condition = %+v", mapper.Name, mapper.Conditions)
		}
	}
	for _, mapper := range got.Status.ManagedTokenClaims {
		if synced := mapperCondition(mapper.Conditions, "Synced"); synced == nil || synced.Status != metav1.ConditionTrue {
			t.Fatalf("token mapper %q condition = %+v", mapper.Name, mapper.Conditions)
		}
	}
	mappings := condition(got, "Mappings")
	if mappings == nil || mappings.Status != metav1.ConditionTrue || mappings.Reason != "Synced" {
		t.Fatalf("Mappings condition: got %+v, want True/Synced", mappings)
	}

	// A second reconcile adopts the same named mappers and performs no writes.
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if got := kc.count("updateIDPMapper"); got != 0 {
		t.Errorf("identity mapper updates after no drift: got %d, want 0", got)
	}
	if got := kc.count("updateProtocolMapper"); got != 0 {
		t.Errorf("protocol mapper updates after no drift: got %d, want 0", got)
	}
}

func TestReconcile_Manage_RejectsReservedTokenClaimAtOperatorBoundary(t *testing.T) {
	for _, reservedClaim := range []string{
		"sub",
		"realm_access",
		"realm_access.roles",
		"resource_access",
		"resource_access.console.roles",
		"authorization",
		"authorization.details",
		"permissions",
		"permissions.scope",
		"https://hanko.sh/authorization",
		"https://hanko.sh/authorization.roles",
		"cnf",
		"cnf.jkt",
		"act",
		"act.sub",
		"may_act",
		"may_act.sub",
		"authorization_details",
		"authorization_details.type",
		"hanko_token_use",
		"nonce",
		"auth_time",
		"acr",
		"amr",
		"at_hash",
		"c_hash",
		"s_hash",
		"client_id",
	} {
		t.Run(reservedClaim, func(t *testing.T) {
			kc := newMockKeycloak(t)
			kc.addClient("alien6", "reserved-client", "client-uuid")
			fixed := "spoofed"
			app := &hankoshv1alpha1.HankoApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "reserved-client", Namespace: "default", Generation: 7},
				Spec: hankoshv1alpha1.HankoApplicationSpec{
					RealmRef: "alien6", ClientID: "reserved-client", Type: "spa", Mode: controller.ExportModeManage,
					TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{{Name: "spoof-authority", Claim: reservedClaim, Value: &fixed}},
				},
			}
			c := newFakeClient(t, app)
			r := newReconciler(t, c, kc.client())
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
			if err == nil || !strings.Contains(err.Error(), "reserved claim") {
				t.Fatalf("Reconcile error = %v, want reserved claim rejection", err)
			}
			for _, mutation := range []string{"create", "update", "createProtocolMapper", "updateProtocolMapper", "deleteProtocolMapper"} {
				if got := kc.count(mutation); got != 0 {
					t.Fatalf("reserved claim caused %d %s provider mutation(s)", got, mutation)
				}
			}
			got := getApp(t, c, app.Name)
			if got.Status.Phase != "Error" || len(got.Status.ManagedTokenClaims) != 1 {
				t.Fatalf("reserved mapper status = %+v", got.Status)
			}
			synced := mapperCondition(got.Status.ManagedTokenClaims[0].Conditions, "Synced")
			if synced == nil || synced.Status != metav1.ConditionFalse || synced.Reason != "Invalid" || synced.ObservedGeneration != 7 {
				t.Fatalf("reserved mapper condition = %+v", synced)
			}
		})
	}
}

func TestReconcile_Manage_RemovesMappingsDeletedFromSpec(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "trunx", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "trunx-cleanup", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "trunx", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "admins", IdentityProvider: "entra", Claim: "groups", MatchValue: "admin-group",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "A6_TRUNX_PLATFORM"},
			}},
			TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{{
				Name: "department", Claim: "department", UserAttribute: "department",
			}},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: "trunx-cleanup", Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}

	updated := getApp(t, c, "trunx-cleanup")
	updated.Spec.IdentityMappings = nil
	updated.Spec.TokenClaims = nil
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatalf("remove mappings from spec: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("cleanup Reconcile: %v", err)
	}
	if got := kc.count("deleteIDPMapper"); got != 1 {
		t.Errorf("identity mapper deletes: got %d, want 1", got)
	}
	if got := kc.count("deleteProtocolMapper"); got != 1 {
		t.Errorf("protocol mapper deletes: got %d, want 1", got)
	}
	if got := len(kc.identityMappers("alien6", "entra")); got != 0 {
		t.Errorf("remaining identity mappers: got %d, want 0", got)
	}
	if got := len(kc.clientProtocolMappers("alien6", "client-uuid")); got != 0 {
		t.Errorf("remaining protocol mappers: got %d, want 0", got)
	}
}

func TestReconcile_Observe_WithMappingSpecMakesNoMapperCalls(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "observed", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "observed-mappings", Namespace: "default",
			Labels: map[string]string{controller.ImportedByLabel: "import-1"},
		},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "observed", Type: "spa",
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "admins", IdentityProvider: "entra", Claim: "groups", MatchValue: "admin-group",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
			}},
			TokenClaims: []hankoshv1alpha1.ApplicationTokenClaim{{
				Name: "department", Claim: "department", UserAttribute: "department",
			}},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "observed-mappings", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, counter := range []string{"listIDPMappers", "createIDPMapper", "updateIDPMapper", "deleteIDPMapper", "listProtocolMappers", "createProtocolMapper", "updateProtocolMapper", "deleteProtocolMapper"} {
		if got := kc.count(counter); got != 0 {
			t.Errorf("%s calls in Observe mode: got %d, want 0", counter, got)
		}
	}
}

func TestReconcile_Manage_ExplicitKeycloakNameAdoptsExistingMapper(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "trunx", "client-uuid")
	kc.addIdentityMapper("alien6", "entra", keycloak.IdentityProviderMapper{
		ID: "existing-mapper", Name: "platform-admin-role", IdentityProviderAlias: "entra",
		IdentityProviderMapper: "oidc-role-idp-mapper",
		Config: map[string]string{
			"syncMode": "FORCE", "claim": "groups", "claim.value": "admin-group", "role": "A6_TRUNX_PLATFORM",
		},
	})
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "trunx-adopt", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "trunx", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "platform-admins", KeycloakName: "platform-admin-role", IdentityProvider: "entra",
				Claim: "groups", MatchValue: "admin-group",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "A6_TRUNX_PLATFORM"},
			}},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "trunx-adopt", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("createIDPMapper"); got != 0 {
		t.Errorf("create calls while adopting: got %d, want 0", got)
	}
	if got := kc.count("updateIDPMapper"); got != 0 {
		t.Errorf("update calls without drift: got %d, want 0", got)
	}
	got := getApp(t, c, "trunx-adopt")
	if len(got.Status.ManagedIdentityMappings) != 1 || got.Status.ManagedIdentityMappings[0].KeycloakID != "existing-mapper" {
		t.Fatalf("adopted mapper status: %+v", got.Status.ManagedIdentityMappings)
	}

	kc.mu.Lock()
	kc.idpMappers["alien6|entra"][0].Config["claim.value"] = "drifted-group"
	kc.mu.Unlock()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "trunx-adopt", Namespace: "default"}}); err != nil {
		t.Fatalf("drift Reconcile: %v", err)
	}
	if got := kc.count("updateIDPMapper"); got != 1 {
		t.Errorf("updates after drift: got %d, want 1", got)
	}
	if got := kc.identityMappers("alien6", "entra")[0].Config["claim.value"]; got != "admin-group" {
		t.Errorf("claim.value after drift correction: got %q, want admin-group", got)
	}
}

func TestReconcile_Manage_ConflictingIdentityMapperOwnersMakeNoKeycloakCalls(t *testing.T) {
	first := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-a-mapper", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "client-a", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "admins", KeycloakName: "shared-admin-mapper", IdentityProvider: "entra", Claim: "groups", MatchValue: "group-a",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin-a"},
			}},
		},
	}
	second := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-b-mapper", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "client-b", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "admins", KeycloakName: "shared-admin-mapper", IdentityProvider: "entra", Claim: "groups", MatchValue: "group-b",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin-b"},
			}},
		},
	}
	kc := newMockKeycloak(t)
	c := newFakeClient(t, first, second)
	r := newReconciler(t, c, kc.client())
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "app-b-mapper", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, counter := range []string{"lookup", "create", "update", "listIDPMappers", "createIDPMapper", "updateIDPMapper"} {
		if got := kc.count(counter); got != 0 {
			t.Errorf("%s calls during mapper ownership conflict: got %d, want 0", counter, got)
		}
	}
	got := getApp(t, c, "app-b-mapper")
	conflict := condition(got, "Conflict")
	if got.Status.Phase != "Conflict" || conflict == nil || conflict.Reason != "DuplicateMapperManager" {
		t.Fatalf("conflict status: phase=%s condition=%+v", got.Status.Phase, conflict)
	}
}

func TestReconcile_Manage_RealmIdentityMapperOwnerMakesNoKeycloakCalls(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
			Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
				Name: "shared-admin-mapper", IdentityProviderMapper: "oidc-role-idp-mapper",
			}},
		}}},
	}
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app-mapper", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "client-a", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "admins", KeycloakName: "shared-admin-mapper", IdentityProvider: "entra", Claim: "groups", MatchValue: "group-a",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin-a"},
			}},
		},
	}
	kc := newMockKeycloak(t)
	c := newFakeClient(t, realm, app)
	r := newReconciler(t, c, kc.client())
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, counter := range []string{"lookup", "create", "update", "listIDPMappers", "createIDPMapper", "updateIDPMapper"} {
		if got := kc.count(counter); got != 0 {
			t.Errorf("%s calls during realm mapper ownership conflict: got %d, want 0", counter, got)
		}
	}
	got := getApp(t, c, app.Name)
	conflict := condition(got, "Conflict")
	if got.Status.Phase != "Conflict" || conflict == nil || !strings.Contains(conflict.Message, "HankoRealm/alien6") {
		t.Fatalf("realm conflict status: phase=%s condition=%+v", got.Status.Phase, conflict)
	}
}

func TestReconcile_Manage_PersistsPartialMapperProgressOnLaterFailure(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "partial-client", "client-uuid")
	duplicateName := "hanko:default:partial-mappers:idp:second"
	for _, id := range []string{"duplicate-a", "duplicate-b"} {
		kc.addIdentityMapper("alien6", "entra", keycloak.IdentityProviderMapper{
			ID: id, Name: duplicateName, IdentityProviderAlias: "entra", IdentityProviderMapper: "oidc-role-idp-mapper",
			Config: map[string]string{"syncMode": "FORCE", "claim": "groups", "claim.value": "second", "role": "admin"},
		})
	}
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "partial-mappers", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "partial-client", Type: "spa", Mode: controller.ExportModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{
				{
					Name: "first", IdentityProvider: "entra", Claim: "groups", MatchValue: "first",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
				},
				{
					Name: "second", IdentityProvider: "entra", Claim: "groups", MatchValue: "second",
					Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
				},
			},
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "partial-mappers", Namespace: "default"}})
	if err == nil {
		t.Fatal("Reconcile succeeded, want duplicate mapper error")
	}
	got := getApp(t, c, "partial-mappers")
	if got.Status.Phase != "Error" || len(got.Status.ManagedIdentityMappings) != 2 {
		t.Fatalf("partial status: phase=%s mappings=%+v", got.Status.Phase, got.Status.ManagedIdentityMappings)
	}
	if got.Status.ManagedIdentityMappings[0].Name != "first" || got.Status.ManagedIdentityMappings[0].KeycloakID == "" {
		t.Fatalf("first mapper not checkpointed: %+v", got.Status.ManagedIdentityMappings)
	}
	failed := got.Status.ManagedIdentityMappings[1]
	if failed.Name != "second" {
		t.Fatalf("failed mapper not reported: %+v", got.Status.ManagedIdentityMappings)
	}
	if synced := mapperCondition(failed.Conditions, "Synced"); synced == nil || synced.Status != metav1.ConditionFalse || synced.Reason != "EnsureFailed" {
		t.Fatalf("failed mapper condition = %+v", synced)
	}
}

func TestReconcile_Manage_WaitsForManagedTheme(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "themed-app", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "themed-app", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "themed-app", Type: "spa", Mode: controller.ExportModeManage,
			Theme: "brand",
		},
	}
	theme := &hankoshv1alpha1.HankoTheme{
		ObjectMeta: metav1.ObjectMeta{Name: "brand", Namespace: "default", Generation: 2},
		Status: hankoshv1alpha1.HankoThemeStatus{
			Phase: "Building", ObservedGeneration: 1,
		},
	}
	c := newFakeClient(t, app, theme)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("update"); got != 0 {
		t.Fatalf("UpdateApp calls: got %d, want 0 while theme is building", got)
	}
	got := getApp(t, c, app.Name)
	themeReady := condition(got, "ThemeReady")
	if got.Status.Phase != "Reconciling" || themeReady == nil || themeReady.Status != metav1.ConditionFalse || themeReady.Reason != "ThemeBuilding" {
		t.Fatalf("theme readiness: phase=%q condition=%+v", got.Status.Phase, themeReady)
	}
}

func TestReconcile_Manage_AssignsReadyManagedTheme(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "themed-app", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "themed-app", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "themed-app", Type: "spa", Mode: controller.ExportModeManage,
			Theme: "brand",
		},
	}
	theme := &hankoshv1alpha1.HankoTheme{
		ObjectMeta: metav1.ObjectMeta{Name: "brand", Namespace: "default", Generation: 2},
		Status: hankoshv1alpha1.HankoThemeStatus{
			Phase: "Ready", JarPath: "/opt/keycloak/providers/brand-theme.jar", ObservedGeneration: 2,
		},
	}
	c := newFakeClient(t, app, theme)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("update"); got != 1 {
		t.Fatalf("UpdateApp calls: got %d, want 1", got)
	}
	got := getApp(t, c, app.Name)
	themeReady := condition(got, "ThemeReady")
	if got.Status.Phase != "Ready" || themeReady == nil || themeReady.Status != metav1.ConditionTrue || themeReady.Reason != "ManagedThemeReady" {
		t.Fatalf("theme readiness: phase=%q condition=%+v", got.Status.Phase, themeReady)
	}
}

func TestReconcile_Manage_AllowsExplicitExternalThemeDuringMigration(t *testing.T) {
	kc := newMockKeycloak(t)
	kc.addClient("alien6", "legacy-app", "client-uuid")
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-app", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "alien6", ClientID: "legacy-app", Type: "spa", Mode: controller.ExportModeManage,
			Theme: "preinstalled-theme",
		},
	}
	c := newFakeClient(t, app)
	r := newReconciler(t, c, kc.client())

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := kc.count("update"); got != 1 {
		t.Fatalf("UpdateApp calls: got %d, want 1 for external theme", got)
	}
	themeReady := condition(getApp(t, c, app.Name), "ThemeReady")
	if themeReady == nil || themeReady.Status != metav1.ConditionUnknown || themeReady.Reason != "ExternalTheme" {
		t.Fatalf("ThemeReady condition: got %+v, want Unknown/ExternalTheme", themeReady)
	}
}

func assertIdentityMapper(t *testing.T, items []keycloak.IdentityProviderMapper, nameSuffix, provider string, config map[string]string) {
	t.Helper()
	for _, item := range items {
		if strings.HasSuffix(item.Name, ":"+nameSuffix) {
			if item.IdentityProviderMapper != provider {
				t.Errorf("identity mapper %q provider: got %q, want %q", nameSuffix, item.IdentityProviderMapper, provider)
			}
			if !maps.Equal(item.Config, config) {
				t.Errorf("identity mapper %q config: got %#v, want %#v", nameSuffix, item.Config, config)
			}
			return
		}
	}
	t.Errorf("identity mapper ending in %q not found: %+v", nameSuffix, items)
}

func assertProtocolMapper(t *testing.T, items []keycloak.ProtocolMapper, nameSuffix, provider, claimName string) {
	t.Helper()
	for _, item := range items {
		if strings.HasSuffix(item.Name, ":"+nameSuffix) {
			if item.ProtocolMapper != provider || item.Config["claim.name"] != claimName {
				t.Errorf("protocol mapper %q: got provider=%q config=%#v", nameSuffix, item.ProtocolMapper, item.Config)
			}
			for _, key := range []string{"id.token.claim", "access.token.claim", "userinfo.token.claim", "introspection.token.claim"} {
				if item.Config[key] != "true" {
					t.Errorf("protocol mapper %q %s: got %q, want true", nameSuffix, key, item.Config[key])
				}
			}
			return
		}
	}
	t.Errorf("protocol mapper ending in %q not found: %+v", nameSuffix, items)
}

func assertAudienceProtocolMapper(t *testing.T, items []keycloak.ProtocolMapper, nameSuffix, audience string) {
	t.Helper()
	for _, item := range items {
		if strings.HasSuffix(item.Name, ":"+nameSuffix) {
			if item.ProtocolMapper != "oidc-audience-mapper" || item.Config["included.custom.audience"] != audience {
				t.Errorf("audience mapper %q: got provider=%q config=%#v", nameSuffix, item.ProtocolMapper, item.Config)
			}
			if item.Config["access.token.claim"] != "true" || item.Config["introspection.token.claim"] != "true" {
				t.Errorf("audience mapper %q must target access and introspection tokens: %#v", nameSuffix, item.Config)
			}
			if item.Config["id.token.claim"] != "false" {
				t.Errorf("audience mapper %q id.token.claim = %q, want false", nameSuffix, item.Config["id.token.claim"])
			}
			return
		}
	}
	t.Errorf("audience mapper ending in %q not found: %+v", nameSuffix, items)
}
