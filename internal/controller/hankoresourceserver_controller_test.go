package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

type recordingAuthorizationDriver struct {
	capabilities   authorization.Capabilities
	capabilityErr  error
	capabilityHook func()
	state          authorization.State
	err            error
	observeCalls   int
	reconcile      []authorization.ManagedObjects
	deleted        []authorization.ManagedObjects
}

func (d *recordingAuthorizationDriver) Capabilities(context.Context, string) (authorization.Capabilities, error) {
	if d.capabilityHook != nil {
		hook := d.capabilityHook
		d.capabilityHook = nil
		hook()
	}
	return d.capabilities, d.capabilityErr
}

func (d *recordingAuthorizationDriver) Observe(context.Context, authorization.Plan) (authorization.State, error) {
	d.observeCalls++
	return d.state, d.err
}

func (d *recordingAuthorizationDriver) Reconcile(_ context.Context, _ authorization.Plan, owned authorization.ManagedObjects) (authorization.State, error) {
	d.reconcile = append(d.reconcile, owned)
	return d.state, d.err
}

func (d *recordingAuthorizationDriver) DeleteOwned(_ context.Context, _ authorization.Model, owned authorization.ManagedObjects, _ string) error {
	d.deleted = append(d.deleted, owned)
	return d.err
}

func resourceServerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func resourceServerClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(resourceServerScheme(t)).WithObjects(objects...).
		WithStatusSubresource(&hankoshv1alpha1.HankoResourceServer{}).Build()
}

func supportedAuthorizationCapabilities() authorization.Capabilities {
	return authorization.Capabilities{
		ScopeGrants: true, RolePrincipals: true, ApplicationPrincipals: true,
		ServiceAccountPrincipals: true, ResourceObjects: true, ResourceURIMatching: true,
		UMARPT: true, NativePermissionClaim: true,
	}
}

func validResourceServerObjects(mode string) (*hankoshv1alpha1.HankoResourceServer, []client.Object) {
	realm := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "default"}}
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "billing-api", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "billing-api"},
	}
	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "billing-reader", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRoleSpec{RealmRef: "acme", Name: "billing-reader"},
	}
	resourceServer := &hankoshv1alpha1.HankoResourceServer{
		ObjectMeta: metav1.ObjectMeta{Name: "billing", Namespace: "default", UID: "resource-server-uid", Generation: 1},
		Spec: hankoshv1alpha1.HankoResourceServerSpec{
			RealmRef: "acme", Audience: "https://api.example/billing", ApplicationRef: "billing-api", Mode: mode,
			Scopes:    []hankoshv1alpha1.AuthorizationScope{{Name: "invoices:read"}},
			Resources: []hankoshv1alpha1.AuthorizationResource{{Name: "invoices", Scopes: []string{"invoices:read"}}},
			Permissions: []hankoshv1alpha1.AuthorizationPermission{{
				Name: "readers", Resources: []string{"invoices"}, Scopes: []string{"invoices:read"},
				Principals: []hankoshv1alpha1.AuthorizationPrincipal{{Kind: "realm_role", Ref: "billing-reader"}},
			}},
		},
	}
	return resourceServer, []client.Object{realm, app, role, resourceServer}
}

func TestResourceServerPortableValidationRejectsDanglingAndDuplicateReferences(t *testing.T) {
	base, _ := validResourceServerObjects(ModeManage)
	for _, test := range []struct {
		name  string
		patch func(*hankoshv1alpha1.HankoResourceServerSpec)
	}{
		{name: "duplicate scope", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Scopes = append(spec.Scopes, spec.Scopes[0]) }},
		{name: "missing required reference", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Audience = "" }},
		{name: "duplicate resource", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) {
			spec.Resources = append(spec.Resources, spec.Resources[0])
		}},
		{name: "dangling resource scope", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Resources[0].Scopes = []string{"missing"} }},
		{name: "dangling permission resource", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) {
			spec.Permissions[0].Resources = []string{"missing"}
		}},
		{name: "unsupported mode", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Mode = "Adopt" }},
		{name: "permission without principals", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Permissions[0].Principals = nil }},
		{name: "dangling permission scope", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Permissions[0].Scopes = []string{"missing"} }},
		{name: "duplicate principal", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) {
			spec.Permissions[0].Principals = append(spec.Permissions[0].Principals, spec.Permissions[0].Principals[0])
		}},
		{name: "unsupported principal", patch: func(spec *hankoshv1alpha1.HankoResourceServerSpec) { spec.Permissions[0].Principals[0].Kind = "group" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := base.Spec.DeepCopy()
			test.patch(spec)
			if err := validatePortableAuthorizationSpec(*spec); err == nil {
				t.Fatal("validation accepted invalid portable model")
			}
		})
	}
}

func TestResourceServerProviderFailuresRemainFailClosed(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      string
		driver    *recordingAuthorizationDriver
		wantCalls int
	}{
		{name: "capability lookup", mode: ModeManage, driver: &recordingAuthorizationDriver{capabilityErr: errors.New("provider unavailable")}},
		{name: "observe", mode: ModeObserve, driver: &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), err: errors.New("observe denied")}, wantCalls: 1},
		{name: "ownership conflict", mode: ModeManage, driver: &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), err: authorization.ErrOwnershipConflict}, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			resourceServer, objects := validResourceServerObjects(test.mode)
			backend := resourceServerClient(t, objects...)
			reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return test.driver }}
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resourceServer)}); err == nil {
				t.Fatal("provider failure must be returned after being checkpointed")
			}
			if test.mode == ModeObserve && test.driver.observeCalls != test.wantCalls {
				t.Fatalf("observe calls = %d", test.driver.observeCalls)
			}
			if test.mode == ModeManage && len(test.driver.reconcile) != test.wantCalls {
				t.Fatalf("reconcile calls = %d", len(test.driver.reconcile))
			}
			var actual hankoshv1alpha1.HankoResourceServer
			_ = backend.Get(context.Background(), client.ObjectKeyFromObject(resourceServer), &actual)
			if actual.Status.Phase != "Error" || conditionTrue(actual.Status.Conditions, "Synced") {
				t.Fatalf("provider failure status = %#v", actual.Status)
			}
		})
	}
}

func TestResourceServerResolvesPortablePrincipalReferences(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	realm := objects[0].(*hankoshv1alpha1.HankoRealm)
	realm.Spec.Roles = []hankoshv1alpha1.RealmRole{{Name: "inline-reader"}}
	account := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "automation", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "automation-client"},
	}
	resourceServer.Spec.Permissions[0].Principals = []hankoshv1alpha1.AuthorizationPrincipal{
		{Kind: "realm_role", Ref: "inline-reader"},
		{Kind: "application", Ref: "billing-api"},
		{Kind: "service_account", Ref: "automation"},
	}
	objects = append(objects, account)
	reconciler := &HankoResourceServerReconciler{Client: resourceServerClient(t, objects...)}
	model, err := reconciler.resolveAuthorizationModel(context.Background(), resourceServer)
	if err != nil {
		t.Fatalf("resolve portable principals: %v", err)
	}
	principals := model.Permissions[0].Principals
	if len(principals) != 3 || principals[0].Ref != "inline-reader" || principals[1].Ref != "billing-api" || principals[2].Ref != "automation-client" {
		t.Fatalf("resolved principals = %#v", principals)
	}

	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(account), account); err != nil {
		t.Fatal(err)
	}
	account.Spec.RealmRef = "other"
	if err := reconciler.Update(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.resolveAuthorizationPrincipal(context.Background(), resourceServer, realm, resourceServer.Spec.Permissions[0].Principals[2]); err == nil {
		t.Fatal("cross-realm service account must be rejected")
	}
}

func TestResourceServerRejectsCrossRealmPrincipalBeforeProviderCall(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	objects[2].(*hankoshv1alpha1.HankoRole).Spec.RealmRef = "victim"
	driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: resourceServer.Name, Namespace: resourceServer.Namespace}})
	if err == nil || len(driver.reconcile) != 0 || driver.observeCalls != 0 {
		t.Fatalf("cross-realm result err=%v reconcile=%d observe=%d", err, len(driver.reconcile), driver.observeCalls)
	}
}

func TestResourceServerObserveNeverMutatesProvider(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeObserve)
	driver := &recordingAuthorizationDriver{
		capabilities: supportedAuthorizationCapabilities(),
		state: authorization.State{Observation: successfulIAMObservation(), ProviderResourceServerID: "provider-id", Capabilities: supportedAuthorizationCapabilities(), Findings: []authorization.Finding{{
			Classification: "unsupported", ObjectKind: "policy", ObjectName: "native", Code: "provider_native_observation", ReadOnly: true,
		}}},
	}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: resourceServer.Name, Namespace: resourceServer.Namespace}}); err != nil {
		t.Fatal(err)
	}
	var got hankoshv1alpha1.HankoResourceServer
	if err := backend.Get(context.Background(), client.ObjectKeyFromObject(resourceServer), &got); err != nil {
		t.Fatal(err)
	}
	if driver.observeCalls != 1 || len(driver.reconcile) != 0 || len(driver.deleted) != 0 {
		t.Fatalf("provider calls observe=%d reconcile=%d delete=%d", driver.observeCalls, len(driver.reconcile), len(driver.deleted))
	}
	if len(got.Finalizers) != 0 || got.Status.Phase != "Ready" || len(got.Status.Findings) != 1 || !got.Status.Findings[0].ReadOnly {
		t.Fatalf("observed resource server = %+v", got)
	}
}

func TestResourceServerUnsupportedCapabilitiesFailBeforeMutation(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	driver := &recordingAuthorizationDriver{capabilities: authorization.Capabilities{ScopeGrants: true, RolePrincipals: true}}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resourceServer)})
	if !errors.Is(err, authorization.ErrCapabilityUnsupported) || len(driver.reconcile) != 0 {
		t.Fatalf("unsupported result err=%v reconcile=%d", err, len(driver.reconcile))
	}
	var got hankoshv1alpha1.HankoResourceServer
	if getErr := backend.Get(context.Background(), client.ObjectKeyFromObject(resourceServer), &got); getErr != nil {
		t.Fatal(getErr)
	}
	if len(got.Finalizers) != 0 || conditionTrue(got.Status.Conditions, "DriftFree") {
		t.Fatalf("unsupported resource server finalizers=%v conditions=%+v", got.Finalizers, got.Status.Conditions)
	}
}

func TestResourceServerDeletionRecoversProviderJournalWithoutStatusOwnership(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	resourceServer.Finalizers = []string{resourceServerFinalizerName}
	resourceServer.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
	driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resourceServer)}); err != nil {
		t.Fatal(err)
	}
	if len(driver.deleted) != 1 || driver.deleted[0].ResourceServerID != "" || len(driver.reconcile) != 0 || driver.observeCalls != 0 {
		t.Fatalf("provider calls observe=%d reconcile=%d delete=%d", driver.observeCalls, len(driver.reconcile), len(driver.deleted))
	}
}

func TestResourceServerDeletionUsesOnlyPersistedOwnership(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	resourceServer.Finalizers = []string{resourceServerFinalizerName}
	resourceServer.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
	resourceServer.Status.ProviderResourceServerID = "provider-id"
	resourceServer.Status.ManagedObjects.Scopes = []hankoshv1alpha1.AuthorizationManagedReference{{Name: "invoices:read", ID: "scope-id"}}
	driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resourceServer)}); err != nil {
		t.Fatal(err)
	}
	if len(driver.deleted) != 1 || driver.deleted[0].ResourceServerID != "provider-id" || len(driver.deleted[0].Scopes) != 1 {
		t.Fatalf("persisted deletion boundary = %#v", driver.deleted)
	}
}

func TestResourceServerPersistsOwnershipAndDriftCondition(t *testing.T) {
	resourceServer, objects := validResourceServerObjects(ModeManage)
	resourceServer.Annotations = map[string]string{"hanko.sh/authorization-plan-hash": "plan-123"}
	driver := &recordingAuthorizationDriver{
		capabilities: supportedAuthorizationCapabilities(),
		state: authorization.State{
			Observation: successfulIAMObservation(), ProviderResourceServerID: "provider-id", Capabilities: supportedAuthorizationCapabilities(),
			ManagedObjects: authorization.ManagedObjects{ResourceServerID: "provider-id", Scopes: []authorization.ManagedReference{{Name: "invoices:read", ID: "scope-id"}}},
		},
	}
	backend := resourceServerClient(t, objects...)
	reconciler := &HankoResourceServerReconciler{Client: backend, Scheme: resourceServerScheme(t), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resourceServer)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(driver.reconcile) != 2 || driver.reconcile[1].ResourceServerID != "provider-id" || len(driver.reconcile[1].Scopes) != 1 {
		t.Fatalf("owned state on retry = %+v", driver.reconcile)
	}
	var got hankoshv1alpha1.HankoResourceServer
	if err := backend.Get(context.Background(), request.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Ready" || !strings.HasPrefix(got.Status.AppliedPlanHash, "sha256:") || got.Status.AppliedPlanHash == "plan-123" || got.Status.ProviderResourceServerID != "provider-id" || !conditionTrue(got.Status.Conditions, "DriftFree") {
		t.Fatalf("status = %+v", got.Status)
	}
}

func conditionTrue(conditions []metav1.Condition, conditionType string) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == metav1.ConditionTrue
		}
	}
	return false
}

func TestResourceServerRejectsChangedInputsBeforeMutation(t *testing.T) {
	for _, kind := range []string{"reference", "mode", "ownership", "generation"} {
		t.Run(kind, func(t *testing.T) {
			obj, objects := validResourceServerObjects(ModeManage)
			backend := resourceServerClient(t, objects...)
			d := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
			d.capabilityHook = func() {
				if kind == "reference" {
					var app hankoshv1alpha1.HankoApplication
					if err := backend.Get(context.Background(), client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.ApplicationRef}, &app); err != nil {
						t.Fatal(err)
					}
					app.Spec.ClientID = "changed-client"
					if err := backend.Update(context.Background(), &app); err != nil {
						t.Fatal(err)
					}
					return
				}
				var current hankoshv1alpha1.HankoResourceServer
				if err := backend.Get(context.Background(), client.ObjectKeyFromObject(obj), &current); err != nil {
					t.Fatal(err)
				}
				if kind == "ownership" {
					current.Status.ProviderResourceServerID = "changed-owner"
					if err := backend.Status().Update(context.Background(), &current); err != nil {
						t.Fatal(err)
					}
					return
				}
				if kind == "mode" {
					current.Spec.Mode = ModeObserve
				} else {
					current.Generation++
				}
				if err := backend.Update(context.Background(), &current); err != nil {
					t.Fatal(err)
				}
			}
			r := &HankoResourceServerReconciler{Client: backend, DriverFactory: func(string, map[string]string) authorization.Driver { return d }}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			if err == nil || len(d.reconcile) > 0 {
				t.Fatal("changed input executed stale plan")
			}
		})
	}
}

func successfulIAMObservation() iamcontract.Observation {
	return iamcontract.Observation{StateHash: iamcontract.Hash(iamcontract.Version, "fixture", "observation", []byte("read-back")), Complete: true}
}
