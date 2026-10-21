package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func pooledTenantObjects() []client.Object {
	return []client.Object{
		&api.HankoRealm{},
		&api.HankoApplication{Spec: api.HankoApplicationSpec{RealmRef: "acme", ClientID: "application"}},
		&api.HankoServiceAccount{Spec: api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "service-account"}},
		&api.HankoOrganization{Spec: api.HankoOrganizationSpec{RealmRef: "acme", Name: "organization"}},
		&api.HankoRole{Spec: api.HankoRoleSpec{RealmRef: "acme", Name: "role"}},
		&api.HankoResourceServer{Spec: api.HankoResourceServerSpec{RealmRef: "acme", Audience: "audience"}},
	}
}

func pooledTenantController(kube client.Client, pool *keycloak.Pool, obj client.Object) reconcile.Reconciler {
	switch obj.(type) {
	case *api.HankoRealm:
		return &HankoRealmReconciler{Client: kube, Pool: pool}
	case *api.HankoApplication:
		return &HankoApplicationReconciler{Client: kube, Pool: pool}
	case *api.HankoServiceAccount:
		return &HankoServiceAccountReconciler{Client: kube, Pool: pool}
	case *api.HankoOrganization:
		return &HankoOrganizationReconciler{Client: kube, Pool: pool}
	case *api.HankoRole:
		return &HankoRoleReconciler{Client: kube, Pool: pool}
	default:
		return &HankoResourceServerReconciler{Client: kube, Pool: pool}
	}
}

func TestTenantClientMissingBlocksEveryPooledController(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected shared provider request", http.StatusInternalServerError)
	}))
	defer server.Close()
	shared := keycloak.New(server.URL, "operator", "fixture", keycloak.WithInsecureHTTP())
	for _, mode := range []string{"Manage", "Observe", "Delete"} {
		for _, registration := range []string{"missing", "removed", "empty-label", "nil-pool"} {
			for _, obj := range pooledTenantObjects() {
				t.Run(reflect.TypeOf(obj).Elem().Name()+"/"+mode+"/"+registration, func(t *testing.T) {
					ctx := context.Background()
					obj.SetName("work")
					obj.SetNamespace("test")
					obj.SetGeneration(2)
					obj.SetUID("owned-resource")
					labels := map[string]string{"hanko.sh/tenant": "tenant"}
					if registration == "empty-label" {
						labels["hanko.sh/tenant"] = ""
					}
					if mode == "Observe" {
						labels[importedByLabel] = "inventory"
					}
					obj.SetLabels(labels)
					finalizers := []string{"hanko.sh/realm-cleanup", "hanko.sh/client-cleanup", "hanko.sh/sa-cleanup", "hanko.sh/organization-cleanup", "hanko.sh/role-cleanup", "hanko.sh/resource-server-cleanup"}
					obj.SetFinalizers(finalizers)
					if mode == "Delete" {
						now := metav1.Now()
						obj.SetDeletionTimestamp(&now)
					}
					pool := keycloak.NewPool(shared)
					if registration == "removed" {
						pool.RegisterShared("test/tenant")
						pool.Remove("test/tenant")
					}
					if registration == "nil-pool" {
						pool = nil
					}
					kube := controllerTestClient(controllerTestScheme(t), obj)
					result, err := pooledTenantController(kube, pool, obj).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
					if err != nil || result.RequeueAfter == 0 {
						t.Fatalf("unavailable tenant was not deferred: %v %v", result, err)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
						t.Fatal(err)
					}
					raw, _ := json.Marshal(obj)
					var status struct {
						Status struct {
							Phase              string
							ObservedGeneration int64
							Conditions         []metav1.Condition
						}
					}
					if err := json.Unmarshal(raw, &status); err != nil {
						t.Fatal(err)
					}
					if status.Status.Phase != "Error" || status.Status.ObservedGeneration != 2 || conditionReason(status.Status.Conditions, "Synced") != "TenantClientUnavailable" {
						t.Fatalf("distinct current refusal missing: %s", raw)
					}
					if !reflect.DeepEqual(obj.GetFinalizers(), finalizers) {
						t.Fatal("unavailable provider released a cleanup finalizer")
					}
					var secrets corev1.SecretList
					if err := kube.List(ctx, &secrets); err != nil || len(secrets.Items) != 0 {
						t.Fatal("blocked resource changed credential inventory")
					}
					if calls.Load() != 0 {
						t.Fatal("tenant resource reached the shared provider")
					}
				})
			}
		}
	}
}

func TestTenantClientMissingReturnsStatusWriteFailure(t *testing.T) {
	ctx := context.Background()
	realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test", Labels: map[string]string{"hanko.sh/tenant": "tenant"}}}
	kube := controllerTestClient(controllerTestScheme(t), realm)
	injected := errors.New("injected status failure")
	wrapped := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return injected
	}})
	if _, err := (&HankoRealmReconciler{Client: wrapped}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); !errors.Is(err, injected) {
		t.Fatalf("status error lost: %v", err)
	}
}

func tenantRoutingFixture(endpoint string) (*api.HankoTenant, *corev1.Secret, *corev1.Secret) {
	tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "test"}, Spec: api.HankoTenantSpec{
		IsolationMode: "keycloak", KeycloakSecretRef: &corev1.LocalObjectReference{Name: "keycloak"}, HubEndpoint: endpoint, HubTenantID: "tenant-id", HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub"},
	}}
	provider := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: "test"}, Data: map[string][]byte{
		"HANKO_KEYCLOAK_URL": []byte("https://dedicated.example"), "HANKO_KC_CLIENT_ID": []byte("operator"), "HANKO_KC_CLIENT_SECRET": []byte("fixture"),
	}}
	hub := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub", Namespace: "test"}, Data: map[string][]byte{
		"hub_token": []byte("fixture-token"), "expires_at": []byte(time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)),
	}}
	return tenant, provider, hub
}

func TestTenantRoutingSurvivesHubOutageAndControllerRestart(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("HANKO_SECURITY_PROFILE", "standard")
	fixture, dedicated := newManagedRealmAPIFixture(t)
	var sharedCalls, hubCalls atomic.Int64
	sharedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sharedCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sharedServer.Close()
	var activePool atomic.Pointer[keycloak.Pool]
	hubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hubCalls.Add(1)
		if kc := activePool.Load().Get("test/tenant"); kc == nil || kc.BaseURL() != dedicated.BaseURL() {
			t.Error("Hub contacted before dedicated client registration")
		}
		http.Error(w, "disconnected", http.StatusServiceUnavailable)
	}))
	defer hubServer.Close()
	tenant, provider, hubSecret := tenantRoutingFixture(hubServer.URL)
	provider.Data["HANKO_KEYCLOAK_URL"] = []byte(dedicated.BaseURL())
	realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test", Labels: map[string]string{"hanko.sh/tenant": "tenant"}}}
	kube := controllerTestClient(controllerTestScheme(t), tenant, provider, hubSecret, realm)
	for range 2 {
		activePool.Store(keycloak.NewPool(keycloak.New(sharedServer.URL, "shared", "fixture", keycloak.WithInsecureHTTP())))
		blocked := &HankoRealmReconciler{Client: kube, Pool: activePool.Load()}
		if _, err := blocked.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
			t.Fatal(err)
		}
		r := &HankoTenantReconciler{Client: kube, Pool: activePool.Load()}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
			t.Fatal(err)
		}
		if activePool.Load().Get("test/tenant") == nil {
			t.Fatal("Hub outage prevented dedicated registration")
		}
		rr := &HankoRealmReconciler{Client: kube, Pool: activePool.Load()}
		if _, err := rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(context.Background(), client.ObjectKeyFromObject(realm), realm); err != nil {
			t.Fatal(err)
		}
		for _, condition := range realm.Status.Conditions {
			if condition.Reason == "TenantClientUnavailable" {
				t.Fatal("successful recovery retained a stale routing refusal")
			}
		}
	}
	if fixture.realmPayload == nil || sharedCalls.Load() != 0 || hubCalls.Load() == 0 {
		t.Fatalf("wrong provider routing: dedicated=%v shared=%d Hub=%d", fixture.realmPayload != nil, sharedCalls.Load(), hubCalls.Load())
	}
}

func TestTenantRoutingRevokesInvalidDeletedAndChangedRegistrations(t *testing.T) {
	for _, failure := range []string{"missing-secret", "empty-secret", "invalid-transport", "invalid-mode", "deleting", "deleted"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			tenant, provider, _ := tenantRoutingFixture("https://hub.example")
			shared := keycloak.New("https://shared.example", "operator", "fixture")
			pool := keycloak.NewPool(shared)
			pool.Register("test/tenant", keycloak.New("https://previous.example", "operator", "fixture"))
			objects := []client.Object{tenant, provider}
			switch failure {
			case "missing-secret":
				objects = []client.Object{tenant}
			case "empty-secret":
				delete(provider.Data, "HANKO_KC_CLIENT_SECRET")
			case "invalid-transport":
				provider.Data["HANKO_KEYCLOAK_URL"] = []byte("file:///untrusted")
			case "invalid-mode":
				tenant.Spec.IsolationMode = "unsupported"
			case "deleting":
				now := metav1.Now()
				tenant.DeletionTimestamp = &now
				tenant.Finalizers = []string{"fixture"}
			case "deleted":
				objects = []client.Object{provider}
			}
			kube := controllerTestClient(controllerTestScheme(t), objects...)
			r := &HankoTenantReconciler{Client: kube, Pool: pool}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)}); err != nil {
				t.Fatal(err)
			}
			if pool.Get("test/tenant") != nil || pool.Get("") != shared {
				t.Fatal("invalid tenant retained or fell back to a shared registration")
			}
		})
	}
}

func TestTenantRoutingReadsOneCurrentCredentialSnapshot(t *testing.T) {
	ctx := context.Background()
	tenant, provider, _ := tenantRoutingFixture("https://hub.example")
	kube := controllerTestClient(controllerTestScheme(t), tenant, provider)
	reads := 0
	current := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*corev1.Secret); ok {
			reads++
		}
		return c.Get(ctx, key, obj, opts...)
	}})
	// The cached client is not the authority for a dedicated credential read.
	staleClient := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return errors.New("stale cache must not be used")
	}})
	pool := keycloak.NewPool(nil)
	r := &HankoTenantReconciler{Client: staleClient, APIReader: current, Pool: pool}
	if reason, err := r.registerTenantKeycloak(ctx, tenant); err != nil {
		t.Fatalf("registration rejected: %s %v", reason, err)
	}
	if reads != 1 || pool.Get("test/tenant") == nil {
		t.Fatalf("credential snapshot split across %d reads", reads)
	}
	tenant.Spec.IsolationMode = "realm"
	if reason, err := r.registerTenantKeycloak(ctx, tenant); err != nil {
		t.Fatalf("realm registration: %s %v", reason, err)
	}
	if pool.Get("test/tenant") != nil {
		t.Fatal("realm transition retained a dedicated credential")
	}
}
