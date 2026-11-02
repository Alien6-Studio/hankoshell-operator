package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type scopeIntentAttachment struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// The ordinary fake client can preserve fields that a real typed HTTP update
// would omit. Round-trip full updates through JSON to exercise that boundary.
type scopeIntentWireClient struct {
	client.Client
	updates int
}

func (c *scopeIntentWireClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	account, ok := object.(*api.HankoServiceAccount)
	if !ok {
		return c.Client.Update(ctx, object, options...)
	}
	raw, err := json.Marshal(account)
	if err != nil {
		return err
	}
	var wire api.HankoServiceAccount
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if err := c.Client.Update(ctx, &wire, options...); err != nil {
		return err
	}
	*account = wire
	c.updates++
	return nil
}

type scopeIntentProvider struct {
	available, defaults, optional []scopeIntentAttachment
	reads, writes                 int
	dropWrites                    bool
}

func scopeIntentClient(t *testing.T, mock *mockKeycloak, state *scopeIntentProvider) *keycloak.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const realmPath = "/admin/realms/acme"
		clientPath := ""
		if parts := strings.Split(r.URL.Path, "/"); len(parts) >= 7 && parts[4] == "clients" {
			clientPath = strings.Join(parts[:6], "/") + "/"
		}
		if r.Method == http.MethodGet && r.URL.Path == realmPath+"/client-scopes" {
			state.reads++
			_ = json.NewEncoder(w).Encode(state.available)
			return
		}
		for _, kind := range []string{"default", "optional"} {
			if clientPath == "" {
				break
			}
			path := clientPath + kind + "-client-scopes"
			attached := &state.defaults
			if kind == "optional" {
				attached = &state.optional
			}
			if r.Method == http.MethodGet && r.URL.Path == path {
				state.reads++
				_ = json.NewEncoder(w).Encode(*attached)
				return
			}
			if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, path+"/") {
				state.writes++
				id := strings.TrimPrefix(r.URL.Path, path+"/")
				if !state.dropWrites {
					*attached = slices.DeleteFunc(*attached, func(scope scopeIntentAttachment) bool { return scope.ID == id })
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		// The native provider fills its default secret authenticator on creation;
		// the shared unit mock intentionally models only submitted JSON fields.
		if r.Method == http.MethodGet && reClientByID.MatchString(r.URL.Path) {
			mock.mu.Lock()
			for _, native := range mock.clientState {
				if native["serviceAccountsEnabled"] == true && native["clientAuthenticatorType"] == nil {
					native["clientAuthenticatorType"] = "client-secret"
				}
			}
			mock.mu.Unlock()
		}
		mock.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return keycloak.New(server.URL, "test-client", "test-secret", keycloak.WithInsecureHTTP())
}

func TestServiceAccountScopeConfirmationPrecedesCredentialPublication(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new native client"
		if existing {
			name = "recovered native client"
		}
		t.Run(name, func(t *testing.T) {
			mock := newMockKeycloak(t)
			account := &api.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "default", Generation: 2},
				Spec:       api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "reader", Scopes: []string{}},
			}
			if existing {
				mock.addClient("acme", "reader", "client-uuid")
				mock.ownServiceAccount(account)
				mock.mu.Lock()
				mock.clientState["acme|client-uuid"]["serviceAccountsEnabled"] = true
				mock.mu.Unlock()
			}
			kube := &scopeIntentWireClient{Client: newFakeClient(t, account)}
			attachment := scopeIntentAttachment{ID: "legacy-id", Name: "legacy", Protocol: "openid-connect"}
			state := &scopeIntentProvider{defaults: []scopeIntentAttachment{attachment}, dropWrites: true}
			reconciler := scopeIntentReconciler(t, kube, scopeIntentClient(t, mock, state))
			key := client.ObjectKeyFromObject(account)
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
				t.Fatal("unconfirmed native scope state was accepted")
			}
			var secrets corev1.SecretList
			if err := kube.List(context.Background(), &secrets); err != nil || len(secrets.Items) != 0 {
				t.Fatal("credential exposed before scope confirmation", err)
			}
			var got api.HankoServiceAccount
			if err := kube.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Phase != "Error" || got.Status.SecretRef != nil || state.writes == 0 {
				t.Fatal("test did not reach the failed native scope write before secret publication")
			}
			if existing && mock.count("getSecret") != 0 {
				t.Fatal("credential recovered before scope confirmation")
			}
			state.dropWrites = false
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal("accepted native creation could not recover after scope confirmation", err)
			}
			if err := kube.List(context.Background(), &secrets); err != nil || len(secrets.Items) != 1 {
				t.Fatal("confirmed client credential was not published", err)
			}
		})
	}
}

func TestServiceAccountExplicitScopesRejectFederatedAuthentication(t *testing.T) {
	for _, scopes := range [][]string{{}, {"basic"}} {
		for _, mode := range []string{"Kubernetes", "Secret"} {
			account := &api.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "default", Generation: 2},
				Spec: api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "reader", Scopes: scopes,
					Authentication: &api.ServiceAccountAuthentication{Mode: mode}},
			}
			if mode == "Secret" {
				account.Spec.Authentication.FallbackBinding = &api.KubernetesServiceAccountAuthentication{}
			}
			kube := newFakeClient(t, account)
			reconciler := scopeIntentReconciler(t, kube, nil)
			key := client.ObjectKeyFromObject(account)
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got api.HankoServiceAccount
			if err := kube.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			condition := mapperCondition(got.Status.Conditions, "Synced")
			if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "OAuthScopesAuthenticationUnsupported" {
				t.Fatalf("unsupported grant activation was not rejected before provider access: %+v", got.Status)
			}
		}
	}
}

func scopeIntentReconciler(t *testing.T, kube client.Client, provider *keycloak.Client) *controller.HankoServiceAccountReconciler {
	t.Helper()
	return &controller.HankoServiceAccountReconciler{
		Client: kube, APIReader: kube, OwnershipReader: kube,
		Scheme: newScheme(t), Pool: keycloak.NewPool(provider), Recorder: events.NewFakeRecorder(10),
	}
}

func TestServiceAccountUnresolvedOAuthScopePreventsCreationAndReady(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new client"
		if existing {
			name = "previously ready client"
		}
		t.Run(name, func(t *testing.T) {
			mock := newMockKeycloak(t)
			account := &api.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "default", Generation: 2},
				Spec:       api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "reader", Scopes: []string{"registry:oci:missing:read"}},
			}
			if existing {
				mock.addClient("acme", "reader", "client-uuid")
				mock.ownServiceAccount(account)
				account.Status.Phase, account.Status.ObservedGeneration = "Ready", 1
			}
			kube := &scopeIntentWireClient{Client: newFakeClient(t, account)}
			state := &scopeIntentProvider{}
			reconciler := scopeIntentReconciler(t, kube, scopeIntentClient(t, mock, state))
			key := client.ObjectKeyFromObject(account)
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
				t.Fatal("unresolved scope unexpectedly reconciled")
			}
			var got api.HankoServiceAccount
			if err := kube.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			condition := mapperCondition(got.Status.Conditions, "Synced")
			if got.Status.Phase != "Error" || got.Status.ObservedGeneration != 2 || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "OAuthScopesUnresolved" {
				t.Fatalf("unresolved scope retained readiness: %+v", got.Status)
			}
			for _, operation := range []string{"create", "update", "rotateSecret", "getSecret", "createProtocolMapper"} {
				if mock.count(operation) != 0 {
					t.Fatalf("unresolved scope triggered provider operation %s", operation)
				}
			}
			var secrets corev1.SecretList
			if err := kube.List(context.Background(), &secrets); err != nil || len(secrets.Items) != 0 || state.writes != 0 {
				t.Fatal("unresolved scope exposed a credential or changed attachments", err)
			}
		})
	}
}

func TestServiceAccountScopeOmissionAndRevocationSurviveFinalizerUpdate(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "omitted scopes remain unmanaged"
		var scopes []string
		if revoke {
			name, scopes = "explicit empty scopes revoke every attachment", []string{}
		}
		t.Run(name, func(t *testing.T) {
			mock := newMockKeycloak(t)
			mock.addClient("acme", "reader", "client-uuid")
			account := &api.HankoServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "default", Generation: 2},
				Spec:       api.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "reader", Scopes: scopes},
			}
			mock.ownServiceAccount(account)
			mock.mu.Lock()
			mock.clientState["acme|client-uuid"]["serviceAccountsEnabled"] = true
			mock.clientState["acme|client-uuid"]["clientAuthenticatorType"] = "client-secret"
			mock.mu.Unlock()
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hanko-sa-reader", Namespace: "default"}, Data: map[string][]byte{"client_secret": []byte("fixture-secret")}}
			kube := &scopeIntentWireClient{Client: newFakeClient(t, account, secret)}
			attachment := scopeIntentAttachment{ID: "legacy-id", Name: "registry:oci:legacy:read", Protocol: "openid-connect"}
			state := &scopeIntentProvider{defaults: []scopeIntentAttachment{attachment}, optional: []scopeIntentAttachment{attachment}}
			reconciler := scopeIntentReconciler(t, kube, scopeIntentClient(t, mock, state))
			key := client.ObjectKeyFromObject(account)
			for range 2 {
				if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatal(err)
				}
				var got api.HankoServiceAccount
				if err := kube.Get(context.Background(), key, &got); err != nil {
					t.Fatal(err)
				}
				if got.Status.Phase != "Ready" || (got.Spec.Scopes != nil) != revoke || len(got.Spec.Scopes) != 0 {
					t.Fatalf("scope intent lost after typed controller update: phase=%s scopes=%#v", got.Status.Phase, got.Spec.Scopes)
				}
			}
			if kube.updates == 0 {
				t.Fatal("test did not exercise the typed finalizer update")
			}
			if revoke {
				if len(state.defaults) != 0 || len(state.optional) != 0 || state.writes != 2 {
					t.Fatal("explicit empty scopes did not revoke both attachment sets idempotently")
				}
			} else if state.reads != 0 || state.writes != 0 || len(state.defaults) != 1 || len(state.optional) != 1 {
				t.Fatal("omitted scopes managed native attachments")
			}
		})
	}
}
