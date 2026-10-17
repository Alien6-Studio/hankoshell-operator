//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type realmSelectorReader struct {
	client.Reader
	t     *testing.T
	lists int
}

func (r *realmSelectorReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	opts := (&client.ListOptions{}).ApplyOptions(options)
	if opts.AsListOptions().FieldSelector != "spec.realmRef=ownership-realm" || opts.Namespace != "auth" {
		r.t.Fatal("ownership list omitted realm selector or namespace")
	}
	r.lists++
	return r.Reader.List(ctx, list, options...)
}

func checkRealmOwnershipSelectors(t *testing.T, ctx context.Context, admin client.Client) {
	t.Helper()
	owner := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "selector-owner", Namespace: "auth"},
		Spec: api.HankoApplicationSpec{RealmRef: "ownership-realm", ClientID: " portal ", Type: "spa"}}
	if err := admin.Create(ctx, owner); err != nil {
		t.Fatal(err)
	}
	// Creation timestamps have second precision. Ensure the fixture's incumbent
	// is older so the deterministic winner does not depend on random server UIDs.
	time.Sleep(1100 * time.Millisecond)
	account := &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "selector-account", Namespace: "auth"},
		Spec: api.HankoServiceAccountSpec{RealmRef: "ownership-realm", ClientID: "portal"}}
	if err := admin.Create(ctx, account); err != nil {
		t.Fatal(err)
	}
	unrelated := owner.DeepCopy()
	unrelated.ObjectMeta = metav1.ObjectMeta{Name: "selector-other-realm", Namespace: "auth"}
	unrelated.Spec.RealmRef = "unrelated-realm"
	if err := admin.Create(ctx, unrelated); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, object := range []client.Object{owner, account, unrelated} {
			if err := admin.Delete(ctx, object); err != nil {
				t.Error(err)
			}
		}
	}()
	var applications api.HankoApplicationList
	if err := admin.List(ctx, &applications, client.InNamespace("auth"), client.MatchingFields{"spec.realmRef": "ownership-realm"}); err != nil || len(applications.Items) != 1 || applications.Items[0].Name != owner.Name {
		t.Fatalf("server did not filter applications by realm: %v", err)
	}
	var accounts api.HankoServiceAccountList
	if err := admin.List(ctx, &accounts, client.InNamespace("auth"), client.MatchingFields{"spec.realmRef": "ownership-realm"}); err != nil || len(accounts.Items) != 1 {
		t.Fatalf("server did not filter service accounts by realm: %v", err)
	}
	providerRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerRequests++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	reader := &realmSelectorReader{Reader: admin, t: t}
	reconciler := &controller.HankoServiceAccountReconciler{Client: admin, OwnershipReader: reader,
		Pool: keycloak.NewPool(keycloak.New(server.URL, "operator", "unused-fixture", keycloak.WithInsecureHTTP()))}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "auth", Name: account.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(account), account); err != nil {
		t.Fatal(err)
	}
	conflict := false
	for _, condition := range account.Status.Conditions {
		if condition.Type == "Synced" && condition.Status == metav1.ConditionFalse && condition.Reason == "OwnershipConflict" {
			conflict = true
		}
	}
	if account.Status.Phase != "Error" || !conflict || reader.lists != 2 || providerRequests != 0 {
		t.Fatal("realm selector hid a whitespace client alias or conflict reached the provider")
	}
	// A realm edit must affect the very next uncached list. No prior list or
	// selector result grants authority over an object that moved away.
	owner.Spec.RealmRef = "moved-realm"
	if err := admin.Update(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := admin.List(ctx, &applications, client.InNamespace("auth"), client.MatchingFields{"spec.realmRef": "ownership-realm"}); err != nil || len(applications.Items) != 0 {
		t.Fatalf("realm selector returned stale ownership candidates: %v", err)
	}
}

// The live API must page beyond 200 children even when the controller cache
// claims there are no children. No provider request is authorized by that cache.
type emptyRealmInventoryCache struct{ client.Client }

func (c emptyRealmInventoryCache) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return nil
}

func checkRealmDeletionInventory(t *testing.T, ctx context.Context, admin client.Client) {
	t.Helper()
	realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "delete-inventory", Namespace: "auth", Finalizers: []string{"hanko.sh/realm-cleanup"}}}
	if err := admin.Create(ctx, realm); err != nil {
		t.Fatal(err)
	}
	for index := range 201 {
		name := fmt.Sprintf("delete-role-%03d", index)
		role := &api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", Labels: map[string]string{"hanko-fixture": "delete-inventory"}}, Spec: api.HankoRoleSpec{RealmRef: realm.Name, Name: name}}
		if err := admin.Create(ctx, role); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := admin.DeleteAllOf(ctx, &api.HankoRole{}, client.InNamespace("auth"), client.MatchingLabels{"hanko-fixture": "delete-inventory"}); err != nil {
			t.Error(err)
		}
	}()
	if err := admin.Delete(ctx, realm); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	reconciler := &controller.HankoRealmReconciler{Client: emptyRealmInventoryCache{admin}, APIReader: admin,
		Pool: keycloak.NewPool(keycloak.New(server.URL, "id", "secret", keycloak.WithInsecureHTTP()))}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)})
	if err != nil || result.RequeueAfter < 30*time.Second || calls != 0 {
		t.Fatalf("incomplete inventory authorized provider access: result=%v err=%v calls=%d", result, err, calls)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(realm), realm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range realm.Status.Conditions {
		if c.Type == "Synced" && c.Status == metav1.ConditionFalse && c.Reason == "DependenciesRemain" && strings.Contains(c.Message, "HankoRole:201") {
			found = true
		}
	}
	if realm.Status.Phase != "Reconciling" || !found {
		t.Fatal("paginated live dependency evidence missing")
	}
}
