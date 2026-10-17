package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type realmInventoryReader struct {
	client.Reader
	list func(client.ObjectList, ...client.ListOption) error
	get  func(client.Object) error
}

func (r realmInventoryReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if r.list != nil {
		return r.list(list, options...)
	}
	return r.Reader.List(ctx, list, options...)
}

func (r realmInventoryReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if r.get != nil {
		return r.get(object)
	}
	return r.Reader.Get(ctx, key, object, options...)
}

func realmDeletionFixture(t *testing.T) (*api.HankoRealm, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth", UID: "realm-owner", Generation: 3,
		DeletionTimestamp: &now, Finalizers: []string{realmFinalizerName}}}
	return realm, fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.HankoRealm{}).WithObjects(realm).Build()
}

func TestRealmDeletionInventoryCoversEveryRealmReference(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for gvk, value := range scheme.AllKnownTypes() {
		if gvk.GroupVersion() != api.GroupVersion {
			continue
		}
		spec, present := value.FieldByName("Spec")
		if !present || spec.Type.Kind() != reflect.Struct {
			continue
		}
		if field, present := spec.Type.FieldByName("RealmRef"); present && strings.Split(field.Tag.Get("json"), ",")[0] == "realmRef" {
			kinds = append(kinds, gvk.Kind)
		}
	}
	slices.Sort(kinds)
	expected := realmDependentKinds()
	slices.Sort(expected)
	if !slices.Equal(kinds, expected) {
		t.Fatalf("realmRef kinds=%v, deletion inventory=%v", kinds, expected)
	}
}

func TestRealmDeletionUsesLiveInventoryForEveryKind(t *testing.T) {
	for _, kind := range realmDependentKinds() {
		t.Run(kind, func(t *testing.T) {
			realm, live := realmDeletionFixture(t)
			object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.GroupVersion.String(), "kind": kind,
				"metadata": map[string]any{"name": "private-dependent-sentinel", "namespace": realm.Namespace,
					"labels": map[string]any{ImportedByLabel: "observed"}}, "spec": map[string]any{"realmRef": realm.Name}}}
			if err := live.Create(t.Context(), object); err != nil {
				t.Fatal(err)
			}
			_, stale := realmDeletionFixture(t)
			r := &HankoRealmReconciler{Client: stale, APIReader: live}
			// A nil provider proves the guard returns before any provider access.
			result, err := r.reconcileRealmDeletion(t.Context(), realm, nil, false)
			if err != nil || result.RequeueAfter < 30*time.Second || realm.Status.Phase != "Reconciling" || conditionReason(realm.Status.Conditions, "Synced") != "DependenciesRemain" {
				t.Fatalf("live %s must block cleanup with a bounded retry: %v, %v", kind, result, err)
			}
			for _, condition := range realm.Status.Conditions {
				if strings.Contains(condition.Message, "private-dependent-sentinel") {
					t.Fatal("dependency names leaked in public status")
				}
			}
		})
	}
}

func TestRealmDeletionInventoryRequiresEveryCompletePage(t *testing.T) {
	for _, scenario := range []string{"last-page-dependent", "page-error", "repeated-token", "missing-continuation", "malformed-reference", "wrong-namespace"} {
		t.Run(scenario, func(t *testing.T) {
			realm, live := realmDeletionFixture(t)
			calls := 0
			reader := realmInventoryReader{Reader: live, list: func(list client.ObjectList, options ...client.ListOption) error {
				page := list.(*unstructured.UnstructuredList)
				if page.GetKind() != "HankoTenantList" {
					return live.List(t.Context(), list, options...)
				}
				settings := (&client.ListOptions{}).ApplyOptions(options)
				if settings.Namespace != realm.Namespace || settings.Limit != 200 || calls > 0 && settings.Continue != "opaque-next" {
					t.Fatalf("unscoped or incomplete pagination: %+v", settings)
				}
				calls++
				if calls == 1 {
					page.SetContinue("opaque-next")
					return nil
				}
				page.Items = []unstructured.Unstructured{{Object: map[string]any{
					"metadata": map[string]any{"namespace": realm.Namespace}, "spec": map[string]any{"realmRef": realm.Name}}}}
				switch scenario {
				case "page-error":
					return errors.New("API unavailable")
				case "repeated-token":
					page.SetContinue("opaque-next")
				case "missing-continuation":
					remaining := int64(1)
					page.SetRemainingItemCount(&remaining)
				case "malformed-reference":
					page.Items[0].Object["spec"] = map[string]any{"realmRef": []any{"acme"}}
				case "wrong-namespace":
					page.Items[0].SetNamespace("foreign")
				}
				return nil
			}}
			r := &HankoRealmReconciler{Client: live, APIReader: reader}
			counts, err := r.realmDeletionBlockers(t.Context(), realm)
			if scenario == "last-page-dependent" {
				if err != nil || counts["HankoTenant"] != 1 {
					t.Fatalf("last page was not counted: %v, %v", counts, err)
				}
			} else if err == nil {
				t.Fatalf("incomplete inventory accepted: %s", scenario)
			}
		})
	}
}

func TestRealmDeletionRefusesEveryUnreadableKind(t *testing.T) {
	for _, kind := range realmDependentKinds() {
		t.Run(kind, func(t *testing.T) {
			realm, live := realmDeletionFixture(t)
			reader := realmInventoryReader{Reader: live, list: func(list client.ObjectList, options ...client.ListOption) error {
				if list.GetObjectKind().GroupVersionKind().Kind == kind+"List" {
					return errors.New("forbidden dependency read")
				}
				return live.List(t.Context(), list, options...)
			}}
			r := &HankoRealmReconciler{Client: live, APIReader: reader}
			if _, err := r.reconcileRealmDeletion(t.Context(), realm, nil, false); err == nil {
				t.Fatal("unreadable live inventory authorized provider access")
			}
		})
	}
}

func TestRealmDeletionWaitDoesNotRewriteUnchangedStatus(t *testing.T) {
	realm, live := realmDeletionFixture(t)
	r := &HankoRealmReconciler{Client: live, APIReader: live}
	if err := live.Get(t.Context(), client.ObjectKeyFromObject(realm), realm); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{"HankoRole": 201}
	if _, err := r.waitForRealmDependents(t.Context(), realm, counts); err != nil {
		t.Fatal(err)
	}
	if err := live.Get(t.Context(), client.ObjectKeyFromObject(realm), realm); err != nil {
		t.Fatal(err)
	}
	version := realm.ResourceVersion
	if _, err := r.waitForRealmDependents(t.Context(), realm, counts); err != nil {
		t.Fatal(err)
	}
	if err := live.Get(t.Context(), client.ObjectKeyFromObject(realm), realm); err != nil || realm.ResourceVersion != version {
		t.Fatalf("unchanged dependency wait rewrote status: %v", err)
	}
}

func TestRealmPrimaryReadCannotFallBackToStaleCache(t *testing.T) {
	realm, cached := realmDeletionFixture(t)
	reader := realmInventoryReader{Reader: cached, get: func(client.Object) error { return errors.New("API unavailable") }}
	r := &HankoRealmReconciler{Client: cached, APIReader: reader}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)}); err == nil {
		t.Fatal("unavailable authoritative parent read fell back to cache")
	}
}

func TestRealmDeletionRechecksAuthorityAfterProviderPreflight(t *testing.T) {
	for _, scenario := range []string{"Observe", "tenant", "connection", "generation", "UID", "approval", "not-deleting", "no-finalizer", "API-error"} {
		t.Run(scenario, func(t *testing.T) {
			realm, live := realmDeletionFixture(t)
			current := realm.DeepCopy()
			switch scenario {
			case "Observe":
				current.Labels = map[string]string{ImportedByLabel: "import"}
			case "tenant", "connection":
				current.Labels = map[string]string{scenario: "changed"}
			case "generation":
				current.Generation++
			case "UID":
				current.UID = "replacement"
			case "approval":
				current.Annotations = map[string]string{"approval": "changed"}
			case "not-deleting":
				current.DeletionTimestamp = nil
			case "no-finalizer":
				current.Finalizers = nil
			}
			read := false
			reader := realmInventoryReader{Reader: live, get: func(object client.Object) error {
				read = true
				if scenario == "API-error" {
					return errors.New("API unavailable")
				}
				current.DeepCopyInto(object.(*api.HankoRealm))
				return nil
			}}
			deletes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.Method {
				case http.MethodPost:
					_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
				case http.MethodGet:
					if read {
						t.Error("authority read must occur after provider preflight")
					}
					_ = json.NewEncoder(w).Encode(keycloak.Realm{ID: "realm-id", RealmName: realm.Name})
				case http.MethodDelete:
					deletes++
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()
			r := &HankoRealmReconciler{Client: live, APIReader: reader}
			kc := keycloak.New(server.URL, "id", "secret", keycloak.WithInsecureHTTP())
			if _, err := r.reconcileRealmDeletion(t.Context(), realm, kc, false); err == nil || deletes != 0 || !read {
				t.Fatalf("stale authority allowed deletion: read=%v deletes=%d err=%v", read, deletes, err)
			}
		})
	}
}

func TestRealmDeletionRecoversAfterAcceptedDeleteLosesAcknowledgement(t *testing.T) {
	realm, live := realmDeletionFixture(t)
	exists, accepted := true, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
		case !exists:
			w.WriteHeader(http.StatusNotFound)
		case req.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(keycloak.Realm{ID: "realm-id", RealmName: realm.Name})
		case req.Method == http.MethodDelete:
			exists = false
			accepted++
			connection, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		}
	}))
	defer server.Close()
	r := &HankoRealmReconciler{Client: live, APIReader: live}
	kc := keycloak.New(server.URL, "id", "secret", keycloak.WithInsecureHTTP())
	if _, err := r.reconcileRealmDeletion(t.Context(), realm, kc, false); err == nil {
		t.Fatal("dropped acknowledgement did not surface as an incomplete attempt")
	}
	if _, err := r.reconcileRealmDeletion(t.Context(), realm, kc, false); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 || !apierrors.IsNotFound(live.Get(t.Context(), client.ObjectKeyFromObject(realm), &api.HankoRealm{})) {
		t.Fatalf("cleanup did not resume exactly once: accepted=%d", accepted)
	}
}
