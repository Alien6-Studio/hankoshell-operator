//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Real API-server status, hierarchy ordering and finalizer behavior; native
// provider semantics are independently qualified by the HTTPS Keycloak suite.
func checkOrganizationStandaloneStatus(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	nodes := []*api.HankoOrganization{}
	groups := map[string]keycloak.Group{}
	path := ""
	for i, name := range []string{"standalone-root", "standalone-child", "standalone-grandchild"} {
		parent := ""
		if i > 0 {
			parent = nodes[i-1].Name
		}
		path += "/" + name
		o := &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}, Spec: api.HankoOrganizationSpec{RealmRef: "organization-realm", Name: name, ParentRef: parent}}
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
		groups[name] = keycloak.Group{ID: name, Name: name, Path: path, Attributes: map[string][]string{"hanko.sh/organization-name": {name}, "hanko.sh/organization-namespace": {"auth"}, "hanko.sh/organization-uid": {string(o.UID)}}}
		nodes = append(nodes, o)
	}
	native := &keycloak.Organization{ID: "native-root", Name: nodes[0].Name, Alias: nodes[0].Name, Enabled: true, Attributes: groups[nodes[0].Name].Attributes}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
		case r.URL.Path == "/admin/realms/organization-realm":
			_ = json.NewEncoder(w).Encode(map[string]any{"realm": "organization-realm", "organizationsEnabled": true})
		case strings.Contains(r.URL.Path, "/group-by-path/"):
			path := "/" + strings.SplitN(r.URL.Path, "/group-by-path/", 2)[1]
			for _, g := range groups {
				if g.Path == path {
					_ = json.NewEncoder(w).Encode(g)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.Contains(r.URL.Path, "/groups/"):
			id := strings.SplitN(r.URL.Path, "/groups/", 2)[1]
			if strings.HasSuffix(id, "/children") {
				id = strings.TrimSuffix(id, "/children")
				children := []keycloak.Group{}
				parent := groups[id]
				for _, g := range groups {
					if strings.HasPrefix(g.Path, parent.Path+"/") {
						children = append(children, g)
					}
				}
				_ = json.NewEncoder(w).Encode(children)
				return
			}
			g, ok := groups[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodDelete {
				delete(groups, id)
				w.WriteHeader(http.StatusNoContent)
			} else {
				_ = json.NewEncoder(w).Encode(g)
			}
		case strings.HasSuffix(r.URL.Path, "/organizations"):
			all := []keycloak.Organization{}
			if native != nil {
				all = append(all, *native)
			}
			_ = json.NewEncoder(w).Encode(all)
		case strings.HasSuffix(r.URL.Path, "/organizations/native-root"):
			if native == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodDelete {
				native = nil
				w.WriteHeader(http.StatusNoContent)
			} else {
				_ = json.NewEncoder(w).Encode(native)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	r := &controller.HankoOrganizationReconciler{Client: c, Pool: keycloak.NewPool(keycloak.New(server.URL, "fixture-client", "fixture-secret", keycloak.WithInsecureHTTP()))}
	reconcile := func(o *api.HankoOrganization) {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), o); err != nil {
			t.Fatal(err)
		}
	}
	reconcile(nodes[1])
	if nodes[1].Status.Phase != "Pending" {
		t.Fatal("child did not await provider parent")
	}
	for _, o := range nodes {
		reconcile(o)
		if o.Status.Phase != "Ready" || o.Status.PositionID != "" || o.Status.GroupID == "" || o.Status.ObservedGeneration != o.Generation {
			t.Fatal("standalone status pruned or inconsistent", o.Status)
		}
		want := map[string]string{"Synced": "Reconciled", "Projection": "Disabled"}
		for _, condition := range o.Status.Conditions {
			if reason, ok := want[condition.Type]; ok {
				if condition.Reason != reason || condition.ObservedGeneration != o.Generation || (condition.Type == "Projection" && condition.Status != metav1.ConditionUnknown) || (condition.Type == "Synced" && condition.Status != metav1.ConditionTrue) {
					t.Fatal("condition round-trip differs", condition)
				}
				delete(want, condition.Type)
			}
		}
		if len(want) != 0 {
			t.Fatal("conditions missing from schema")
		}
		if o.Spec.Name != o.Name || o.Spec.RealmRef != "organization-realm" {
			t.Fatal("status processing mutated spec")
		}
	}
	for i := len(nodes) - 1; i >= 0; i-- {
		o := nodes[i]
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), &api.HankoOrganization{}); !apierrors.IsNotFound(err) {
			t.Fatal("finalizer did not complete", err)
		}
	}
	if len(groups) != 0 || native != nil {
		t.Fatal("owned provider fixture cleanup incomplete")
	}
}
