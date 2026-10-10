package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDeriveSlug(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "simple lowercase", in: "demo", want: "demo"},
		{name: "uppercase folded", in: "Demo", want: "demo"},
		{name: "spaces to hyphens", in: "Demo Org", want: "demo-org"},
		{name: "collapse separators", in: "Demo   Org", want: "demo-org"},
		{name: "trim leading and trailing", in: "  Demo!  ", want: "demo"},
		{name: "punctuation runs collapse", in: "A6 / Trunx", want: "a6-trunx"},
		{name: "digits kept", in: "team42", want: "team42"},
		{name: "already slug", in: "alien6-demo", want: "alien6-demo"},
		{name: "empty", in: "", want: ""},
		{name: "only separators", in: "  --  ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveSlug(tt.in); got != tt.want {
				t.Errorf("deriveSlug(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestOrganizationParentSeparatesProviderAndProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_, _ = w.Write([]byte(`{"access_token":"fixture","expires_in":300}`))
			return
		}
		if req.Method != http.MethodGet || req.URL.Path != "/admin/realms/realm/group-by-path/Root" {
			t.Error("unexpected parent operation")
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write([]byte(`{"id":"group-root","name":"Root","path":"/Root"}`))
	}))
	defer server.Close()
	parent := &hankoshv1alpha1.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "auth", UID: "root-uid", Generation: 2}, Spec: hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "realm", Name: "Root"}, Status: hankoshv1alpha1.HankoOrganizationStatus{GroupID: "forged-status-id", GroupPath: "/Forged", Phase: "Error", Conditions: []metav1.Condition{{Type: "Synced", Status: metav1.ConditionTrue, ObservedGeneration: 2}}}}
	child := &hankoshv1alpha1.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "auth"}, Spec: hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "realm", Name: "Child", ParentRef: "root"}}
	r := &HankoOrganizationReconciler{Client: controllerTestClient(controllerTestScheme(t), parent), Pool: keycloak.NewPool(keycloak.New(server.URL, "fixture", "secret", keycloak.WithInsecureHTTP()))}
	id, path, err := r.resolveProviderParent(context.Background(), child)
	if err != nil || id != "group-root" || path != "/Root" {
		t.Fatal("provider hierarchy depended on projection", err)
	}
	if _, err := r.resolveProjectionParent(context.Background(), child); err == nil {
		t.Fatal("missing projection accepted")
	}
	parent.Status.PositionID = "legacy-position"
	r.Client = controllerTestClient(controllerTestScheme(t), parent)
	if _, err := r.resolveProjectionParent(context.Background(), child); err == nil {
		t.Fatal("last-known projection identity accepted as current readiness")
	}
	parent.Status.Conditions = append(parent.Status.Conditions, metav1.Condition{Type: "Projection", Status: metav1.ConditionTrue, ObservedGeneration: 2})
	r.Client = controllerTestClient(controllerTestScheme(t), parent)
	if id, err := r.resolveProjectionParent(context.Background(), child); err != nil || id != "legacy-position" {
		t.Fatal("ready projection rejected", err)
	}
	parent.Generation = 3
	r.Client = controllerTestClient(controllerTestScheme(t), parent)
	if _, _, err := r.resolveProviderParent(context.Background(), child); err == nil {
		t.Fatal("stale parent provider evidence accepted")
	}
}

func TestOrgSlug(t *testing.T) {
	tests := []struct {
		name string
		spec hankoshv1alpha1.HankoOrganizationSpec
		want string
	}{
		{
			name: "explicit slug wins",
			spec: hankoshv1alpha1.HankoOrganizationSpec{Name: "Demo Org", Slug: "demo"},
			want: "demo",
		},
		{
			name: "derived from name when empty",
			spec: hankoshv1alpha1.HankoOrganizationSpec{Name: "Demo Org"},
			want: "demo-org",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org := &hankoshv1alpha1.HankoOrganization{Spec: tt.spec}
			if got := orgSlug(org); got != tt.want {
				t.Errorf("orgSlug(%+v) = %q, want %q", tt.spec, got, tt.want)
			}
		})
	}
}
