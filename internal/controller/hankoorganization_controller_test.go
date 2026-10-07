package controller

import (
	"context"
	"testing"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
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

func TestResolveParentRequiresBothProjections(t *testing.T) {
	parent := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "auth"},
		Status: hankoshv1alpha1.HankoOrganizationStatus{
			GroupID: "group-root", GroupPath: "/Root",
		},
	}
	child := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "auth"},
		Spec:       hankoshv1alpha1.HankoOrganizationSpec{ParentRef: "root"},
	}
	reconciler := &HankoOrganizationReconciler{Client: controllerTestClient(controllerTestScheme(t), parent)}
	if _, _, _, err := reconciler.resolveParent(context.Background(), child); err == nil {
		t.Fatal("expected a group-only parent to remain pending")
	}

	parent.Status.PositionID = "pos_root"
	reconciler = &HankoOrganizationReconciler{Client: controllerTestClient(controllerTestScheme(t), parent)}
	groupID, groupPath, positionID, err := reconciler.resolveParent(context.Background(), child)
	if err != nil || groupID != "group-root" || groupPath != "/Root" || positionID != "pos_root" {
		t.Fatalf("resolveParent() = %q, %q, %q, %v", groupID, groupPath, positionID, err)
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
