//go:build integration

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkAuthorizationExplanationSchema(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	rs := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Name: "explanation-schema", Namespace: "auth"}, Spec: api.HankoResourceServerSpec{RealmRef: "realm", ApplicationRef: "app", Audience: "urn:explanation-schema", Scopes: []api.AuthorizationScope{{Name: "read"}}, Permissions: []api.AuthorizationPermission{{Name: "access", Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "realm_role", Ref: "reader"}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	valid := api.AuthorizationExplanation{SourceGeneration: 1, SourcePlanHash: hash, SourceObservationHash: hash, Source: "Applied", Complete: false, Truncated: true, ExplanationHash: hash, Paths: make([]api.AuthorizationExplanationPath, 256)}
	for i := range valid.Paths {
		valid.Paths[i] = api.AuthorizationExplanationPath{Permission: "access", Resource: "invoice", Action: "read", SourceKind: "realm_role", SourceRef: "reader", Relationship: "mapped_composite_role", Ancestry: make([]string, 33), RoleChain: make([]api.AuthorizationExplanationRoleStep, 33)}
		for j := range valid.Paths[i].Ancestry {
			valid.Paths[i].Ancestry[j] = "europe"
			valid.Paths[i].RoleChain[j] = api.AuthorizationExplanationRoleStep{Kind: "realm_role", Ref: "reader"}
		}
	}
	rs.Status.AuthorizationExplanation = &valid
	if err := c.Status().Update(ctx, rs); err != nil {
		t.Fatal("bounded maximum status rejected", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(rs), rs); err != nil {
		t.Fatal(err)
	}
	if x := rs.Status.AuthorizationExplanation; x == nil || len(x.Paths) != 256 || len(x.Paths[0].Ancestry) != 33 || len(x.Paths[0].RoleChain) != 33 {
		t.Fatal("structural status pruned")
	}
	for _, test := range []struct {
		name   string
		mutate func(*api.AuthorizationExplanation)
	}{
		{"paths", func(x *api.AuthorizationExplanation) { x.Paths = append(x.Paths, x.Paths[0]) }},
		{"ancestry", func(x *api.AuthorizationExplanation) { x.Paths[0].Ancestry = append(x.Paths[0].Ancestry, "extra") }},
		{"role-chain", func(x *api.AuthorizationExplanation) {
			x.Paths[0].RoleChain = append(x.Paths[0].RoleChain, x.Paths[0].RoleChain[0])
		}},
		{"source", func(x *api.AuthorizationExplanation) { x.Source = "Desired" }},
		{"hash", func(x *api.AuthorizationExplanation) { x.ExplanationHash = "caller-supplied-authority" }},
		{"principal", func(x *api.AuthorizationExplanation) { x.Paths[0].SourceKind = "user" }},
	} {
		candidate := rs.DeepCopy()
		test.mutate(candidate.Status.AuthorizationExplanation)
		if err := c.Status().Update(ctx, candidate); !apierrors.IsInvalid(err) {
			t.Fatal("unsafe status admitted", test.name, err)
		}
	}
}
