//go:build integration

package v1alpha1_test

import (
	"context"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkDelegationAdmission(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	base := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Namespace: "auth"}, Spec: api.HankoResourceServerSpec{
		RealmRef: "realm", ApplicationRef: "api", Scopes: []api.AuthorizationScope{{Name: "read"}},
		Resources: []api.AuthorizationResource{{Name: "invoice", Scopes: []string{"read"}}},
		Permissions: []api.AuthorizationPermission{{Name: "delegated-read", Resources: []string{"invoice"}, Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "realm_role", Ref: "reader"}},
			Delegation: &api.AuthorizationDelegation{Actor: api.AuthorizationDelegationIdentity{Kind: "service_account", Ref: "actor"}, Subject: api.AuthorizationDelegationIdentity{Kind: "application", Ref: "subject"}},
		}},
	}}
	ptr := func(value int32) *int32 { return &value }
	for _, tc := range []struct {
		name    string
		invalid bool
		edit    func(*api.AuthorizationPermission)
	}{
		{"defaults", false, func(*api.AuthorizationPermission) {}},
		{"explicit", false, func(p *api.AuthorizationPermission) {
			p.Delegation.MaxDepth, p.Delegation.MaxTTLSeconds = ptr(4), ptr(600)
		}},
		{"zero-depth", true, func(p *api.AuthorizationPermission) { p.Delegation.MaxDepth = ptr(0) }},
		{"depth-overflow", true, func(p *api.AuthorizationPermission) { p.Delegation.MaxDepth = ptr(5) }},
		{"zero-lifetime", true, func(p *api.AuthorizationPermission) { p.Delegation.MaxTTLSeconds = ptr(0) }},
		{"lifetime-overflow", true, func(p *api.AuthorizationPermission) { p.Delegation.MaxTTLSeconds = ptr(601) }},
		{"same-identity", true, func(p *api.AuthorizationPermission) { p.Delegation.Subject = p.Delegation.Actor }},
		{"human-identity", true, func(p *api.AuthorizationPermission) { p.Delegation.Subject.Kind = "human" }},
		{"raw-client", true, func(p *api.AuthorizationPermission) { p.Delegation.Actor.Ref = "https://foreign.example/client" }},
		{"cross-namespace", true, func(p *api.AuthorizationPermission) { p.Delegation.Actor.Ref = "other/actor" }},
		{"missing-actor", true, func(p *api.AuthorizationPermission) { p.Delegation.Actor = api.AuthorizationDelegationIdentity{} }},
		{"implicit-resources", true, func(p *api.AuthorizationPermission) { p.Resources = nil }},
		{"unknown-resource", true, func(p *api.AuthorizationPermission) { p.Resources = []string{"other"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := base.DeepCopy()
			obj.Name = "delegation-" + tc.name
			obj.Spec.Audience = "urn:" + obj.Name
			tc.edit(&obj.Spec.Permissions[0])
			err := c.Create(ctx, obj)
			if tc.invalid {
				if !apierrors.IsInvalid(err) {
					t.Fatal("invalid delegation admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var stored api.HankoResourceServer
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), &stored); err != nil {
				t.Fatal(err)
			}
			d := stored.Spec.Permissions[0].Delegation
			if d == nil || d.MaxDepth == nil || d.MaxTTLSeconds == nil || d.Actor.Ref != "actor" || d.Subject.Ref != "subject" {
				t.Fatal("delegation pruned or defaults missing")
			}
			if tc.name == "defaults" && (*d.MaxDepth != 1 || *d.MaxTTLSeconds != 120) {
				t.Fatal("unexpected delegation defaults")
			}
			stored.Status.Capabilities.BoundedDelegation = false
			stored.Status.Phase = "Error"
			if err := c.Status().Update(ctx, &stored); err != nil {
				t.Fatal(err)
			}
			legacy := client.RawPatch(types.MergePatchType, []byte(`{"status":{"capabilities":{"boundedDelegation":null}}}`))
			if err := c.Status().Patch(ctx, &stored, legacy); err != nil {
				t.Fatal("legacy capability snapshot rejected", err)
			}
			stored.Spec.Permissions[0].Delegation.MaxDepth = ptr(5)
			if err := c.Update(ctx, &stored); !apierrors.IsInvalid(err) {
				t.Fatal("update bypassed delegation bounds", err)
			}
		})
	}
}
