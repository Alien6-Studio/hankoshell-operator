//go:build keycloak_integration

package controller_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRealKeycloakOrganizationReadiness(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	// Use the fixture's existing target-realm organization/group profile. No
	// additional grants or new Admin API routes are introduced by separation.
	kc := f.kc
	f.admin(http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": "organization-reader"}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "organization-app", "enabled": true, "publicClient": true}, nil)
	cid := f.client("managed", "organization-app")["id"].(string)
	f.admin(http.MethodPost, "/admin/realms/managed/clients/"+cid+"/roles", map[string]any{"name": "access"}, nil)
	idp := keycloak.IdentityProvider{Alias: "organization-idp", ProviderID: "oidc", Enabled: false, Config: map[string]string{"clientId": "organization", "authorizationUrl": "https://identity.invalid/authorize", "tokenUrl": "https://identity.invalid/token"}}
	_, err := kc.EnsureIdentityProvider(ctx, "managed", idp)
	f.requireNoError(err)
	nodes := []*api.HankoOrganization{}
	for i, name := range []string{"contract-org", "contract-child", "contract-grandchild"} {
		parent := ""
		if i > 0 {
			parent = nodes[i-1].Name
		}
		o := &api.HankoOrganization{ObjectMeta: fixtureMeta(name), Spec: api.HankoOrganizationSpec{RealmRef: "managed", Name: name, ParentRef: parent, Roles: []string{"organization-reader"}, ClientRoles: []api.OrganizationClientRoles{{Client: "organization-app", Roles: []string{"access"}}}}}
		if i == 0 {
			o.Spec.Domains = []string{"company.invalid"}
			o.Spec.IdentityProvider = idp.Alias
		}
		nodes = append(nodes, o)
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(nodes[0], nodes[1], nodes[2]).WithStatusSubresource(&api.HankoOrganization{}).Build()
	r := &controller.HankoOrganizationReconciler{Client: c, Pool: keycloak.NewPool(kc)}
	for _, o := range nodes {
		runOrganization(t, r, o)
		if o.Status.Phase != "Ready" || o.Status.PositionID != "" {
			t.Fatal("standalone requires optional projection")
		}
		requireOrganizationCondition(t, o, "Synced", "True", "Reconciled")
		requireOrganizationCondition(t, o, "Projection", "Unknown", "Disabled")
		g, err := kc.GetGroup(ctx, "managed", o.Status.GroupID)
		f.requireNoError(err)
		if !strings.HasSuffix(g.Path, "/"+o.Name) || !keycloak.GroupMatchesOwnership(g, testOrganizationOwnership(o), "") {
			t.Fatal("provider hierarchy or UID ownership differs")
		}
		var realmRoles []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/groups/"+g.ID+"/role-mappings/realm", nil, &realmRoles)
		if len(realmRoles) != 1 || realmRoles[0]["name"] != "organization-reader" {
			t.Fatal("realm role mapping differs")
		}
		var clientRoles []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/groups/"+g.ID+"/role-mappings/clients/"+cid, nil, &clientRoles)
		if len(clientRoles) != 1 || clientRoles[0]["name"] != "access" {
			t.Fatal("client role mapping differs")
		}
	}
	if nodes[2].Status.GroupPath != "/contract-org/contract-child/contract-grandchild" {
		t.Fatal("three-level hierarchy differs")
	}
	native, err := kc.GetOrganization(ctx, "managed", nodes[0].Status.OrgID)
	f.requireNoError(err)
	if native.Alias != "contract-org" || len(native.Domains) != 1 || native.Domains[0].Name != "company.invalid" {
		t.Fatal("root native semantics differ")
	}
	var links []keycloak.IdentityProvider
	f.admin(http.MethodGet, "/admin/realms/managed/organizations/"+native.ID+"/identity-providers", nil, &links)
	if len(links) != 1 || links[0].Alias != idp.Alias {
		t.Fatal("root IdP link differs")
	}
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)
		return len(events)
	}
	before := writes()
	for _, o := range nodes {
		runOrganization(t, r, o)
		if o.Status.Phase != "Ready" {
			t.Fatal("repeat reconciliation lost standalone readiness", o.Status)
		}
	}
	if writes() != before {
		t.Fatal("matching provider reconciliation mutated Keycloak")
	}
	native.Name = "provider drift"
	f.admin(http.MethodPut, "/admin/realms/managed/organizations/"+native.ID, native, nil)
	runOrganization(t, r, nodes[0])
	native, err = kc.GetOrganization(ctx, "managed", native.ID)
	f.requireNoError(err)
	if native.Name != "contract-org" {
		reasons := []string{}
		for _, c := range nodes[0].Status.Conditions {
			reasons = append(reasons, c.Type+"/"+c.Reason)
		}
		t.Fatalf("root provider drift not repaired: phase=%s reasons=%v nativeName=%q", nodes[0].Status.Phase, reasons, native.Name)
	}
	r.ProjectionMode = hankoapi.ProjectionEnabled
	p := &testOrganizationProjector{err: errors.New("sentinel-projection-token")}
	r.Positions = p
	before = writes()
	runOrganization(t, r, nodes[0])
	runOrganization(t, r, nodes[1])
	if writes() != before {
		t.Fatal("projection failure retried provider writes")
	}
	requireOrganizationCondition(t, nodes[0], "Synced", "True", "Reconciled")
	requireOrganizationCondition(t, nodes[0], "Projection", "False", "ProjectionFailed")
	if nodes[1].Status.Phase != "Pending" {
		t.Fatal("child projection dependency not separated")
	}
	requireOrganizationCondition(t, nodes[1], "Synced", "True", "Reconciled")
	requireOrganizationCondition(t, nodes[1], "Projection", "False", "ParentProjectionPending")
	p.err = nil
	for _, o := range nodes {
		runOrganization(t, r, o)
		requireOrganizationCondition(t, o, "Projection", "True", "Reconciled")
	}
	r.ProjectionMode = hankoapi.ProjectionDisabled
	beforeCalls := p.deleteCalls
	for i := len(nodes) - 1; i >= 0; i-- {
		o := nodes[i]
		f.requireNoError(c.Delete(ctx, o))
		_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)})
		f.requireNoError(err)
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), &api.HankoOrganization{}); !apierrors.IsNotFound(err) {
			t.Fatal("standalone finalizer remained", err)
		}
		if _, err := kc.GetGroup(ctx, "managed", o.Status.GroupID); !keycloak.IsNotFound(err) {
			t.Fatal("owned group survived deletion", err)
		}
	}
	if p.deleteCalls != beforeCalls {
		t.Fatal("disabled legacy PositionID caused API deletion")
	}
	if _, err := kc.GetOrganization(ctx, "managed", native.ID); !keycloak.IsNotFound(err) {
		t.Fatal("root native Organization survived deletion", err)
	}
	fixtureEqual(t, "organization identity cannot administer master", f.identityStatus("fixture-operator", f.credential, http.MethodGet, "/admin/realms/master/clients", nil), http.StatusForbidden)
}
