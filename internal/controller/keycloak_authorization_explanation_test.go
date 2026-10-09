//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func requireExplanation(t *testing.T, q *reconciledOrganizationFixture, source string, complete bool) *api.AuthorizationExplanation {
	t.Helper()
	x := q.server.Status.AuthorizationExplanation
	if x == nil || x.Source != source || x.Complete != complete || x.SourceGeneration != q.server.Generation || x.SourcePlanHash != q.server.Status.EvaluatedPlanHash || x.ExplanationHash == "" || x.SourceObservationHash == "" {
		t.Fatalf("structural explanation source/proof differs: explanation=%+v evaluated=%s conditions=%v findings=%v", x, q.server.Status.EvaluatedPlanHash, q.server.Status.Conditions, q.server.Status.Findings)
	}
	bytes, _ := json.Marshal(q.server.Status)
	for _, sentinel := range append(q.experiment.f.secrets, "Disposable", "europe@example.test", q.experiment.users["europe"]) {
		if sentinel != "" && strings.Contains(string(bytes), sentinel) {
			t.Fatal("subject/secret exported in status")
		}
	}
	return x
}
func explanationPath(x *api.AuthorizationExplanation, kind, ref, organization, relationship string) *api.AuthorizationExplanationPath {
	for _, p := range x.Paths {
		if p.SourceKind == kind && p.SourceRef == ref && p.OrganizationRef == organization && p.Relationship == relationship {
			return &p
		}
	}
	return nil
}
func TestRealKeycloakAuthorizationExplanation(t *testing.T) {
	q := newReconciledOrganizationFixture(t)
	e, f := q.experiment, q.experiment.f
	f.requireNoError(q.reconcile())
	x := requireExplanation(t, q, "Applied", true)
	if len(x.Paths) != 1 || explanationPath(x, "organization", "europe", "europe", "direct") == nil {
		t.Fatal("direct structural path not observed")
	}
	e.decision("europe", "invoice#read", true)
	e.decision("france", "invoice#read", false)
	q.server.Spec.Permissions[0].Principals[0].IncludeDescendants = true
	q.update()
	x = requireExplanation(t, q, "Applied", true)
	if len(x.Paths) != 4 {
		t.Fatal("declared descendant explanation count differs")
	}
	p := explanationPath(x, "organization", "europe", "paris", "descendant")
	if p == nil || !slices.Equal(p.Ancestry, []string{"europe", "france", "paris"}) {
		t.Fatal("declared ancestry not explained")
	}
	for _, ref := range []string{"external", "europe-sibling"} {
		for _, p := range x.Paths {
			if p.OrganizationRef == ref {
				t.Fatal("foreign/prefix child included")
			}
		}
	}
	e.decision("paris", "invoice#read", true)
	e.decision("external", "invoice#read", false)
	e.decision("prefix", "invoice#read", false)
	// Declaration labels do not prove these role edges: bootstrap provider writes
	// create mappings/composites, while the constrained actor reads them.
	for _, name := range []string{"invoice-reader", "finance-user"} {
		f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": name}, nil)
		f.requireNoError(q.client.Create(context.Background(), &api.HankoRole{ObjectMeta: fixtureMeta(name), Spec: api.HankoRoleSpec{RealmRef: "managed", Name: name}}))
	}
	var reader, finance map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/roles/invoice-reader", nil, &reader)
	f.admin(http.MethodGet, "/admin/realms/managed/roles/finance-user", nil, &finance)
	f.admin(http.MethodPost, "/admin/realms/managed/roles/finance-user/composites", []map[string]any{reader}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Europe"]+"/role-mappings/realm", []map[string]any{reader, finance}, nil)
	// Directly mapped client role -> realm role composite.
	cid := f.client("managed", "orgauth-billing")["id"].(string)
	f.admin(http.MethodPost, "/admin/realms/managed/clients/"+cid+"/roles", map[string]any{"name": "client-finance"}, nil)
	var cr map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/clients/"+cid+"/roles/client-finance", nil, &cr)
	f.admin(http.MethodPost, "/admin/realms/managed/clients/"+cid+"/roles/client-finance/composites", []map[string]any{reader}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Europe"]+"/role-mappings/clients/"+cid, []map[string]any{cr}, nil)
	node := q.nodes["europe"]
	f.requireNoError(q.client.Get(context.Background(), client.ObjectKeyFromObject(node), node))
	node.Spec.Roles = []string{"invoice-reader", "finance-user"}
	node.Spec.ClientRoles = []api.OrganizationClientRoles{{Client: "orgauth-billing", Roles: []string{"client-finance"}}}
	node.Generation++
	f.requireNoError(q.client.Update(context.Background(), node))
	runOrganization(t, q.organizations, node)
	actor, _ := f.serviceClient("explanation-operator")
	f.grantClientRoles("explanation-operator", "managed", []string{"manage-clients", "view-users", "view-realm"})
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(actor) }
	q.server.Spec.Permissions[0].Principals = append(q.server.Spec.Permissions[0].Principals, api.AuthorizationPrincipal{Kind: "realm_role", Ref: "invoice-reader"})
	q.update()
	x = requireExplanation(t, q, "Applied", true)
	for _, rel := range []string{"generic", "mapped_role", "mapped_composite_role", "mapped_client_role"} {
		org := "europe"
		if rel == "generic" {
			org = ""
		}
		path := explanationPath(x, "realm_role", "invoice-reader", org, rel)
		if path == nil {
			t.Fatal("role provenance alternative missing", rel)
		}
		if rel == "mapped_composite_role" && len(path.RoleChain) != 2 {
			t.Fatal("provider composite chain lost")
		}
	}
	e.decision("france", "invoice#read", true)
	before := q.writes()
	hash := x.ExplanationHash
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "explanation idempotent writes", q.writes(), before)
	fixtureEqual(t, "explanation idempotent hash", q.server.Status.AuthorizationExplanation.ExplanationHash, hash)
	// Optional view-users disappears; role-only provider reconciliation still
	// succeeds with manage-clients + view-realm. Explanation alone is incomplete.
	without, _ := f.serviceClient("explanation-no-provenance")
	f.grantClientRoles("explanation-no-provenance", "managed", []string{"manage-clients", "view-realm"})
	q.server.Spec.Permissions[0].Principals = q.server.Spec.Permissions[0].Principals[1:]
	q.update()
	before = q.writes()
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(without) }
	f.requireNoError(q.reconcile())
	x = requireExplanation(t, q, "Applied", false)
	fixtureEqual(t, "optional provenance failure induced no writes", q.writes(), before)
	synced, explained := false, false
	for _, c := range q.server.Status.Conditions {
		synced = synced || (c.Type == "Synced" && c.Status == "True")
		explained = explained || (c.Type == "AuthorizationExplained" && c.Status == "False")
	}
	if !synced || !explained || explanationPath(x, "realm_role", "invoice-reader", "", "generic") == nil {
		t.Fatal("provenance became authorization availability dependency")
	}
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(actor) }
	f.requireNoError(q.reconcile())
	requireExplanation(t, q, "Applied", true)
	// Remove a composite only at the provider; declaration cannot fabricate it.
	f.admin(http.MethodDelete, "/admin/realms/managed/roles/finance-user/composites", []map[string]any{reader}, nil)
	before = q.writes()
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "provider composite read-only refresh", q.writes(), before)
	x = requireExplanation(t, q, "Applied", true)
	if explanationPath(x, "realm_role", "invoice-reader", "europe", "mapped_composite_role") != nil {
		t.Fatal("YAML fabricated removed composite")
	}
	// Native policy remains untouched and prevents an exhaustive claim.
	f.admin(http.MethodPost, e.base+"/policy/group", map[string]any{"name": "native-explanation", "groups": []map[string]any{{"id": e.groups["Africa"], "extendChildren": true}}, "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE"}, nil)
	var nativePolicies, scopes, resources []map[string]any
	f.admin(http.MethodGet, e.base+"/policy/group", nil, &nativePolicies)
	f.admin(http.MethodGet, e.base+"/scope", nil, &scopes)
	f.admin(http.MethodGet, e.base+"/resource", nil, &resources)
	nativeID, scopeID, resourceID := "", "", ""
	for _, p := range nativePolicies {
		if p["name"] == "native-explanation" {
			nativeID = p["id"].(string)
		}
	}
	for _, v := range scopes {
		if v["name"] == "read" {
			scopeID = v["id"].(string)
		}
	}
	for _, v := range resources {
		if v["name"] == "invoice" {
			resourceID = v["_id"].(string)
		}
	}
	f.admin(http.MethodPost, e.base+"/permission/scope", map[string]any{"name": "native-invoice", "type": "scope", "resources": []string{resourceID}, "scopes": []string{scopeID}, "policies": []string{nativeID}, "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE"}, nil)
	before = q.writes()
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "foreign explanation read-only", q.writes(), before)
	x = requireExplanation(t, q, "Applied", false)
	// The provider-wide UNANIMOUS strategy can make a native permission
	// constrain the runtime result even while a managed allow path remains.
	e.decision("europe", "invoice#read", false)
	if len(x.Paths) == 0 {
		t.Fatal("native gap erased proven managed alternatives")
	}
	// Forge status: new explanation is recalculated, never trusted as authority.
	q.server.Status.AuthorizationExplanation = &api.AuthorizationExplanation{Source: "Applied", Complete: true, ExplanationHash: "forged", Paths: []api.AuthorizationExplanationPath{{SourceRef: "foreign-forged"}}}
	f.requireNoError(q.client.Status().Update(context.Background(), q.server))
	before = q.writes()
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "forged explanation induced writes", q.writes(), before)
	data, _ := json.Marshal(q.server.Status.AuthorizationExplanation)
	if strings.Contains(string(data), "forged") {
		t.Fatal("forged status influenced recalculation")
	}
	q.server.Spec.Mode = "Observe"
	q.server.Generation++
	f.requireNoError(q.client.Update(context.Background(), q.server))
	before = q.writes()
	f.requireNoError(q.reconcile())
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "Observe explanation mutated provider", q.writes(), before)
	requireExplanation(t, q, "Observed", false)
}
