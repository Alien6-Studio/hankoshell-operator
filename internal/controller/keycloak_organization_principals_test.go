//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type reconciledOrganizationFixture struct {
	experiment    *organizationAuthorizationExperiment
	client        client.Client
	organizations *controller.HankoOrganizationReconciler
	reconciler    *controller.HankoResourceServerReconciler
	server        *api.HankoResourceServer
	nodes         map[string]*api.HankoOrganization
	actor         *keycloak.Client
	actorSecret   string
}

func newReconciledOrganizationFixture(t *testing.T) *reconciledOrganizationFixture {
	f := newKeycloakFixture(t)
	e := &organizationAuthorizationExperiment{f: f, groups: map[string]string{}, users: map[string]string{}, passwords: map[string]string{}, policies: map[string]string{}, client: fixtureSecret(t)}
	f.secrets = append(f.secrets, e.client)
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "orgauth-billing", "secret": e.client, "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "directAccessGrantsEnabled": true}, nil)
	cid := f.client("managed", "orgauth-billing")["id"].(string)
	e.base = "/admin/realms/managed/clients/" + cid + "/authz/resource-server"
	actor, actorSecret := f.serviceClient("organization-grant-operator")
	f.grantClientRoles("organization-grant-operator", "managed", []string{"manage-clients", "view-users"})
	realm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}
	app := &api.HankoApplication{ObjectMeta: fixtureMeta("billing-app"), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: "orgauth-billing"}}
	rs := &api.HankoResourceServer{ObjectMeta: fixtureMeta("organization-billing"), Spec: api.HankoResourceServerSpec{RealmRef: "managed", Audience: "urn:organization-billing", ApplicationRef: app.Name, Scopes: []api.AuthorizationScope{{Name: "read"}, {Name: "write"}}, Resources: []api.AuthorizationResource{{Name: "invoice", Scopes: []string{"read", "write"}}}, Permissions: []api.AuthorizationPermission{{Name: "invoice-read", Resources: []string{"invoice"}, Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "organization", Ref: "europe"}}}}}}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(realm, app, rs).WithStatusSubresource(&api.HankoResourceServer{}, &api.HankoOrganization{}).Build()
	q := &reconciledOrganizationFixture{experiment: e, client: c, server: rs, nodes: map[string]*api.HankoOrganization{}, actor: actor, actorSecret: actorSecret}
	q.organizations = &controller.HankoOrganizationReconciler{Client: c, Pool: keycloak.NewPool(f.kc)}
	q.reconciler = &controller.HankoResourceServerReconciler{Client: c, APIReader: c, DriverFactory: func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(actor) }}
	for _, path := range []string{"Europe", "Europe/France", "Europe/France/Paris", "Europe/Germany", "Europe-sibling", "Africa"} {
		parts := strings.Split(path, "/")
		name := strings.ToLower(parts[len(parts)-1])
		parent := ""
		if len(parts) > 1 {
			parent = strings.ToLower(parts[len(parts)-2])
		}
		o := &api.HankoOrganization{ObjectMeta: fixtureMeta(name), Spec: api.HankoOrganizationSpec{RealmRef: "managed", Name: parts[len(parts)-1], ParentRef: parent}}
		f.requireNoError(c.Create(context.Background(), o))
		runOrganization(t, q.organizations, o)
		if o.Status.GroupID == "" || o.Status.GroupPath != "/"+path {
			t.Fatal("real organization reconciliation failed")
		}
		q.nodes[name] = o
		e.groups[path] = o.Status.GroupID
	}
	// Deliberately foreign, markerless subgroup: never a declared organization.
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Europe"]+"/children", map[string]any{"name": "External"}, nil)
	var foreign map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/group-by-path/Europe/External", nil, &foreign)
	e.groups["Europe/External"] = foreign["id"].(string)
	for name, path := range map[string]string{"europe": "Europe", "france": "Europe/France", "paris": "Europe/France/Paris", "germany": "Europe/Germany", "prefix": "Europe-sibling", "africa": "Africa", "external": "Europe/External", "outsider": ""} {
		q.subject(name, path)
	}
	f.admin(http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	return q
}

func (q *reconciledOrganizationFixture) subject(name, path string) {
	e, f := q.experiment, q.experiment.f
	password := fixtureSecret(f.t)
	f.secrets = append(f.secrets, password)
	f.admin(http.MethodPost, "/admin/realms/managed/users", map[string]any{"username": name, "enabled": true, "firstName": "Disposable", "lastName": "Fixture", "email": name + "@example.test", "emailVerified": true, "credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}}}, nil)
	var users []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/users?username="+name+"&exact=true", nil, &users)
	if len(users) != 1 {
		f.t.Fatal("subject fixture not unique")
	}
	e.users[name], e.passwords[name] = users[0]["id"].(string), password
	if path != "" {
		f.admin(http.MethodPut, "/admin/realms/managed/users/"+e.users[name]+"/groups/"+e.groups[path], nil, nil)
	}
}

func (q *reconciledOrganizationFixture) reconcile() error {
	_, err := q.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(q.server)})
	q.experiment.f.requireNoError(q.client.Get(context.Background(), client.ObjectKeyFromObject(q.server), q.server))
	return err
}
func (q *reconciledOrganizationFixture) update() {
	q.server.Generation++
	q.experiment.f.requireNoError(q.client.Update(context.Background(), q.server))
	q.experiment.f.requireNoError(q.reconcile())
	if q.server.Status.Phase != "Ready" || !q.server.Status.ObservationComplete || q.server.Status.DriftState != "InSync" || q.server.Status.AppliedGeneration != q.server.Generation || q.server.Status.AppliedPlanHash != q.server.Status.EvaluatedPlanHash {
		q.experiment.f.t.Fatal("organizational applied proof is not current")
	}
}
func (q *reconciledOrganizationFixture) writes() int {
	var events []map[string]any
	q.experiment.f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)
	return len(events)
}
func (q *reconciledOrganizationFixture) groupPolicy() map[string]any {
	var policies []map[string]any
	q.experiment.f.admin(http.MethodGet, q.experiment.base+"/policy/group", nil, &policies)
	if len(policies) != 1 {
		q.experiment.f.t.Fatal("expected one owned organization policy")
	}
	return policies[0]
}
func (q *reconciledOrganizationFixture) requireGroupSet(refs ...string) {
	p := q.groupPolicy()
	groups, ok := p["groups"].([]any)
	if !ok || len(groups) != len(refs) || (p["groupsClaim"] != nil && p["groupsClaim"] != "") {
		q.experiment.f.t.Fatal("typed group policy shape differs")
	}
	expected := map[string]bool{}
	for _, ref := range refs {
		expected[q.nodes[ref].Status.GroupID] = true
	}
	for _, entry := range groups {
		g := entry.(map[string]any)
		id, _ := g["id"].(string)
		if !expected[id] || g["extendChildren"] != false {
			q.experiment.f.t.Fatal("group expansion is foreign, duplicated or native-inherited")
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		q.experiment.f.t.Fatal("owned group omitted")
	}
}

func TestRealKeycloakReconciledOrganizationPrincipals(t *testing.T) {
	q := newReconciledOrganizationFixture(t)
	checkOrganizationSharedConformance(t, q)
	checkReconciledOrganizationUMA(t, q)
	checkOrganizationGraphAndReadOnlyRecovery(t, q)
	checkOrganizationReadProfilesAndDrift(t, q)
	checkOrganizationStrictOwnership(t, q)
	checkOrganizationMultipleAndMixedGrants(t, q)
	checkOrganizationVerifiedRename(t, q)
	checkOrganizationHierarchyChange(t, q)
	checkOrganizationGrantCleanup(t, q)
}

func checkReconciledOrganizationUMA(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	f.requireNoError(q.reconcile())
	q.requireGroupSet("europe")
	for _, subject := range []string{"europe", "france", "paris", "germany", "prefix", "africa", "external", "outsider"} {
		e.decision(subject, "invoice#read", subject == "europe")
	}
	first := q.groupPolicy()["id"]
	writes := q.writes()
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "idempotent organization reconcile writes", q.writes(), writes)
	fixtureEqual(t, "idempotent organization policy UUID", q.groupPolicy()["id"], first)
	q.server.Spec.Permissions[0].Principals[0].IncludeDescendants = true
	q.update()
	q.requireGroupSet("europe", "france", "paris", "germany")
	for _, subject := range []string{"europe", "france", "paris", "germany", "prefix", "africa", "external", "outsider"} {
		e.decision(subject, "invoice#read", subject == "europe" || subject == "france" || subject == "paris" || subject == "germany")
	}
}

func checkOrganizationGraphAndReadOnlyRecovery(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	first := q.groupPolicy()["id"]
	// Previously unknown declared child updates the provider plan, not portable intent.
	oldIntent, oldPlan, oldObservation := q.server.Status.IntentHash, q.server.Status.AppliedPlanHash, q.server.Status.ObservedStateHash
	spain := &api.HankoOrganization{ObjectMeta: fixtureMeta("spain"), Spec: api.HankoOrganizationSpec{RealmRef: "managed", Name: "Spain", ParentRef: "europe"}}
	f.requireNoError(q.client.Create(context.Background(), spain))
	runOrganization(t, q.organizations, spain)
	q.nodes["spain"] = spain
	e.groups["Europe/Spain"] = spain.Status.GroupID
	q.subject("spain", "Europe/Spain")
	f.requireNoError(q.reconcile())
	q.requireGroupSet("europe", "france", "paris", "germany", "spain")
	e.decision("spain", "invoice#read", true)
	if q.server.Status.IntentHash != oldIntent || q.server.Status.AppliedPlanHash == oldPlan || q.server.Status.ObservedStateHash == oldObservation {
		t.Fatal("new descendant did not update provider-bound applied evidence")
	}
	// Observe never changes provider state or publishes application authority.
	observer, _ := f.serviceClient("organization-grant-observer")
	f.grantClientRoles("organization-grant-observer", "managed", []string{"view-clients", "view-authorization", "view-users"})
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(observer) }
	q.server.Spec.Mode = "Observe"
	q.server.Generation++
	f.requireNoError(q.client.Update(context.Background(), q.server))
	writes := q.writes()
	f.requireNoError(q.reconcile())
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "Observe organization writes", q.writes(), writes)
	if q.server.Status.AppliedPlanHash != "" || q.server.Status.AppliedGeneration != 0 {
		t.Fatal("Observe published applied authority")
	}
	q.server.Spec.Mode = "Manage"
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(q.actor) }
	q.update()
	// Existing status can be lost; the owner-UID journal recovers exact object IDs.
	q.server.Status = api.HankoResourceServerStatus{}
	f.requireNoError(q.client.Status().Update(context.Background(), q.server))
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "journal recovers group policy UUID", q.groupPolicy()["id"], first)
}

func checkOrganizationStrictOwnership(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	f := q.experiment.f
	path := "/admin/realms/managed/groups/" + q.nodes["europe"].Status.GroupID
	var original map[string]any
	f.admin(http.MethodGet, path, nil, &original)
	encoded, err := json.Marshal(original)
	f.requireNoError(err)
	defer f.admin(http.MethodPut, path, original, nil)
	for _, test := range []struct {
		key    string
		values []string
	}{
		{organization.OwnerName, nil},
		{organization.OwnerName, []string{"another"}},
		{organization.OwnerNamespace, []string{"foreign"}},
		{organization.OwnerUID, []string{"foreign"}},
		{organization.OwnerUID, []string{string(q.nodes["europe"].UID), "foreign"}},
	} {
		var current map[string]any
		f.requireNoError(json.Unmarshal(encoded, &current))
		attrs := current["attributes"].(map[string]any)
		if test.values == nil {
			delete(attrs, test.key)
		} else {
			attrs[test.key] = test.values
		}
		f.admin(http.MethodPut, path, current, nil)
		writes, prior := q.writes(), q.server.Status.AppliedPlanHash
		if q.reconcile() == nil {
			t.Fatal("non-singleton or foreign real provider ownership accepted")
		}
		fixtureEqual(t, "strict ownership refusal writes", q.writes(), writes)
		if q.server.Status.AppliedPlanHash != prior || len(q.server.Status.Findings) != 1 || q.server.Status.Findings[0].Code != "OrganizationOwnershipConflict" {
			t.Fatal("strict ownership refusal lost bounded historical proof")
		}
	}
	f.admin(http.MethodPut, path, original, nil)
	f.requireNoError(q.reconcile())
}

func checkOrganizationReadProfilesAndDrift(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	// Both missing view-users and query-groups are insufficient for ownership proof.
	for _, roles := range [][]string{{"manage-clients"}, {"manage-clients", "query-groups"}} {
		name := "organization-no-read"
		if len(roles) > 1 {
			name = "organization-query-only"
		}
		denied, _ := f.serviceClient(name)
		f.grantClientRoles(name, "managed", roles)
		q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(denied) }
		writes := q.writes()
		prior := q.server.Status.AppliedPlanHash
		if q.reconcile() == nil {
			t.Fatal("insufficient group read accepted")
		}
		fixtureEqual(t, "denied group read authorization writes", q.writes(), writes)
		if q.server.Status.AppliedPlanHash != prior || len(q.server.Status.Findings) != 1 || q.server.Status.Findings[0].Code != "OrganizationReadUnavailable" {
			t.Fatal("read denial lost bounded historical proof")
		}
	}
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(q.actor) }
	f.requireNoError(q.reconcile())
	t.Log("missing view-users and query-groups-only profiles refuse without writes")
	// Group policies with native inheritance or claim overrides are managed drift.
	policy := q.groupPolicy()
	policy["groupsClaim"] = "untrusted-claim"
	policy["groups"].([]any)[0].(map[string]any)["extendChildren"] = true
	f.admin(http.MethodPut, e.base+"/policy/group/"+policy["id"].(string), policy, nil)
	if err := q.reconcile(); err != nil {
		for _, condition := range q.server.Status.Conditions {
			t.Log("drift repair condition", condition.Type, condition.Reason)
		}
		t.Fatal("group drift repair refused")
	}
	q.requireGroupSet("europe", "france", "paris", "germany", "spain")
	for _, op := range []struct {
		method, path string
		payload      any
	}{
		{http.MethodPost, "/admin/realms/managed/users", map[string]any{"username": "denied-fixture"}},
		{http.MethodPut, "/admin/realms/managed/users/" + e.users["europe"], map[string]any{"enabled": false}},
		{http.MethodPost, "/admin/realms/managed/groups", map[string]any{"name": "denied-fixture"}},
		{http.MethodPut, "/admin/realms/managed/groups/" + e.groups["Europe"], map[string]any{"name": "denied-fixture"}},
		{http.MethodPut, "/admin/realms/managed/users/" + e.users["outsider"] + "/groups/" + e.groups["Europe"], nil},
		{http.MethodPost, "/admin/realms/managed/users/" + e.users["europe"] + "/impersonation", nil},
		{http.MethodPost, "/admin/realms", map[string]any{"realm": "denied-fixture"}},
		{http.MethodGet, "/admin/realms/master/clients", nil},
	} {
		fixtureEqual(t, "organizational authorization excluded authority", f.identityStatus("organization-grant-operator", q.actorSecret, op.method, op.path, op.payload), http.StatusForbidden)
	}
}

func checkOrganizationMultipleAndMixedGrants(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	q.server.Spec.Permissions[0].Principals = []api.AuthorizationPrincipal{{Kind: "organization", Ref: "europe"}, {Kind: "organization", Ref: "africa"}}
	q.update()
	q.requireGroupSet("europe", "africa")
	e.decision("europe", "invoice#read", true)
	e.decision("africa", "invoice#read", true)
	e.decision("france", "invoice#read", false)
	q.server.Spec.Resources = append(q.server.Spec.Resources, api.AuthorizationResource{Name: "credit-note", Scopes: []string{"write"}})
	q.server.Spec.Permissions[0].Resources = []string{"credit-note"}
	q.server.Spec.Permissions[0].Scopes = []string{"write"}
	q.update()
	e.decision("europe", "invoice#read", false)
	e.decision("europe", "credit-note#write", true)
	q.server.Spec.Resources = q.server.Spec.Resources[:1]
	q.server.Spec.Permissions[0].Resources = []string{"invoice"}
	q.server.Spec.Permissions[0].Scopes = []string{"read"}
	f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": "organization-reader"}, nil)
	var role map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/roles/organization-reader", nil, &role)
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Europe"]+"/role-mappings/realm", []map[string]any{role}, nil)
	f.requireNoError(q.client.Create(context.Background(), &api.HankoRole{ObjectMeta: fixtureMeta("organization-reader"), Spec: api.HankoRoleSpec{RealmRef: "managed", Name: "organization-reader"}}))
	// The existing realm-role lookup has its separate view-realm requirement.
	// This fixture profile adds read authority explicitly, not in operator code.
	mixed, _ := f.serviceClient("organization-mixed-reader")
	f.grantClientRoles("organization-mixed-reader", "managed", []string{"manage-clients", "view-users", "view-realm"})
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(mixed) }
	q.server.Spec.Permissions[0].Principals = []api.AuthorizationPrincipal{{Kind: "organization", Ref: "europe"}, {Kind: "realm_role", Ref: "organization-reader"}}
	q.update()
	q.requireGroupSet("europe")
	e.decision("europe", "invoice#read", true)
	e.decision("france", "invoice#read", true)
	e.decision("outsider", "invoice#read", false)
	if len(q.server.Status.ManagedObjects.Policies) != 2 {
		t.Fatal("mixed allow policy count differs")
	}
	q.server.Spec.Permissions[0].Principals = q.server.Spec.Permissions[0].Principals[1:]
	q.update()
	e.decision("france", "invoice#read", true)
	if len(q.server.Status.ManagedObjects.Policies) != 1 || !strings.HasSuffix(q.server.Status.ManagedObjects.Policies[0].Name, "#realm_roles") {
		t.Fatal("organization removal changed the surviving role grant")
	}
	q.server.Spec.Permissions[0].Principals = []api.AuthorizationPrincipal{{Kind: "organization", Ref: "europe", IncludeDescendants: true}}
	q.reconciler.DriverFactory = func(string, map[string]string) authorization.Driver { return authorization.NewKeycloakDriver(q.actor) }
	q.update()
	q.requireGroupSet("europe", "france", "paris", "germany", "spain")
}

func checkOrganizationVerifiedRename(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	f := q.experiment.f
	france := q.nodes["france"]
	oldID := q.groupPolicy()["id"]
	oldPlan := q.server.Status.AppliedPlanHash
	var provider map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/groups/"+france.Status.GroupID, nil, &provider)
	provider["name"] = "FranceRenamed"
	f.admin(http.MethodPut, "/admin/realms/managed/groups/"+france.Status.GroupID, provider, nil)
	france.Spec.Name = "FranceRenamed"
	france.Generation++
	f.requireNoError(q.client.Update(context.Background(), france))
	runOrganization(t, q.organizations, france)
	runOrganization(t, q.organizations, q.nodes["paris"])
	writes := q.writes()
	f.requireNoError(q.reconcile())
	fixtureEqual(t, "verified UUID rename needs no policy replacement/write", q.writes(), writes)
	fixtureEqual(t, "verified rename retains policy UUID", q.groupPolicy()["id"], oldID)
	if q.server.Status.AppliedPlanHash == oldPlan || france.Status.GroupPath != "/Europe/FranceRenamed" {
		t.Fatal("fresh renamed hierarchy absent from applied evidence")
	}
	q.experiment.decision("france", "invoice#read", true)
	x := q.server.Status.AuthorizationExplanation
	if x == nil || explanationPath(x, "organization", "europe", "france", "descendant") == nil {
		t.Fatal("UUID-preserving rename lost Hanko provenance")
	}
}

func checkOrganizationSharedConformance(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	f := q.experiment.f
	ctx := context.Background()
	driver := authorization.NewKeycloakDriver(q.actor)
	groups := []authorization.OrganizationGroup{}
	for _, ref := range []string{"europe", "france", "paris", "germany"} {
		o := q.nodes[ref]
		g, err := driver.ReadOrganizationGroup(ctx, "managed", authorization.OrganizationGroup{Ref: ref, Namespace: o.Namespace, UID: string(o.UID), ID: o.Status.GroupID, Name: o.Spec.Name, Path: o.Status.GroupPath})
		f.requireNoError(err)
		groups = append(groups, g)
	}
	model := authorization.Model{Name: q.server.Name, Realm: "managed", Audience: q.server.Spec.Audience, ApplicationRef: "orgauth-billing", Scopes: []authorization.Scope{{Name: "read"}}, Resources: []authorization.Resource{{Name: "invoice", Scopes: []string{"read"}}}, Permissions: []authorization.Permission{{Name: "conformance", Resources: []string{"invoice"}, Scopes: []string{"read"}, Principals: []authorization.Principal{{Kind: "organization", Ref: "europe", IncludeDescendants: true, Organization: &authorization.ResolvedOrganizationPrincipal{Groups: groups, Graph: iamcontract.Hash(iamcontract.Version, "conformance", "graph", nil)}}}}}}
	compile := func(reverse bool, owner string) authorization.Plan {
		m := model
		m.Permissions = append([]authorization.Permission{}, model.Permissions...)
		m.Permissions[0].Principals = append([]authorization.Principal{}, model.Permissions[0].Principals...)
		resolved := *model.Permissions[0].Principals[0].Organization
		resolved.Groups = append([]authorization.OrganizationGroup{}, groups...)
		if reverse {
			for i, j := 0, len(resolved.Groups)-1; i < j; i, j = i+1, j-1 {
				resolved.Groups[i], resolved.Groups[j] = resolved.Groups[j], resolved.Groups[i]
			}
		}
		m.Permissions[0].Principals[0].Organization = &resolved
		i := authorization.Normalize(m)
		r, err := authorization.Resolve(i, m)
		f.requireNoError(err)
		caps, _ := driver.Capabilities(ctx, "managed")
		p, err := authorization.Compile(i, r, authorization.KeycloakEvidence(caps), iamcontract.Preconditions{ResourceUID: owner})
		f.requireNoError(err)
		return p
	}
	plan := compile(false, string(q.server.UID))
	var owned authorization.ManagedObjects
	iamconformance.Run(t, iamconformance.Fixture{
		Compile: func(reverse bool) iamcontract.PlanIdentity { return compile(reverse, string(q.server.UID)).Identity() }, Writes: q.writes,
		Refuse: func() error {
			i := authorization.Normalize(model)
			r, _ := authorization.Resolve(i, model)
			caps, _ := driver.Capabilities(ctx, "managed")
			caps.OrganizationDescendants = false
			_, err := authorization.Compile(i, r, authorization.KeycloakEvidence(caps), iamcontract.Preconditions{})
			return err
		},
		Manage: func() error {
			state, err := driver.Reconcile(ctx, plan, owned)
			if err == nil {
				owned = state.ManagedObjects
			}
			return err
		},
		Observe: func() error { _, err := driver.Observe(ctx, plan); return err },
		DriftAndRepair: func() error {
			p := q.groupPolicy()
			p["groupsClaim"] = "native-claim"
			f.admin(http.MethodPut, q.experiment.base+"/policy/group/"+p["id"].(string), p, nil)
			_, err := driver.Reconcile(ctx, plan, owned)
			return err
		},
		Foreign:     func() error { _, err := driver.Reconcile(ctx, compile(false, "foreign-owner"), owned); return err },
		DeleteOwned: func() error { return driver.DeleteOwned(ctx, model, owned, string(q.server.UID)) },
		VerifyDeleted: func() error {
			for _, g := range groups {
				_, err := q.actor.GetGroup(ctx, "managed", g.ID)
				if err != nil {
					return err
				}
			}
			return nil
		},
	})
	iamconformance.NoSecrets(t, f.secrets, plan, plan.Identity())
}

func checkOrganizationHierarchyChange(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	// Provider-only reparenting cannot be trusted through status. No grant writes.
	previousExplanation := q.server.Status.AuthorizationExplanation.DeepCopy()
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+q.nodes["africa"].Status.GroupID+"/children", map[string]any{"id": q.nodes["paris"].Status.GroupID, "name": "Paris"}, nil)
	writes := q.writes()
	if q.reconcile() == nil {
		t.Fatal("provider hierarchy mismatch accepted")
	}
	fixtureEqual(t, "reparent refusal writes", q.writes(), writes)
	if q.server.Status.AuthorizationExplanation == nil || q.server.Status.AuthorizationExplanation.ExplanationHash != previousExplanation.ExplanationHash {
		t.Fatal("refused reparent replaced historical explanation")
	}
	for _, c := range q.server.Status.Conditions {
		if c.Type == "AuthorizationExplained" && c.Status == "True" {
			t.Fatal("old reparent provenance labelled current")
		}
	}
	if len(q.server.Status.Findings) != 1 || q.server.Status.Findings[0].Code != "OrganizationHierarchyMismatch" {
		t.Fatal("reparent finding differs")
	}
	// Explicitly update fixture desired/current provider evidence after the move.
	paris := q.nodes["paris"]
	paris.Spec.ParentRef = "africa"
	paris.Generation++
	f.requireNoError(q.client.Update(context.Background(), paris))
	paris.Status.GroupPath = "/Africa/Paris"
	paris.Status.ObservedGeneration = paris.Generation
	for i := range paris.Status.Conditions {
		paris.Status.Conditions[i].ObservedGeneration = paris.Generation
	}
	f.requireNoError(q.client.Status().Update(context.Background(), paris))
	f.requireNoError(q.reconcile())
	t.Log("provider move refusal and declared move qualified")
	if x := q.server.Status.AuthorizationExplanation; x == nil || explanationPath(x, "organization", "europe", "paris", "descendant") != nil {
		t.Fatal("reparent retained old applied ancestry")
	}

	q.requireGroupSet("europe", "france", "germany", "spain")
	e.decision("paris", "invoice#read", false)
	// Removing a descendant through its normal finalizer removes only its grant UUID.
	spain := q.nodes["spain"]
	f.requireNoError(q.client.Delete(context.Background(), spain))
	_, cleanupErr := q.organizations.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(spain)})
	f.requireNoError(cleanupErr)
	if err := q.reconcile(); err != nil {
		for _, condition := range q.server.Status.Conditions {
			t.Log("descendant deletion condition", condition.Type, condition.Reason)
		}
		t.Fatal("descendant deletion repair refused")
	}
	q.requireGroupSet("europe", "france", "germany")
	e.decision("spain", "invoice#read", false)
}

func checkOrganizationGrantCleanup(t *testing.T, q *reconciledOrganizationFixture) {
	t.Helper()
	e, f := q.experiment, q.experiment.f
	// Keep a foreign group policy across owned grant removal and finalization.
	f.admin(http.MethodPost, e.base+"/policy/group", map[string]any{"name": "foreign-organization-policy", "groups": []map[string]any{{"id": e.groups["Europe/External"], "extendChildren": false}}, "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE"}, nil)
	q.server.Spec.Permissions = nil
	q.update()
	var policies []map[string]any
	f.admin(http.MethodGet, e.base+"/policy/group", nil, &policies)
	fixtureEqual(t, "foreign policy survives grant removal", len(policies), 1)
	if policies[0]["name"] != "foreign-organization-policy" {
		t.Fatal("foreign policy identity lost")
	}
	f.requireNoError(q.client.Delete(context.Background(), q.server))
	_, cleanupErr := q.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(q.server)})
	f.requireNoError(cleanupErr)
	for _, o := range q.nodes {
		if o.Name == "spain" {
			continue
		}
		var g map[string]any
		fixtureEqual(t, "organization survives ResourceServer cleanup", f.admin(http.MethodGet, "/admin/realms/managed/groups/"+o.Status.GroupID, nil, &g), http.StatusOK)
	}
	f.admin(http.MethodGet, e.base+"/policy/group", nil, &policies)
	fixtureEqual(t, "foreign policy survives ResourceServer cleanup", len(policies), 1)
	evidence, _ := json.Marshal(q.server.Status)
	f.requireNoCredentials("organization status", evidence)
}
