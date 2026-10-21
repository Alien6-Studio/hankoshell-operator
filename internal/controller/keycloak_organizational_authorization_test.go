//go:build keycloak_integration

package controller_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// This is provider characterization, not an organization principal adapter.
// Bootstrap provisions groups/users only; constrained actors perform policy CRUD
// and evaluation. Tokens and fixture subjects never become public evidence.
type organizationAuthorizationExperiment struct {
	f         *keycloakFixture
	actor     string
	reader    string
	denied    string
	base      string
	groups    map[string]string
	users     map[string]string
	passwords map[string]string
	policies  map[string]string
	client    string
}

func organizationRequest(f *keycloakFixture, token, method, path string, payload any) (int, []byte) {
	f.t.Helper()
	var data []byte
	contentType := "application/json"
	if form, ok := payload.(url.Values); ok {
		data = []byte(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		var err error
		data, err = json.Marshal(payload)
		f.requireNoError(err)
	}
	req, err := http.NewRequest(method, f.baseURL+path, bytes.NewReader(data))
	f.requireNoError(err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	response, err := f.http.Do(req)
	f.requireNoError(err)
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	f.requireNoError(err)
	if len(result) > 1<<20 {
		f.t.Fatal("organization characterization response exceeds 1 MiB")
	}
	return response.StatusCode, result
}

func (e *organizationAuthorizationExperiment) object(method, path string, payload any, want int) map[string]any {
	e.f.t.Helper()
	status, data := organizationRequest(e.f, e.actor, method, path, payload)
	fixtureEqual(e.f.t, method+" "+path, status, want)
	result := map[string]any{}
	if len(data) != 0 && want != http.StatusNoContent {
		e.f.requireNoError(json.Unmarshal(data, &result))
	}
	return result
}

func (e *organizationAuthorizationExperiment) policy(name string, groups []map[string]any) string {
	e.f.t.Helper()
	payload := map[string]any{"name": name, "type": "group", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "groups": groups}
	method, path, status := http.MethodPost, e.base+"/policy/group", http.StatusCreated
	if id := e.policies[name]; id != "" {
		method, path, status = http.MethodPut, path+"/"+id, http.StatusCreated
		payload["id"] = id
	}
	result := e.object(method, path, payload, status)
	if method == http.MethodPost {
		id, ok := result["id"].(string)
		if !ok || id == "" {
			e.f.t.Fatal("group policy create did not return an ID")
		}
		e.policies[name] = id
	}
	return e.policies[name]
}

func (e *organizationAuthorizationExperiment) permission(name, policy, resource, scope string) string {
	e.f.t.Helper()
	p := e.object(http.MethodPost, e.base+"/permission/scope", map[string]any{
		"name": name, "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE",
		"resources": []string{resource}, "scopes": []string{scope}, "policies": []string{policy},
	}, http.StatusCreated)
	id, ok := p["id"].(string)
	if !ok || id == "" {
		e.f.t.Fatal("scope permission create did not return an ID")
	}
	return id
}

func (e *organizationAuthorizationExperiment) userToken(name string) string {
	e.f.t.Helper()
	status, _, data := protocolHTTP(e.f, e.f.http, http.MethodPost, e.f.baseURL+"/realms/managed/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"orgauth-billing"}, "client_secret": {e.client},
		"username": {name}, "password": {e.passwords[name]},
	})
	fixtureEqual(e.f.t, "fixture user token", status, http.StatusOK)
	var result struct {
		AccessToken string `json:"access_token"`
	}
	e.f.requireNoError(json.Unmarshal(data, &result))
	if result.AccessToken == "" {
		e.f.t.Fatal("missing fixture subject token")
	}
	e.f.secrets = append(e.f.secrets, result.AccessToken)
	return result.AccessToken
}

func (e *organizationAuthorizationExperiment) decision(subject, permission string, allow bool) {
	e.f.t.Helper()
	e.tokenDecision(subject, e.userToken(subject), permission, allow)
}

func (e *organizationAuthorizationExperiment) tokenDecision(subject, token, permission string, allow bool) {
	e.f.t.Helper()
	status, data := organizationRequest(e.f, token, http.MethodPost, "/realms/managed/protocol/openid-connect/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:uma-ticket"}, "audience": {"orgauth-billing"},
		"permission": {permission}, "response_mode": {"decision"},
	})
	want := http.StatusForbidden
	if allow {
		want = http.StatusOK
	}
	fixtureEqual(e.f.t, "UMA "+subject+" "+permission, status, want)
	if allow {
		var result struct{ Result bool }
		e.f.requireNoError(json.Unmarshal(data, &result))
		if !result.Result {
			e.f.t.Fatal("successful UMA response did not grant requested access")
		}
	}
}

func newOrganizationAuthorizationExperiment(t *testing.T) *organizationAuthorizationExperiment {
	f := newKeycloakFixture(t)
	e := &organizationAuthorizationExperiment{f: f, groups: map[string]string{}, users: map[string]string{}, passwords: map[string]string{}, policies: map[string]string{}}
	for _, path := range []string{"Europe", "Europe/France", "Europe/France/Paris", "Europe/Germany", "Europe/External", "Europe-sibling", "Africa"} {
		parts := strings.Split(path, "/")
		endpoint := "/admin/realms/managed/groups"
		if len(parts) > 1 {
			endpoint += "/" + e.groups[strings.Join(parts[:len(parts)-1], "/")] + "/children"
		}
		attrs := map[string][]string{"hanko.sh/organization-name": {strings.ToLower(parts[len(parts)-1])}, "hanko.sh/organization-namespace": {"iam"}, "hanko.sh/organization-uid": {"fixture-" + path}}
		if path == "Europe/External" {
			attrs = map[string][]string{"external-fixture": {"not-Hanko-owned"}}
		}
		f.admin(http.MethodPost, endpoint, map[string]any{"name": parts[len(parts)-1], "attributes": attrs}, nil)
		var group map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/group-by-path/"+path, nil, &group)
		id, ok := group["id"].(string)
		if !ok || id == "" {
			t.Fatal("bootstrap group identity missing")
		}
		e.groups[path] = id
	}
	for name, group := range map[string]string{"europe": "Europe", "france": "Europe/France", "paris": "Europe/France/Paris", "germany": "Europe/Germany", "external": "Europe/External", "prefix": "Europe-sibling", "africa": "Africa", "outsider": "", "native-only": ""} {
		password := fixtureSecret(t)
		f.secrets = append(f.secrets, password)
		f.admin(http.MethodPost, "/admin/realms/managed/users", map[string]any{"username": name, "enabled": true, "firstName": "Disposable", "lastName": "Fixture", "email": name + "@example.test", "emailVerified": true,
			"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}}}, nil)
		var users []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/users?username="+name+"&exact=true", nil, &users)
		if len(users) != 1 {
			t.Fatal("bootstrap user not unique")
		}
		uid, ok := users[0]["id"].(string)
		if !ok {
			t.Fatal("bootstrap user identity missing")
		}
		e.users[name], e.passwords[name] = uid, password
		if group != "" {
			f.admin(http.MethodPut, "/admin/realms/managed/users/"+uid+"/groups/"+e.groups[group], nil, nil)
		}
	}
	e.client = fixtureSecret(t)
	f.secrets = append(f.secrets, e.client)
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "orgauth-billing", "secret": e.client, "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "directAccessGrantsEnabled": true, "authorizationServicesEnabled": true}, nil)
	cid, ok := f.client("managed", "orgauth-billing")["id"].(string)
	if !ok {
		t.Fatal("bootstrap resource-server identity missing")
	}
	e.base = "/admin/realms/managed/clients/" + cid + "/authz/resource-server"
	_, noRoleSecret := f.serviceClient("orgauth-no-role")
	e.denied = f.token(url.Values{"client_id": {"orgauth-no-role"}, "client_secret": {noRoleSecret}, "grant_type": {"client_credentials"}})
	for name, roles := range map[string][]string{"orgauth-clients": {"manage-clients"}, "orgauth-query": {"manage-clients", "query-groups"}, "orgauth-reader": {"manage-clients", "view-users"}} {
		_, secret := f.serviceClient(name)
		f.grantClientRoles(name, "managed", roles)
		token := f.token(url.Values{"client_id": {name}, "client_secret": {secret}, "grant_type": {"client_credentials"}})
		for i, route := range []string{"/groups/" + e.groups["Europe"], "/group-by-path/Europe", "/groups?briefRepresentation=false&populateHierarchy=false", "/users"} {
			status, body := organizationRequest(f, token, http.MethodGet, "/admin/realms/managed"+route, nil)
			want := http.StatusForbidden
			if name == "orgauth-reader" || (name == "orgauth-query" && i == 2) {
				want = http.StatusOK
			}
			fixtureEqual(t, "profile "+name+" "+route, status, want)
			t.Logf("permission profile %s GET %s HTTP %d", strings.Join(roles, "+"), route, status)
			if strings.HasPrefix(route, "/groups?") && status == http.StatusOK {
				var groups []map[string]any
				f.requireNoError(json.Unmarshal(body, &groups))
				found := false
				for _, g := range groups {
					if g["id"] == e.groups["Europe"] {
						found = true
						attrs, ok := g["attributes"].(map[string]any)
						if !ok || attrs["hanko.sh/organization-uid"] == nil || g["path"] != "/Europe" {
							t.Fatal("readable group lacks expected ownership/path")
						}
					}
				}
				fixtureEqual(t, "profile list resolves owned group "+name, found, name == "orgauth-reader")
			}
		}
		if name == "orgauth-clients" {
			e.actor = token
		}
		if name == "orgauth-reader" {
			e.reader = token
		}
	}
	return e
}

func (e *organizationAuthorizationExperiment) nativeMembership() {
	f := e.f
	f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"organizationsEnabled": true}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/organizations", map[string]any{"name": "Europe", "alias": "native-europe", "enabled": true}, nil)
	var native []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/organizations", nil, &native)
	if len(native) != 1 {
		f.t.Fatal("native organization fixture is not unique")
	}
	id, ok := native[0]["id"].(string)
	if !ok {
		f.t.Fatal("native organization identity missing")
	}
	f.admin(http.MethodPost, "/admin/realms/managed/organizations/"+id+"/members", e.users["native-only"], nil)
	var members []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/organizations/"+id+"/members", nil, &members)
	if len(members) != 1 || members[0]["id"] != e.users["native-only"] {
		f.t.Fatal("native membership fixture was not established")
	}
}

func (e *organizationAuthorizationExperiment) roleComposition(scope map[string]any, sid string) {
	f := e.f
	f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": "organization-composed-reader"}, nil)
	var role map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/roles/organization-composed-reader", nil, &role)
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Europe"]+"/role-mappings/realm", []any{role}, nil)
	policy := e.object(http.MethodPost, e.base+"/policy/role", map[string]any{"name": "preserved-role-composition", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "roles": []any{map[string]any{"id": role["id"], "required": false}}}, http.StatusCreated)
	resource := e.object(http.MethodPost, e.base+"/resource", map[string]any{"name": "role-invoice", "scopes": []any{scope}}, http.StatusCreated)
	rid, rok := resource["_id"].(string)
	pid, pok := policy["id"].(string)
	if !rok || !pok {
		f.t.Fatal("role composition fixture identity missing")
	}
	e.policies["preserved-role-composition"] = pid
	e.permission("preserved-role-read", pid, rid, sid)
	for _, subject := range []string{"europe", "france", "paris", "germany", "prefix", "africa"} {
		e.decision(subject, "role-invoice#read", subject != "prefix" && subject != "africa")
	}
}

func (e *organizationAuthorizationExperiment) overlappingAllows(permission, pid, rid, sid string) {
	update := func(policies []string) {
		e.object(http.MethodPut, e.base+"/permission/scope/"+permission, map[string]any{"id": permission, "name": "invoice-read", "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "resources": []string{rid}, "scopes": []string{sid}, "policies": policies}, http.StatusCreated)
	}
	update([]string{pid, e.policies["preserved-role-composition"]})
	e.decision("europe", "invoice#read", true) // Both direct group and role paths.
	e.decision("france", "invoice#read", true) // Inherited role only; group policy remains direct-only.
	e.decision("prefix", "invoice#read", false)
	update([]string{pid})
	e.decision("france", "invoice#read", false)
}

func (e *organizationAuthorizationExperiment) policyRepresentation(pid string) {
	f := e.f
	typed := e.object(http.MethodGet, e.base+"/policy/group/"+pid, nil, http.StatusOK)
	groups, ok := typed["groups"].([]any)
	if !ok || len(groups) != 1 {
		f.t.Fatal("typed group policy representation missing")
	}
	g, ok := groups[0].(map[string]any)
	if !ok || g["id"] != e.groups["Europe"] || g["extendChildren"] != false || typed["groupsClaim"] != nil {
		f.t.Fatal("group ID/direct-only representation differs")
	}
	generic := e.object(http.MethodGet, e.base+"/policy/"+pid, nil, http.StatusOK)
	config, ok := generic["config"].(map[string]any)
	if !ok || config["groups"] == nil {
		f.t.Fatal("generic group policy config was not observed")
	}
	f.t.Log("typed group policy uses UUID + extendChildren; generic policy stores JSON groups config; groupsClaim unset")
	status, body := organizationRequest(f, e.actor, http.MethodPost, e.base+"/policy/group", map[string]any{"name": "path-input-characterization", "groups": []any{map[string]any{"path": "/Europe", "extendChildren": false}}})
	f.t.Logf("path-based group policy input HTTP %d", status)
	if status == http.StatusCreated {
		var p map[string]any
		f.requireNoError(json.Unmarshal(body, &p))
		id, ok := p["id"].(string)
		if !ok {
			f.t.Fatal("path policy create identity missing")
		}
		typedPath := e.object(http.MethodGet, e.base+"/policy/group/"+id, nil, http.StatusOK)
		definitions, ok := typedPath["groups"].([]any)
		if !ok || len(definitions) != 1 {
			f.t.Fatal("path input did not resolve to one group")
		}
		definition, ok := definitions[0].(map[string]any)
		if !ok || definition["id"] != e.groups["Europe"] {
			f.t.Fatal("path input was not canonicalized to group UUID")
		}
		e.object(http.MethodDelete, e.base+"/policy/"+id, nil, http.StatusNoContent)
	} else {
		fixtureEqual(f.t, "invalid path policy status", status, http.StatusBadRequest)
	}
}

func (e *organizationAuthorizationExperiment) permissionUpdate(permission, pid, rid, sid string) {
	f := e.f
	write := e.object(http.MethodPost, e.base+"/scope", map[string]any{"name": "write"}, http.StatusCreated)
	resource := e.object(http.MethodPost, e.base+"/resource", map[string]any{"name": "credit-note", "scopes": []any{write}}, http.StatusCreated)
	wrid, rok := resource["_id"].(string)
	wsid, sok := write["id"].(string)
	if !rok || !sok {
		f.t.Fatal("updated resource/scope identity missing")
	}
	update := func(resource, scope string) {
		e.object(http.MethodPut, e.base+"/permission/scope/"+permission, map[string]any{"id": permission, "name": "invoice-read", "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "resources": []string{resource}, "scopes": []string{scope}, "policies": []string{pid}}, http.StatusCreated)
	}
	update(wrid, wsid)
	e.decision("europe", "invoice#read", false)
	e.decision("europe", "credit-note#write", true)
	e.decision("outsider", "credit-note#write", false)
	update(rid, sid)
	e.decision("europe", "invoice#read", true)
	e.decision("europe", "credit-note#write", false)
	for _, route := range []string{"/policy/group", "/permission/scope", "/scope", "/resource", "/policy/evaluate"} {
		status, _ := organizationRequest(f, e.denied, http.MethodPost, e.base+route, map[string]any{"name": "denied"})
		fixtureEqual(f.t, "missing manage-clients "+route, status, http.StatusForbidden)
	}
	status, _ := organizationRequest(f, e.actor, http.MethodPost, e.base+"/policy/evaluate", map[string]any{"userId": e.users["europe"], "clientId": strings.Split(e.base, "/")[5], "resources": []any{map[string]any{"_id": rid, "scopes": []any{map[string]any{"id": sid}}}}})
	fixtureEqual(f.t, "constrained Admin evaluation", status, http.StatusOK)
}

func TestRealKeycloakOrganizationalAuthorizationCharacterization(t *testing.T) {
	e := newOrganizationAuthorizationExperiment(t)
	f := e.f
	// Remove Keycloak's initial permissive template in this isolated resource server.
	for _, collection := range []string{"permission", "policy", "resource"} {
		status, data := organizationRequest(f, e.actor, http.MethodGet, e.base+"/"+collection, nil)
		fixtureEqual(t, "initial collection read", status, http.StatusOK)
		var values []map[string]any
		f.requireNoError(json.Unmarshal(data, &values))
		for _, value := range values {
			id, ok := value["id"].(string)
			if !ok {
				t.Fatal("initial provider object missing identity")
			}
			e.object(http.MethodDelete, e.base+"/"+collection+"/"+id, nil, http.StatusNoContent)
		}
	}
	read := e.object(http.MethodPost, e.base+"/scope", map[string]any{"name": "read"}, http.StatusCreated)
	resource := e.object(http.MethodPost, e.base+"/resource", map[string]any{"name": "invoice", "scopes": []any{read}}, http.StatusCreated)
	rid, rok := resource["_id"].(string)
	sid, sok := read["id"].(string)
	if !rok || !sok {
		t.Fatal("resource/scope create identity missing")
	}
	e.nativeMembership()
	e.roleComposition(read, sid)
	group := func(path string, descendants bool) map[string]any {
		return map[string]any{"id": e.groups[path], "extendChildren": descendants}
	}
	pid := e.policy("org-europe", []map[string]any{group("Europe", false)})
	permission := e.permission("invoice-read", pid, rid, sid)
	e.permissionUpdate(permission, pid, rid, sid)
	for _, subject := range []string{"europe", "france", "paris", "germany", "external", "prefix", "africa", "outsider", "native-only"} {
		e.decision(subject, "invoice#read", subject == "europe")
	}
	e.overlappingAllows(permission, pid, rid, sid)
	e.policyRepresentation(pid)
	status, _ := organizationRequest(f, e.actor, http.MethodPost, e.base+"/policy/group", map[string]any{"name": "org-europe", "groups": []any{group("Africa", false)}})
	fixtureEqual(t, "same-name native policy collision", status, http.StatusConflict)
	e.policy("org-europe", []map[string]any{group("Europe", true)})
	for _, subject := range []string{"europe", "france", "paris", "germany", "external", "prefix", "africa", "outsider"} {
		e.decision(subject, "invoice#read", subject == "europe" || subject == "france" || subject == "paris" || subject == "germany" || subject == "external")
	}
	// Native extendChildren includes an unowned subgroup. The portable contract
	// instead expands proven declared descendants into direct-only UUID entries.
	e.policy("org-europe", []map[string]any{group("Europe", false), group("Europe/France", false), group("Europe/France/Paris", false), group("Europe/Germany", false)})
	for _, subject := range []string{"europe", "france", "paris", "germany", "external", "prefix", "africa", "outsider"} {
		e.decision(subject, "invoice#read", subject == "europe" || subject == "france" || subject == "paris" || subject == "germany")
	}
	e.policy("org-europe", []map[string]any{group("Europe/France", false)})
	for _, subject := range []string{"europe", "france", "paris", "germany"} {
		e.decision(subject, "invoice#read", subject == "france")
	}
	e.policy("org-europe", []map[string]any{group("Europe/France", true), group("Africa", false)})
	for _, subject := range []string{"france", "paris", "africa", "europe", "germany", "prefix"} {
		e.decision(subject, "invoice#read", subject == "france" || subject == "paris" || subject == "africa")
	}
	e.policy("org-europe", []map[string]any{group("Europe/France", true)})
	before := e.object(http.MethodGet, e.base+"/policy/group/"+pid, nil, http.StatusOK)
	e.policy("org-europe", []map[string]any{group("Europe/France", true)})
	fixtureEqual(t, "repeat same policy keeps exact ID and representation", e.object(http.MethodGet, e.base+"/policy/group/"+pid, nil, http.StatusOK), before)
	parisToken := e.userToken("paris")
	e.tokenDecision("paris", parisToken, "invoice#read", true)
	// UUID-based policies survive renames; path is reobserved, never portable intent.
	f.admin(http.MethodPut, "/admin/realms/managed/groups/"+e.groups["Europe/France"], map[string]any{"name": "France-renamed"}, nil)
	status, body := organizationRequest(f, e.reader, http.MethodGet, "/admin/realms/managed/groups/"+e.groups["Europe/France"], nil)
	fixtureEqual(t, "renamed group read", status, http.StatusOK)
	var renamed map[string]any
	f.requireNoError(json.Unmarshal(body, &renamed))
	fixtureEqual(t, "renamed path", renamed["path"], "/Europe/France-renamed")
	e.decision("paris", "invoice#read", true)
	// Reparent Paris outside France: descendant membership stops granting access.
	f.admin(http.MethodPost, "/admin/realms/managed/groups/"+e.groups["Africa"]+"/children", map[string]any{"id": e.groups["Europe/France/Paris"], "name": "Paris"}, nil)
	status, body = organizationRequest(f, e.reader, http.MethodGet, "/admin/realms/managed/groups/"+e.groups["Europe/France/Paris"], nil)
	fixtureEqual(t, "moved group read", status, http.StatusOK)
	var moved map[string]any
	f.requireNoError(json.Unmarshal(body, &moved))
	fixtureEqual(t, "moved path", moved["path"], "/Africa/Paris")
	e.decision("paris", "invoice#read", false)
	e.tokenDecision("paris", parisToken, "invoice#read", false)
	e.decision("france", "invoice#read", true)
	// An explicit UUID snapshot needs recompilation after a structural change;
	// UUID membership alone does not carry its former parent relationship.
	e.policy("org-europe", []map[string]any{group("Europe/France", false), group("Europe/France/Paris", false)})
	e.tokenDecision("paris", parisToken, "invoice#read", true)
	e.policy("org-europe", []map[string]any{group("Europe/France", false)})
	e.tokenDecision("paris", parisToken, "invoice#read", false)
	// Keep unrelated policies and the entire group/resource lifecycle independent.
	foreign := e.policy("foreign-native-group", []map[string]any{group("Africa", false)})
	e.object(http.MethodDelete, e.base+"/permission/"+permission, nil, http.StatusNoContent)
	e.object(http.MethodDelete, e.base+"/policy/"+pid, nil, http.StatusNoContent)
	e.object(http.MethodGet, e.base+"/policy/group/"+foreign, nil, http.StatusOK)
	e.object(http.MethodGet, e.base+"/resource/"+rid, nil, http.StatusOK)
	status, _ = organizationRequest(f, e.reader, http.MethodGet, "/admin/realms/managed/groups/"+e.groups["Europe"], nil)
	fixtureEqual(t, "group survives policy cleanup", status, http.StatusOK)
	e.decision("france", "invoice#read", false)
	e.decision("france", "role-invoice#read", true)
	for _, denied := range []struct{ method, path string }{{http.MethodPut, "/admin/realms/managed/groups/" + e.groups["Europe"]}, {http.MethodPost, "/admin/realms/managed/users"}, {http.MethodGet, "/admin/realms/master/clients"}, {http.MethodPost, "/admin/realms"}, {http.MethodPost, "/admin/realms/managed/users/" + e.users["europe"] + "/impersonation"}} {
		for _, actor := range []string{e.actor, e.reader} {
			status, _ := organizationRequest(f, actor, denied.method, denied.path, map[string]any{})
			fixtureEqual(t, "excluded authority "+denied.path, status, http.StatusForbidden)
		}
	}
	t.Log("qualified direct-only, native vs bounded explicit descendant sets, foreign-child exclusion, OR across groups, prefix-sibling denial, UUID rename/reparent, policy CRUD and UMA decisions")
}
