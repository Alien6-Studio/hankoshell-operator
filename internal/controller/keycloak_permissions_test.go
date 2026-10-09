//go:build keycloak_integration

package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// Bootstrap grants both the service user's roles and the client's permitted
// token scope. Operator identities cannot grant themselves either authority.
func (f *keycloakFixture) grantClientRoles(name, realm string, names []string) {
	f.t.Helper()
	f.adminToken = f.token(url.Values{"client_id": {"admin-cli"}, "grant_type": {"password"}, "username": {"fixture-admin"}, "password": {f.secrets[0]}})
	client := f.client("master", name)
	proxy := f.client("master", realm+"-realm")
	var user map[string]any
	f.admin(http.MethodGet, "/admin/realms/master/clients/"+client["id"].(string)+"/service-account-user", nil, &user)
	roles := make([]map[string]any, 0, len(names))
	for _, name := range names {
		var role map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/clients/"+proxy["id"].(string)+"/roles/"+name, nil, &role)
		roles = append(roles, role)
	}
	f.admin(http.MethodPost, "/admin/realms/master/users/"+user["id"].(string)+"/role-mappings/clients/"+proxy["id"].(string), roles, nil)
	f.admin(http.MethodPost, "/admin/realms/master/clients/"+client["id"].(string)+"/scope-mappings/clients/"+proxy["id"].(string), roles, nil)
}

func (f *keycloakFixture) identityStatus(name, secret, method, path string, payload any) int {
	f.t.Helper()
	token := f.token(url.Values{"client_id": {name}, "client_secret": {secret}, "grant_type": {"client_credentials"}})
	data, err := json.Marshal(payload)
	f.requireNoError(err)
	req, err := http.NewRequest(method, f.baseURL+path, bytes.NewReader(data))
	f.requireNoError(err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := f.http.Do(req)
	f.requireNoError(err)
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	f.requireNoError(err)
	return response.StatusCode
}

func TestRealKeycloakPermissionProfiles(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	baseline := []string{"manage-realm", "manage-clients", "manage-events"}
	kc, secret := f.serviceClient("minimal")
	_, noRoleSecret := f.serviceClient("no-role")
	f.grantClientRoles("minimal", "managed", baseline)
	_, err := kc.ServerVersion(ctx)
	f.requireNoError(err)
	f.requireNoError(kc.EnsureRealmManagementAccess(ctx, "managed"))
	f.requireNoError(kc.UpdateRealm(ctx, "managed", keycloak.RealmSpec{DisplayName: "Minimum", Enabled: true}))
	f.requireNoError(kc.ConfigureRealmEvents(ctx, "managed", keycloak.RealmSpec{}))
	f.requireNoError(kc.SyncRealmRole(ctx, "managed", keycloak.RealmRole{Name: "reader"}))
	_, err = kc.CreateApp(ctx, "managed", keycloak.CreateAppSpec{ClientID: "minimal-app", Type: "m2m"})
	f.requireNoError(err)
	f.requireNoError(kc.CreateClientRole(ctx, "managed", "minimal-app", "access", ""))
	_, err = kc.RotateClientSecret(ctx, "managed", "minimal-app")
	f.requireNoError(err)
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "permissions-unrelated", "enabled": true}, nil)
	fixtureEqual(t, "unrelated realm mutation excluded", f.identityStatus("minimal", secret, http.MethodPut, "/admin/realms/permissions-unrelated", map[string]any{"displayName": "denied-unrelated"}), http.StatusForbidden)
	fixtureEqual(t, "unrelated realm client access excluded", f.identityStatus("minimal", secret, http.MethodGet, "/admin/realms/permissions-unrelated/clients", nil), http.StatusForbidden)
	for _, path := range []string{"/admin/realms/master/clients", "/admin/realms/managed/users", "/admin/realms/managed/identity-provider/instances"} {
		fixtureEqual(t, "excluded authority "+path, f.identityStatus("minimal", secret, http.MethodGet, path, nil), http.StatusForbidden)
	}
	fixtureEqual(t, "master mutation excluded", f.identityStatus("minimal", secret, http.MethodPut, "/admin/realms/master", map[string]any{"displayName": "denied"}), http.StatusForbidden)
	fixtureEqual(t, "realm creation excluded", f.identityStatus("minimal", secret, http.MethodPost, "/admin/realms", map[string]any{"realm": "denied"}), http.StatusForbidden)
	fixtureEqual(t, "session revocation excluded", f.identityStatus("minimal", secret, http.MethodPost, "/admin/realms/managed/logout-all", nil), http.StatusForbidden)

	f.run("each baseline role is necessary", func(t *testing.T) {
		checks := []struct {
			role, method, path string
			payload            any
		}{
			{"manage-realm", http.MethodPut, "/admin/realms/managed", map[string]any{"displayName": "denied"}},
			{"manage-clients", http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "denied"}},
			{"manage-events", http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"eventsEnabled": false}},
		}
		client, proxy := f.client("master", "minimal"), f.client("master", "managed-realm")
		var user map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/clients/"+client["id"].(string)+"/service-account-user", nil, &user)
		mappingPath := "/admin/realms/master/users/" + user["id"].(string) + "/role-mappings/clients/" + proxy["id"].(string)
		for _, check := range checks {
			var role map[string]any
			f.admin(http.MethodGet, "/admin/realms/master/clients/"+proxy["id"].(string)+"/roles/"+check.role, nil, &role)
			f.admin(http.MethodDelete, mappingPath, []any{role}, nil)
			fixtureEqual(t, "missing "+check.role, f.identityStatus("minimal", secret, check.method, check.path, check.payload), http.StatusForbidden)
			f.admin(http.MethodPost, mappingPath, []any{role}, nil)
		}
	})

	f.run("protocol mappers and role scopes", func(t *testing.T) {
		f.requireNoError(kc.EnsureClientRole(ctx, "managed", "minimal-app", "application-role", "Initial"))
		f.requireNoError(kc.EnsureClientRole(ctx, "managed", "minimal-app", "application-role", "Updated"))
		provider := f.client("managed", "minimal-app")
		fixtureEqual(t, "no-role client-role update denied", f.identityStatus("no-role", noRoleSecret, http.MethodPut, "/admin/realms/managed/clients/"+provider["id"].(string)+"/roles/application-role", map[string]any{"description": "denied"}), http.StatusForbidden)
		mapper := keycloak.ProtocolMapper{Name: "department", Protocol: "openid-connect", ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{"user.attribute": "department", "claim.name": "department", "jsonType.label": "String"}}
		created, err := kc.EnsureClientProtocolMapper(ctx, "managed", "minimal-app", mapper)
		f.requireNoError(err)
		mapper.Config["claim.name"] = "division"
		_, err = kc.EnsureClientProtocolMapper(ctx, "managed", "minimal-app", mapper)
		f.requireNoError(err)
		f.requireNoError(kc.ReconcileClientRealmRoleScopes(ctx, "managed", "minimal-app", []string{"reader"}))
		f.requireNoError(kc.ReconcileClientRealmRoleScopes(ctx, "managed", "minimal-app", nil))
		f.requireNoError(kc.DeleteClientProtocolMapper(ctx, "managed", "minimal-app", created.ID))
	})

	f.run("authorization without extra authorization role", func(t *testing.T) {
		model := keycloak.AuthorizationModel{Name: "permissions", Realm: "managed", ApplicationRef: "minimal-app",
			Scopes:      []keycloak.AuthorizationScope{{Name: "read"}},
			Resources:   []keycloak.AuthorizationResource{{Name: "document", URIs: []string{"/documents/*"}, Scopes: []string{"read"}}},
			Permissions: []keycloak.AuthorizationPermission{{Name: "read-document", Resources: []string{"document"}, Scopes: []string{"read"}, Principals: []keycloak.AuthorizationPrincipal{{Kind: "realm_role", Ref: "reader"}, {Kind: "application", Ref: "minimal-app"}}}},
		}
		state, err := kc.ReconcileAuthorization(ctx, model, keycloak.AuthorizationManagedObjects{})
		f.requireNoError(err)
		observer, credential := f.serviceClient("authorization-observer")
		f.grantClientRoles("authorization-observer", "managed", []string{"view-clients", "view-realm", "view-authorization"})
		_, err = observer.ObserveAuthorization(ctx, model)
		f.requireNoError(err)
		fixtureEqual(t, "authorization observer cannot mutate", f.identityStatus("authorization-observer", credential, http.MethodPost, "/admin/realms/managed/clients/"+state.ResourceServerID+"/authz/resource-server/scope", map[string]any{"name": "denied"}), http.StatusForbidden)
		_, err = kc.ObserveAuthorization(ctx, model)
		f.requireNoError(err)
		model.Scopes[0].Description = "updated"
		model.Resources[0].URIs = []string{"/documents/owned/*"}
		state, err = kc.ReconcileAuthorization(ctx, model, state.ManagedObjects)
		f.requireNoError(err)
		f.requireNoError(kc.DeleteAuthorizationOwned(ctx, model, state.ResourceServerID, state.ManagedObjects))
	})

	f.run("identity providers only", func(t *testing.T) {
		idp, credential := f.serviceClient("idp-only")
		f.grantClientRoles("idp-only", "managed", []string{"manage-identity-providers"})
		provider := keycloak.IdentityProvider{Alias: "restricted-idp", ProviderID: "oidc", Enabled: false, Config: map[string]string{"clientId": "upstream", "authorizationUrl": "https://identity.invalid/authorize", "tokenUrl": "https://identity.invalid/token", "jwksUrl": "https://identity.invalid/jwks", "useJwksUrl": "true"}}
		_, err := idp.EnsureIdentityProvider(ctx, "managed", provider)
		f.requireNoError(err)
		mapper := keycloak.IdentityProviderMapper{Name: "email", IdentityProviderAlias: provider.Alias, IdentityProviderMapper: "oidc-user-attribute-idp-mapper", Config: map[string]string{"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}}
		created, err := idp.EnsureIdentityProviderMapper(ctx, "managed", mapper)
		f.requireNoError(err)
		mapper.Config["claim"] = "contact"
		_, err = idp.EnsureIdentityProviderMapper(ctx, "managed", mapper)
		f.requireNoError(err)
		provider.DisplayName = "updated"
		_, err = idp.EnsureIdentityProvider(ctx, "managed", provider)
		f.requireNoError(err)
		f.requireNoError(idp.DeleteIdentityProviderMapper(ctx, "managed", provider.Alias, created.ID))
		f.requireNoError(idp.DeleteIdentityProvider(ctx, "managed", provider.Alias))
		fixtureEqual(t, "IdP role cannot create clients", f.identityStatus("idp-only", credential, http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "denied-idp"}), http.StatusForbidden)
	})

	f.run("groups and sessions without impersonation", func(t *testing.T) {
		users, credential := f.serviceClient("groups-only")
		f.grantClientRoles("groups-only", "managed", []string{"manage-users", "view-realm", "view-clients"})
		groupID, err := users.EnsureGroup(ctx, "managed", keycloak.GroupSpec{Name: "team"})
		f.requireNoError(err)
		child, err := users.EnsureGroup(ctx, "managed", keycloak.GroupSpec{Name: "nested", ParentID: groupID, ParentPath: "/team"})
		f.requireNoError(err)
		f.requireNoError(users.AssignRealmRolesToGroup(ctx, "managed", child, []string{"reader"}))
		f.requireNoError(users.AssignClientRolesToGroup(ctx, "managed", child, "minimal-app", []string{"access"}))
		_, err = users.GetGroupEffectiveRoleClosure(ctx, "managed", child)
		f.requireNoError(err)
		f.requireNoError(users.LogoutAllRealmSessions(ctx, "managed"))
		f.admin(http.MethodPost, "/admin/realms/managed/users", map[string]any{"username": "ordinary-user", "enabled": true}, nil)
		var usersInRealm []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/users?username=ordinary-user&exact=true", nil, &usersInRealm)
		if len(usersInRealm) != 1 {
			t.Fatal("impersonation fixture user missing")
		}
		fixtureEqual(t, "impersonation excluded within authorized realm", f.identityStatus("groups-only", credential, http.MethodPost, "/admin/realms/managed/users/"+usersInRealm[0]["id"].(string)+"/impersonation", nil), http.StatusForbidden)
		fixtureEqual(t, "user manager cannot change realm policy", f.identityStatus("groups-only", credential, http.MethodPut, "/admin/realms/managed", map[string]any{"displayName": "denied-users"}), http.StatusForbidden)
		groupObserver, groupCredential := f.serviceClient("group-observer")
		f.grantClientRoles("group-observer", "managed", []string{"view-users", "view-realm", "view-clients"})
		_, err = groupObserver.GetGroupByPath(ctx, "managed", "/team/nested")
		f.requireNoError(err)
		_, err = groupObserver.GetGroupEffectiveRoleClosure(ctx, "managed", child)
		f.requireNoError(err)
		fixtureEqual(t, "group observer cannot create groups", f.identityStatus("group-observer", groupCredential, http.MethodPost, "/admin/realms/managed/groups", map[string]any{"name": "denied"}), http.StatusForbidden)
		f.requireNoError(users.DeleteGroup(ctx, "managed", child))
		f.requireNoError(users.DeleteGroup(ctx, "managed", groupID))
	})

	f.run("native organizations", func(t *testing.T) {
		f.requireNoError(kc.EnsureOrganizationsEnabled(ctx, "managed"))
		commonOrg, err := kc.EnsureOrganization(ctx, "managed", keycloak.OrganizationSpec{Alias: "common-org", Name: "Common"})
		f.requireNoError(err)
		f.requireNoError(kc.DeleteOrganization(ctx, "managed", commonOrg))
		orgs, credential := f.serviceClient("organizations-only")
		f.grantClientRoles("organizations-only", "managed", []string{"manage-organizations", "manage-identity-providers"})
		org := keycloak.OrganizationSpec{Alias: "company", Name: "Company", Domains: []string{"company.invalid"}}
		id, err := orgs.EnsureOrganization(ctx, "managed", org)
		f.requireNoError(err)
		org.Name = "Updated company"
		_, err = orgs.EnsureOrganization(ctx, "managed", org)
		f.requireNoError(err)
		provider := keycloak.IdentityProvider{Alias: "organization-idp", ProviderID: "oidc", Enabled: false, Config: map[string]string{"clientId": "organization", "authorizationUrl": "https://identity.invalid/authorize", "tokenUrl": "https://identity.invalid/token"}}
		_, err = orgs.EnsureIdentityProvider(ctx, "managed", provider)
		f.requireNoError(err)
		f.requireNoError(orgs.EnsureOrganizationIdentityProvider(ctx, "managed", id, provider.Alias))
		provider.Alias = "organization-other-idp"
		_, err = orgs.EnsureIdentityProvider(ctx, "managed", provider)
		f.requireNoError(err)
		f.requireNoError(orgs.EnsureOrganizationIdentityProvider(ctx, "managed", id, provider.Alias))
		fixtureEqual(t, "organization manager cannot manage users", f.identityStatus("organizations-only", credential, http.MethodGet, "/admin/realms/managed/users", nil), http.StatusForbidden)
		fixtureEqual(t, "organization manager cannot manage master clients", f.identityStatus("organizations-only", credential, http.MethodGet, "/admin/realms/master/clients", nil), http.StatusForbidden)
		f.requireNoError(orgs.DeleteOrganization(ctx, "managed", id))
		f.requireNoError(orgs.DeleteIdentityProvider(ctx, "managed", provider.Alias))
		f.requireNoError(orgs.DeleteIdentityProvider(ctx, "managed", "organization-idp"))
	})

	f.run("read-only inventory", func(t *testing.T) {
		observer, credential := f.serviceClient("observer")
		f.grantClientRoles("observer", "managed", []string{"view-realm", "view-clients", "view-identity-providers"})
		_, err := observer.ListRealms(ctx)
		f.requireNoError(err)
		_, err = observer.GetRealm(ctx, "managed")
		f.requireNoError(err)
		_, err = observer.ListApps(ctx, "managed")
		f.requireNoError(err)
		_, err = observer.ListClientRoles(ctx, "managed", "minimal-app")
		f.requireNoError(err)
		_, err = observer.GetRealmRole(ctx, "managed", "reader")
		f.requireNoError(err)
		_, err = observer.ListIdentityProviders(ctx, "managed")
		f.requireNoError(err)
		fixtureEqual(t, "observer cannot update realm", f.identityStatus("observer", credential, http.MethodPut, "/admin/realms/managed", map[string]any{"displayName": "denied-observer"}), http.StatusForbidden)
		app := f.client("managed", "minimal-app")
		actualSecret, err := kc.GetClientSecret(ctx, "managed", "minimal-app")
		f.requireNoError(err)
		f.secrets = append(f.secrets, actualSecret)
		readSecret, readErr := observer.GetClientSecret(ctx, "managed", "minimal-app")
		if f.version == "26.7.5" {
			f.requireNoError(readErr)
			fixtureEqual(t, "26.7.5 view-clients includes secret reads; documented residual authority", readSecret, actualSecret)
		} else if !keycloak.IsForbidden(readErr) {
			t.Fatal("26.8.0 observer secret-read boundary changed; review permission contract")
		}
		fixtureEqual(t, "observer cannot rotate secrets on either version", f.identityStatus("observer", credential, http.MethodPost, "/admin/realms/managed/clients/"+app["id"].(string)+"/client-secret", nil), http.StatusForbidden)
	})

	f.run("native realm creation has scoped broad creator grants", func(t *testing.T) {
		creator, credential := f.serviceClient("realm-creator")
		client := f.client("master", "realm-creator")
		// New proxy role IDs do not exist beforehand. This optional identity uses
		// full scope so native creator grants become usable after token refresh.
		f.admin(http.MethodPut, "/admin/realms/master/clients/"+client["id"].(string), map[string]any{"fullScopeAllowed": true}, nil)
		var user, role map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/clients/"+client["id"].(string)+"/service-account-user", nil, &user)
		f.admin(http.MethodGet, "/admin/realms/master/roles/create-realm", nil, &role)
		f.admin(http.MethodPost, "/admin/realms/master/users/"+user["id"].(string)+"/role-mappings/realm", []any{role}, nil)
		f.requireNoError(creator.CreateRealm(ctx, keycloak.RealmSpec{ID: "created", Enabled: true}))
		f.requireNoError(creator.UpdateRealm(ctx, "created", keycloak.RealmSpec{Enabled: true, DisplayName: "Created"}))
		proxy := f.client("master", "created-realm")
		var grants []map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/users/"+user["id"].(string)+"/role-mappings/clients/"+proxy["id"].(string), nil, &grants)
		actual := make([]string, 0, len(grants))
		for _, grant := range grants {
			actual = append(actual, grant["name"].(string))
		}
		slices.Sort(actual)
		expected := "create-client,manage-authorization,manage-clients,manage-events,manage-identity-providers,manage-organizations,manage-realm,manage-users,query-clients,query-groups,query-organizations,query-realms,query-users,view-authorization,view-clients,view-events,view-identity-providers,view-organizations,view-realm,view-users"
		fixtureEqual(t, "native creator grants must match documented broad authority", strings.Join(actual, ","), expected)
		fixtureEqual(t, "creator cannot administer existing realm", f.identityStatus("realm-creator", credential, http.MethodPut, "/admin/realms/managed", map[string]any{"displayName": "denied-creator"}), http.StatusForbidden)
		fixtureEqual(t, "creator cannot modify master", f.identityStatus("realm-creator", credential, http.MethodPut, "/admin/realms/master", map[string]any{"displayName": "denied-creator"}), http.StatusForbidden)
		f.requireNoError(creator.DeleteRealm(ctx, "created"))
		var proxies []map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/clients?clientId=created-realm", nil, &proxies)
		fixtureEqual(t, "Keycloak removes native proxy", len(proxies), 0)
	})

	f.run("optional master authority is isolated", func(t *testing.T) {
		verifyRealInstanceCapabilityBoundary(f)
		hardener, hardenerCredential := f.serviceClient("master-hardener")
		f.grantClientRoles("master-hardener", "master", []string{"manage-realm"})
		f.requireNoError(hardener.HardenMasterRealm(ctx))
		version, err := hardener.ServerVersion(ctx)
		f.requireNoError(err)
		fixtureEqual(t, "master manager version disclosure", version, f.version)
		fixtureEqual(t, "master policy role cannot manage master clients", f.identityStatus("master-hardener", hardenerCredential, http.MethodPost, "/admin/realms/master/clients", map[string]any{"clientId": "denied-hardener"}), http.StatusForbidden)
		rotator, rotatorCredential := f.serviceClient("master-rotator")
		f.grantClientRoles("master-rotator", "master", []string{"manage-clients"})
		fixtureEqual(t, "master client role cannot change master policy", f.identityStatus("master-rotator", rotatorCredential, http.MethodPut, "/admin/realms/master", map[string]any{"displayName": "denied-rotator"}), http.StatusForbidden)
		pending := fixtureSecret(t)
		f.secrets = append(f.secrets, pending)
		f.requireNoError(rotator.SetClientSecret(ctx, "master", "master-rotator", pending))
		fixtureEqual(t, "rotated own credential authenticates", f.identityStatus("master-rotator", pending, http.MethodGet, "/admin/realms/master/clients", nil), http.StatusOK)
	})
}

func (f *keycloakFixture) run(name string, test func(*testing.T)) {
	parent := f.t
	parent.Run(name, func(t *testing.T) {
		f.t = t
		defer func() { f.t = parent }()
		test(t)
	})
}
