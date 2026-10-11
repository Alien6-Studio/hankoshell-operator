//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// P6.2 requires complete dependent-client reads before provider mutation. This
// characterization keeps IdP authority separate from client inventory authority;
// an HTTP 403 must never be interpreted as an empty dependency collection.
func TestRealKeycloakWorkloadTrustRequiredInventoryPermissions(t *testing.T) {
	f := newKeycloakFixture(t)
	base := "/admin/realms/managed"
	f.admin(http.MethodPost, base+"/users", map[string]any{"username": "p62-negative-user", "enabled": true}, nil)
	var users []map[string]any
	f.admin(http.MethodGet, base+"/users?username=p62-negative-user&exact=true", nil, &users)
	if len(users) != 1 {
		t.Fatal("negative permission fixture user is ambiguous")
	}
	impersonation := base + "/users/" + users[0]["id"].(string) + "/impersonation"
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "p62-unrelated", "enabled": true}, nil)
	provider := map[string]any{
		"alias": "inventory-trust", "providerId": "kubernetes", "enabled": true,
		"config": map[string]string{"issuer": "https://inventory-cluster.example.test"},
	}
	f.admin(http.MethodPost, base+"/identity-provider/instances", provider, nil)
	// This native fixture client exists solely to demonstrate the dependency
	// inventory requirement. No HankoServiceAccount or controller activates it.
	dependentSecret := fixtureSecret(t)
	f.secrets = append(f.secrets, dependentSecret)
	f.admin(http.MethodPost, base+"/clients", map[string]any{
		"clientId": "foreign-trust-dependent", "protocol": "openid-connect",
		"secret":                  dependentSecret,
		"clientAuthenticatorType": "client-secret",
		"attributes":              map[string]string{"jwt.credential.issuer": "inventory-trust", "jwt.credential.sub": "system:serviceaccount:workloads:foreign"},
	}, nil)
	dependent := f.client("managed", "foreign-trust-dependent")
	dependent["secret"] = dependentSecret
	// Create a conventional credential first, then explicitly activate only this
	// native fixture. Keycloak's federated authenticator does not generate secrets.
	dependent["clientAuthenticatorType"] = "federated-jwt"
	f.admin(http.MethodPut, base+"/clients/"+dependent["id"].(string), dependent, nil)
	for _, profile := range []struct {
		name  string
		roles []string
	}{
		{"p62-trust-writer", []string{"manage-identity-providers", "view-realm"}},
		{"p62-trust-reader", []string{"view-identity-providers", "view-realm"}},
	} {
		kc, secret := f.serviceClient(profile.name)
		f.grantClientRoles(profile.name, "managed", profile.roles)
		for _, path := range []string{
			base, base + "/identity-provider/instances",
			base + "/identity-provider/instances/inventory-trust",
			base + "/authentication/flows/clients/executions",
		} {
			fixtureEqual(t, profile.name+" allowed read "+path,
				f.identityStatus(profile.name, secret, http.MethodGet, path, nil), http.StatusOK)
		}
		for _, path := range []string{
			base + "/clients?first=0&max=100",
			base + "/clients?clientId=foreign-trust-dependent",
			base + "/clients/" + dependent["id"].(string),
		} {
			fixtureEqual(t, profile.name+" dependent inventory denied "+path,
				f.identityStatus(profile.name, secret, http.MethodGet, path, nil), http.StatusForbidden)
		}
		clients, err := kc.InventoryClients(context.Background(), "managed")
		if err == nil || len(clients) != 0 {
			t.Fatal("denied dependency inventory must return an error and no partial collection")
		}
		fixtureEqual(t, "trust profile cannot impersonate actual user", f.identityStatus(profile.name, secret, http.MethodPost, impersonation, nil), http.StatusForbidden)
		fixtureEqual(t, "trust profile cannot inventory unrelated realm", f.identityStatus(profile.name, secret, http.MethodGet, "/admin/realms/p62-unrelated/clients", nil), http.StatusForbidden)
		fixtureEqual(t, "trust profile cannot administer unrelated realm", f.identityStatus(profile.name, secret, http.MethodPut, "/admin/realms/p62-unrelated", map[string]any{"enabled": false}), http.StatusForbidden)
		if profile.name == "p62-trust-reader" {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				path := base + "/identity-provider/instances/inventory-trust"
				if method == http.MethodPost {
					path = base + "/identity-provider/instances"
				}
				fixtureEqual(t, "reader IdP write denied", f.identityStatus(profile.name, secret, method, path, provider), http.StatusForbidden)
			}
		}
		t.Logf("Keycloak %s, %s: exact roles %v; IdP/realm/flow GET 200; client collection/filter/exact GET 403; production inventory blocks", f.version, profile.name, profile.roles)
	}
	reader, secret := f.serviceClient("p62-dependency-reader-control")
	f.grantClientRoles("p62-dependency-reader-control", "managed", []string{"view-clients"})
	f.requireNoError(reader.RestrictToDependentClients("managed"))
	clients, err := reader.ListKubernetesWorkloadTrustDependents(context.Background(), "managed")
	f.requireNoError(err)
	found := false
	for _, item := range clients {
		if item.ID == dependent["id"].(string) && item.Issuer == "inventory-trust" && item.Authenticator == "federated-jwt" {
			found = true
		}
	}
	if !found {
		t.Fatal("view-clients control did not observe the actual native dependent")
	}
	fixtureEqual(t, "dependency reader cannot mutate clients",
		f.identityStatus("p62-dependency-reader-control", secret, http.MethodPut, base+"/clients/"+dependent["id"].(string), dependent), http.StatusForbidden)
	t.Logf("Keycloak %s: separate view-clients control inventories the real native dependent; client PUT 403", f.version)
	// Native token authority and the controller's application route boundary are
	// distinct proofs. The credential is not confidential on 26.7.5.
	native := adoptionProbe{f, "p62-dependency-reader-control", secret}
	f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": "p62-native-secret-target", "protocol": "openid-connect", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "fullScopeAllowed": false, "clientAuthenticatorType": "client-secret", "secret": dependentSecret}, nil)
	secretTarget := f.client("managed", "p62-native-secret-target")
	var recovered struct {
		Value string `json:"value"`
	}
	status := native.request(http.MethodGet, base+"/clients/"+secretTarget["id"].(string)+"/client-secret", nil, &recovered)
	if f.version == "26.7.5" {
		fixtureEqual(t, "native reader credential secret authority", status, http.StatusOK)
		if recovered.Value != dependentSecret {
			t.Fatal("native secret access did not return the fixture credential (withheld)")
		}
	} else {
		fixtureEqual(t, "native 26.8 reader secret denial", status, http.StatusForbidden)
	}
	proxy, routes, _ := newAdoptionInventoryProxy(t, f, "p62-dependency-reader-control", secret)
	f.requireNoError(proxy.RestrictToDependentClients("managed"))
	projected, err := proxy.ListKubernetesWorkloadTrustDependents(context.Background(), "managed")
	f.requireNoError(err)
	f.requireNoCredentials("dependent metadata projection", fixtureJSON(t, projected))
	if _, err := proxy.GetClientSecret(context.Background(), "managed", "foreign-trust-dependent"); err == nil {
		t.Fatal("controller reader accepted credential operation")
	}
	for _, route := range routes() {
		if strings.Contains(route, "client-secret") || strings.HasPrefix(route, "PUT ") || strings.HasPrefix(route, "DELETE ") {
			t.Fatal("controller reader dispatched forbidden route")
		}
	}
	for _, request := range []struct {
		method, path string
		payload      any
	}{
		{http.MethodPost, base + "/clients", map[string]any{"clientId": "forbidden"}},
		{http.MethodPost, base + "/users", map[string]any{"username": "forbidden"}},
		{http.MethodPost, base + "/groups", map[string]any{"name": "forbidden"}},
		{http.MethodDelete, base, nil}, {http.MethodPut, base, map[string]any{"sslRequired": "none"}},
		{http.MethodPost, "/admin/realms", map[string]any{"realm": "forbidden"}},
		{http.MethodPut, "/admin/realms/master", map[string]any{"enabled": false}},
		{http.MethodGet, "/admin/realms/master/clients", nil},
		{http.MethodPost, impersonation, nil},
		{http.MethodGet, "/admin/realms/p62-unrelated/clients", nil},
		{http.MethodPut, "/admin/realms/p62-unrelated", map[string]any{"enabled": false}},
	} {
		fixtureEqual(t, "dependency reader native denial", f.identityStatus("p62-dependency-reader-control", secret, request.method, request.path, request.payload), http.StatusForbidden)
	}
	t.Logf("Keycloak %s: native reader client-secret HTTP %d; controller metadata transport dispatched zero credential routes; projection excludes fixture secret", f.version, status)
}
