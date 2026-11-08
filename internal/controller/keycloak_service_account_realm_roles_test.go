//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// TestRealKeycloakServiceAccountRealmRoles checks the mappings Keycloak stores,
// that default and unmanaged mappings survive, and that view-only credentials
// cannot grant a role.
func TestRealKeycloakServiceAccountRealmRoles(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	f.requireNoError(f.kc.EnsureRealmRole(ctx, "managed", "SA_GRANTED", "granted"))
	f.requireNoError(f.kc.EnsureRealmRole(ctx, "managed", "SA_UNMANAGED", "unmanaged"))
	secret, err := f.kc.CreateApp(ctx, "managed", keycloak.CreateAppSpec{ClientID: "role-robot", Name: "role-robot", Type: "m2m", ServiceAccountOwnerUID: "role-owner"})
	f.requireNoError(err)
	f.secrets = append(f.secrets, secret)
	var clients []struct{ ID string }
	f.admin(http.MethodGet, "/admin/realms/managed/clients?clientId=role-robot", nil, &clients)
	var user struct{ ID string }
	f.admin(http.MethodGet, "/admin/realms/managed/clients/"+clients[0].ID+"/service-account-user", nil, &user)
	mappings := "/admin/realms/managed/users/" + user.ID + "/role-mappings/realm"
	var unmanaged keycloak.RealmRole
	f.admin(http.MethodGet, "/admin/realms/managed/roles/SA_UNMANAGED", nil, &unmanaged)
	f.admin(http.MethodPost, mappings, []keycloak.RealmRole{unmanaged}, nil)
	mapped := func() []string {
		var roles []keycloak.RealmRole
		f.admin(http.MethodGet, mappings, nil, &roles)
		names := make([]string, 0, len(roles))
		for _, role := range roles {
			names = append(names, role.Name)
		}
		return names
	}
	before := mapped()

	reader, _ := f.serviceClient("role-observer")
	f.grantClientRoles("role-observer", "managed", []string{"view-clients", "view-users"})
	if reader.ReconcileServiceAccountRealmRoles(ctx, "managed", "role-robot", []string{"SA_GRANTED"}, nil) == nil {
		t.Fatal("view-only identity granted a service-account realm role")
	}
	f.requireNoError(f.kc.ReconcileServiceAccountRealmRoles(ctx, "managed", "role-robot", []string{"SA_GRANTED"}, nil))
	f.requireNoError(f.kc.ReconcileServiceAccountRealmRoles(ctx, "managed", "role-robot", []string{"SA_GRANTED"}, []string{"SA_GRANTED"}))
	if got := mapped(); !slices.Contains(got, "SA_GRANTED") || len(got) != len(before)+1 {
		t.Fatalf("grant changed unrelated mappings: before=%v after=%v", before, got)
	}
	f.requireNoError(f.kc.ReconcileServiceAccountRealmRoles(ctx, "managed", "role-robot", nil, []string{"SA_GRANTED"}))
	got := mapped()
	slices.Sort(got)
	slices.Sort(before)
	if !slices.Equal(got, before) {
		t.Fatalf("revocation did not restore the original mappings: before=%v after=%v", before, got)
	}
}
