//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestRealKeycloakServiceAccountAuthenticationRoundTrip(t *testing.T) {
	f := newKeycloakFixtureWithTransportAndDiscovery(t, false, false, true)
	ctx := context.Background()
	_, err := f.kc.CreateApp(ctx, "managed", keycloak.CreateAppSpec{ClientID: "round-trip", Name: "round-trip", Type: "m2m", ServiceAccountOwnerUID: "round-trip-owner", Attributes: map[string]string{"locale": "fr"}})
	f.requireNoError(err)
	credential, err := f.kc.GetServiceAccountSecretIfOwned(ctx, "managed", "round-trip", "round-trip-owner")
	f.requireNoError(err)
	f.secrets = append(f.secrets, credential)
	initial := f.client("managed", "round-trip")
	id := initial["id"].(string)
	path := "/admin/realms/managed/clients/" + id
	f.admin(http.MethodPost, path+"/roles", map[string]any{"name": "independent-use"}, nil)
	var role, serviceUser map[string]any
	f.admin(http.MethodGet, path+"/roles/independent-use", nil, &role)
	f.admin(http.MethodGet, path+"/service-account-user", nil, &serviceUser)
	grantPath := "/admin/realms/managed/users/" + serviceUser["id"].(string) + "/role-mappings/clients/" + id
	f.admin(http.MethodPost, grantPath, []any{role}, nil)
	var grantsBefore []map[string]any
	f.admin(http.MethodGet, grantPath, nil, &grantsBefore)
	for _, method := range []string{"federated-jwt", "client-secret", "federated-jwt"} {
		t.Log("qualifying native method " + method)
		old := f.client("managed", "round-trip")
		snapshot, err := f.kc.ReadClientOwnership(ctx, "managed", "round-trip")
		f.requireNoError(err)
		before, err := snapshot.AuthenticationStateHash()
		f.requireNoError(err)
		after, err := snapshot.AuthenticationTargetHash(method, "qualified-kube", "system:serviceaccount:workload:worker", method == "federated-jwt")
		f.requireNoError(err)
		applyErr := f.kc.ApplyServiceAccountAuthenticator(ctx, "managed", "round-trip", "round-trip-owner", "qualified-kube", "system:serviceaccount:workload:worker", method, snapshot, before, after, method == "federated-jwt", func(context.Context) error { return nil })
		if applyErr != nil {
			actual := f.client("managed", "round-trip")
			for key, value := range actual {
				if key != "secret" && !reflect.DeepEqual(value, old[key]) {
					t.Log("changed native field: " + key)
				}
			}
		}
		f.requireNoError(applyErr)
		native := f.client("managed", "round-trip")
		fixtureEqual(t, "native UUID retained", native["id"], id)
		fixtureEqual(t, "native method applied", native["clientAuthenticatorType"], method)
		fixtureEqual(t, "default scopes retained", native["defaultClientScopes"], initial["defaultClientScopes"])
		fixtureEqual(t, "optional scopes retained", native["optionalClientScopes"], initial["optionalClientScopes"])
		fixtureEqual(t, "independent attributes retained", native["attributes"].(map[string]any)["locale"], "fr")
		var grantsAfter []map[string]any
		f.admin(http.MethodGet, grantPath, nil, &grantsAfter)
		fixtureEqual(t, "independent authorization grants retained", grantsAfter, grantsBefore)
		var secret map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/clients/"+id+"/client-secret", nil, &secret)
		if secret["value"] != credential {
			t.Fatal("native recovery credential changed (values withheld)")
		}
	}
	t.Logf("Keycloak %s: native authentication round trip preserves UUID, credential and independent configuration", f.version)
}
