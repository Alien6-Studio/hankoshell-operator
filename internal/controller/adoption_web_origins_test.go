package controller

import (
	"slices"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestImportedWebOriginsPreserveNativeEmptyAndRestrictedPolicies(t *testing.T) {
	for _, origins := range [][]string{nil, {}, {"https://portal.test", "http://localhost:3000"}, {"+"}} {
		client := keycloak.InventoryClient{Application: keycloak.Application{ClientID: "portal", Protocol: "openid-connect", PublicClient: true, WebOrigins: origins}}
		spec, qualified := importedApplicationSpec("realm", client, nil, nil)
		if !qualified || spec.WebOrigins == nil || !slices.Equal(*spec.WebOrigins, origins) {
			t.Fatal("discovery replaced the observed CORS policy with an implicit default")
		}
		item := newInventoryItem("application", "realm", "uuid", "portal")
		facts := desiredInventoryFacts(item, &api.HankoApplication{Spec: spec})
		found := false
		for _, fact := range facts {
			if fact.Field == "webOrigins" {
				found = true
				if !slices.Equal(fact.Value.Set, origins) {
					t.Fatal("reviewed diff discarded explicit native origins")
				}
			}
		}
		if !found {
			t.Fatal("CORS policy absent from candidate review")
		}
	}
	for _, origin := range []string{"*", "https://portal.test?token=private", "https://user:password@portal.test"} {
		_, qualified := importedApplicationSpec("realm", keycloak.InventoryClient{Application: keycloak.Application{ClientID: "portal", Protocol: "openid-connect", WebOrigins: []string{origin}}}, nil, nil)
		if qualified {
			t.Fatal("discovery approved an unqualified origin policy")
		}
	}
}
