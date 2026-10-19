package applications

import (
	"encoding/json"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"maps"
	"reflect"
	"strings"
	"testing"
)

func TestApplicationObservationSeparatesOwnedDelegation(t *testing.T) {
	p := testApplicationPlan(t, Intent{Protocol: "oidc", Pattern: "m2m", ClientID: "api"}, ResolvedReferences{}, iamcontract.Preconditions{})
	baseline, complete := observedClient(desired(p), p)
	if !complete {
		t.Fatal("baseline incomplete")
	}
	actor := keycloak.BoundedDelegationBinding{ID: "actor", Attribute: OwnerAttribute, Value: "actor-owner"}
	subject := keycloak.BoundedDelegationBinding{ID: "subject", Attribute: OwnerAttribute, Value: "subject-owner"}
	document := keycloak.BoundedDelegationDocument{Version: 1, Phase: "Committed", OwnerUID: "server-owner", Revision: "sha256:" + strings.Repeat("a", 64), RealmID: "realm", Audience: keycloak.BoundedDelegationBinding{ID: "api-id", Attribute: OwnerAttribute, Value: "uid"}, Grants: []keycloak.BoundedDelegationGrant{{Name: "read", Actor: actor, Subject: subject, MaxDepth: 2, MaxTTLSeconds: 30, Authority: keycloak.BoundedDelegationAuthority{Scopes: []string{}, RealmRoles: []string{}, ClientRoles: map[string][]string{}, Permissions: map[string][]string{"resource": {"read"}}}, Conditions: []keycloak.BoundedDelegationCondition{{Kind: "client", ID: "actor", Attribute: OwnerAttribute, Value: "actor-owner"}, {Kind: "client", ID: "subject", Attribute: OwnerAttribute, Value: "subject-owner"}}}}}
	for _, phase := range []string{"Prepared", "Applied", "Verified", "Committed"} {
		t.Run(phase, func(t *testing.T) {
			d := document
			d.Phase = phase
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			native := desired(p)
			native.ID = "api-id"
			native.Attributes[keycloak.BoundedDelegationAttribute] = string(raw)
			original := maps.Clone(native.Attributes)
			got, complete := observedClient(native, p)
			if !complete || !reflect.DeepEqual(got, baseline) {
				t.Fatal("owned sibling journal changed application semantics")
			}
			if !maps.Equal(native.Attributes, original) {
				t.Fatal("observation mutated native attributes")
			}
		})
	}
	for _, mutation := range []string{"owned", "foreign-uid", "foreign-client", "invalid", "unmarked", "disabled"} {
		t.Run("actor/"+mutation, func(t *testing.T) {
			native := desired(p)
			native.ID = "api-id"
			raw := `{"version":1,"actor":{"id":"api-id","attribute":"hanko.sh/application-owner","value":"uid"},"previousExchange":"false","exchangePresent":true,"owners":{"other-api":"server-owner"}}`
			switch mutation {
			case "foreign-uid":
				raw = strings.Replace(raw, `"value":"uid"`, `"value":"foreign"`, 1)
			case "foreign-client":
				raw = strings.Replace(raw, `"id":"api-id"`, `"id":"foreign"`, 1)
			case "invalid":
				raw = `{"opaque":"private-sentinel"}`
			}
			if mutation != "unmarked" {
				native.Attributes[keycloak.BoundedDelegationActorAttribute] = raw
			}
			native.Attributes["standard.token.exchange.enabled"] = "true"
			if mutation == "disabled" {
				native.Attributes["standard.token.exchange.enabled"] = "false"
			}
			got, complete := observedClient(native, p)
			valid := mutation == "owned"
			if valid != (complete && reflect.DeepEqual(got, baseline)) {
				t.Fatal("actor activation ownership classification incorrect")
			}
			if _, present := got.Attributes[keycloak.BoundedDelegationActorAttribute]; present {
				t.Fatal("sibling actor document entered application observation")
			}
		})
	}
}
