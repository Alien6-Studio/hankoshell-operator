package keycloak

import (
	"encoding/json"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func TestBoundedActorPreservationRequiresItsOwnedClientBinding(t *testing.T) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount"} {
		for _, mutation := range []string{"owned", "unmarked", "missing-owner", "foreign-client", "foreign-uid", "empty-owners", "future-marker", "invalid-flag"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				key := adoption.ApplicationOwnerKey
				attributes := map[string]any{"standard.token.exchange.enabled": "true"}
				if kind == "HankoServiceAccount" {
					key = adoption.ClientOwnerUIDKey
					attributes[adoption.ClientOwnerKindKey] = kind
				}
				attributes[key] = "actor-owner"
				marker := boundedDelegationActorMarker{Version: 1, Actor: BoundedDelegationBinding{ID: "actor-id", Attribute: key, Value: "actor-owner"}, Owners: map[string]string{"api-id": "server-owner"}}
				switch mutation {
				case "missing-owner":
					delete(attributes, key)
				case "foreign-client":
					marker.Actor.ID = "foreign-client"
				case "foreign-uid":
					marker.Actor.Value = "foreign-owner"
				case "empty-owners":
					marker.Owners = map[string]string{}
				case "future-marker":
					marker.Version = 2
				case "invalid-flag":
					attributes["standard.token.exchange.enabled"] = "TRUE"
				}
				encoded, err := json.Marshal(marker)
				if err != nil {
					t.Fatal(err)
				}
				if mutation != "unmarked" {
					attributes[BoundedDelegationActorAttribute] = string(encoded)
				}
				document := map[string]any{"id": "actor-id", "clientId": "actor", "protocol": "openid-connect", "attributes": attributes}
				snapshot := &ClientOwnershipSnapshot{document: document, mappers: []map[string]any{}}
				if err := decodeSnapshot(document, &snapshot.Application); err != nil {
					t.Fatal(err)
				}
				if got, want := snapshot.PreservationQualified(), mutation == "owned"; got != want {
					t.Fatalf("native delegation preservation=%v, want %v", got, want)
				}
				if QualifiedClientAttributes(snapshot.Application.Attributes) || QualifiedClientAttribute("standard.token.exchange.enabled", "true") {
					t.Fatal("general attribute schema accepted native exchange activation")
				}
			})
		}
	}
}
