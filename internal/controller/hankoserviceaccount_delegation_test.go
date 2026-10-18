package controller

import (
	"encoding/json"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestCommittedFederatedAuthenticationPreservesOwnedDelegation(t *testing.T) {
	for _, mutation := range []string{"owned", "multiple-owners", "missing-marker", "foreign-uid", "foreign-client", "malformed-marker", "invalid-flag", "unknown-security"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.runAuthentication(4)
			if f.account.Status.Phase != "Ready" || f.journal().Step != "Committed" {
				t.Fatal("initial federated authentication did not commit")
			}
			native := f.dependents[0]
			id := native["id"].(string)
			owners := map[string]string{"delegated-api": "server-owner"}
			binding := map[string]string{"id": id, "attribute": adoption.ClientOwnerUIDKey, "value": string(f.account.UID)}
			if mutation == "foreign-uid" {
				binding["value"] = "foreign-owner"
			}
			if mutation == "foreign-client" {
				binding["id"] = "foreign-client"
			}
			if mutation == "multiple-owners" {
				owners["second-api"] = "second-server-owner"
			}
			marker, err := json.Marshal(map[string]any{"version": 1, "actor": binding, "previousExchange": "", "exchangePresent": false, "owners": owners})
			if err != nil {
				t.Fatal(err)
			}
			attributes := native["attributes"].(map[string]any)
			attributes[keycloak.BoundedDelegationActorAttribute] = string(marker)
			attributes["standard.token.exchange.enabled"] = "true"
			switch mutation {
			case "missing-marker":
				delete(attributes, keycloak.BoundedDelegationActorAttribute)
			case "malformed-marker":
				attributes[keycloak.BoundedDelegationActorAttribute] = "invalid"
			case "invalid-flag":
				attributes["standard.token.exchange.enabled"] = "TRUE"
			case "unknown-security":
				attributes["unqualified.security.setting"] = "true"
			}
			f.runAuthentication(2)
			wantReady := mutation == "owned" || mutation == "multiple-owners"
			if (f.account.Status.Phase == "Ready") != wantReady {
				t.Fatalf("delegation coexistence ready=%v, want %v; reason=%s", f.account.Status.Phase == "Ready", wantReady, conditionReason(f.account.Status.Conditions, "Synced"))
			}
			if native["id"] != id || native["clientAuthenticatorType"] != "federated-jwt" || f.creates != 1 || f.switches != 0 || f.rotations != 0 || f.credentialRoutes != 0 {
				t.Fatal("delegation coexistence changed the native authentication method or credential")
			}
			if wantReady {
				if attributes[keycloak.BoundedDelegationActorAttribute] != string(marker) || attributes["standard.token.exchange.enabled"] != "true" {
					t.Fatal("authentication reconciliation changed the owned delegation")
				}
				delete(attributes, keycloak.BoundedDelegationActorAttribute)
				delete(attributes, "standard.token.exchange.enabled")
				f.runAuthentication(2)
				if f.account.Status.Phase != "Ready" {
					t.Fatal("grant withdrawal invalidated committed federated authentication")
				}
			}
		})
	}
}
