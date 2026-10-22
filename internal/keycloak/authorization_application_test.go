package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestAuthorizationRejectsUnownedBackingApplicationWithoutWrites(t *testing.T) {
	for _, scenario := range []string{"unmarked", "foreign owner", "missing UID", "credential client", "built-in client"} {
		t.Run(scenario, func(t *testing.T) {
			provider := newAuthorizationTestServer(t)
			model := authorizationTestModel()
			model.OwnerUID = "resource-server-uid"
			switch scenario {
			case "unmarked":
				delete(provider.attributes, "hanko.sh/application-owner")
			case "foreign owner":
				provider.attributes["hanko.sh/application-owner"] = "foreign-uid"
			case "missing UID":
				model.ApplicationUID = ""
			case "credential client":
				model.ApplicationRef = "operator"
			case "built-in client":
				model.ApplicationRef = "realm-management"
			}
			var err error
			if scenario == "credential client" || scenario == "built-in client" {
				// Protected IDs stay forbidden even with a matching ownership marker.
				_, err = provider.client().authorizationWriter(context.Background(), model, "client-uuid")
			} else {
				_, err = provider.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
			}
			if !errors.Is(err, ErrAuthorizationOwnershipConflict) || provider.mutationCount() != 0 {
				t.Fatalf("foreign application accepted: err=%v writes=%d", err, provider.mutationCount())
			}
		})
	}
}

func TestAuthorizationOwnershipDriftImmediatelyBeforeFirstWrite(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	model := authorizationTestModel()
	model.OwnerUID = "resource-server-uid"
	guardCalls := 0
	client := provider.client().WithMutationGuard(func(context.Context) error {
		guardCalls++
		provider.mu.Lock()
		provider.attributes["hanko.sh/application-owner"] = "foreign-uid"
		provider.mu.Unlock()
		return nil
	})
	_, err := client.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if !errors.Is(err, ErrAuthorizationOwnershipConflict) || guardCalls == 0 || provider.mutationCount() != 0 {
		t.Fatalf("ownership drift allowed a write: err=%v guard=%d writes=%d", err, guardCalls, provider.mutationCount())
	}
}

func TestAuthorizationJournalBindsExactApplicationOnRecovery(t *testing.T) {
	for _, scenario := range []string{"valid", "reference changed", "provider owner changed", "legacy owned", "legacy foreign"} {
		t.Run(scenario, func(t *testing.T) {
			provider := newAuthorizationTestServer(t)
			model := authorizationTestModel()
			model.OwnerUID = "resource-server-uid"
			journal := authorizationJournal{Version: 3, OwnerUID: model.OwnerUID, ApplicationUID: model.ApplicationUID,
				Objects: AuthorizationManagedObjects{ResourceServerID: "client-uuid"}}
			switch scenario {
			case "reference changed":
				model.ApplicationUID = "replacement-application"
			case "provider owner changed":
				provider.attributes["hanko.sh/application-owner"] = "replacement-application"
			case "legacy owned", "legacy foreign":
				journal.Version, journal.ApplicationUID = 1, ""
				if scenario == "legacy foreign" {
					delete(provider.attributes, "hanko.sh/application-owner")
				}
			}
			encoded, _ := json.Marshal(journal)
			provider.attributes[authorizationOwnerAttribute] = string(encoded)
			state, err := provider.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
			if scenario != "valid" && scenario != "legacy owned" {
				if !errors.Is(err, ErrAuthorizationOwnershipConflict) || provider.mutationCount() != 0 {
					t.Fatalf("foreign recovery accepted: err=%v writes=%d", err, provider.mutationCount())
				}
				return
			}
			if err != nil || len(state.ManagedObjects.Scopes) != 1 {
				t.Fatalf("owned graph did not converge: state=%+v err=%v", state, err)
			}
			provider.mu.Lock()
			raw := provider.attributes[authorizationOwnerAttribute].(string)
			provider.mu.Unlock()
			var saved authorizationJournal
			if json.Unmarshal([]byte(raw), &saved) != nil || saved.Version != 3 || saved.ApplicationUID != model.ApplicationUID || saved.OwnerUID != model.OwnerUID {
				t.Fatal("journal lost its exact application binding")
			}
		})
	}
}
