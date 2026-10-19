package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckpointCapacityRefusesBeforeNativeOrCredentialWrites(t *testing.T) {
	ctx := context.Background()
	app := &api.HankoApplication{}
	for i := range statusInventoryLimit {
		name := fmt.Sprintf("retained-%03d", i)
		app.Status.ManagedIdentityMappings = append(app.Status.ManagedIdentityMappings, api.ManagedIdentityMappingReference{Name: name, KeycloakID: "retained-id"})
		app.Status.ManagedTokenClaims = append(app.Status.ManagedTokenClaims, api.ManagedTokenClaimReference{Name: name, KeycloakID: "retained-id"})
		app.Status.ManagedClientSecretProjections = append(app.Status.ManagedClientSecretProjections, api.ApplicationSecretProjection{Namespace: "workload", Name: name})
	}
	app.Spec.IdentityMappings = []api.ApplicationIdentityMapping{{Name: "new-mapping"}}
	app.Spec.TokenClaims = []api.ApplicationTokenClaim{{Name: "new-claim"}}
	app.Spec.ClientSecretProjections = []api.ApplicationSecretProjection{{Namespace: "workload", Name: "new-projection"}}
	before := app.DeepCopy()
	// Nil clients are intentional: every refusal must happen before even a
	// provider lookup or projection write. All existing cleanup evidence stays.
	r := &HankoApplicationReconciler{}
	for _, call := range []func() error{
		func() error { return r.reconcileIdentityMappings(ctx, app, nil) },
		func() error { return r.reconcileTokenClaims(ctx, app, nil) },
		func() error { return r.reconcileSecretProjections(ctx, app, "never-delivered", nil) },
	} {
		if err := call(); !errors.Is(err, errStatusInventoryCapacity) {
			t.Fatalf("unreserved native write was not refused: %v", err)
		}
		if !reflect.DeepEqual(before, app) {
			t.Fatal("capacity refusal lost or manufactured accepted identity evidence")
		}
	}
	claims, err := preflightTokenClaims("workload", "owner", 1, app.Spec.TokenClaims, app.Status.ManagedTokenClaims)
	if !errors.Is(err, errStatusInventoryCapacity) || !reflect.DeepEqual(claims, before.Status.ManagedTokenClaims) {
		t.Fatal("invalid-claim preflight exceeded its status reservation")
	}
	realm := &api.HankoRealm{Spec: api.HankoRealmSpec{IdentityProviders: []api.RealmIdentityProvider{{Alias: "new-broker"}}}}
	for i := range statusInventoryLimit {
		realm.Status.ManagedIdentityProviders = append(realm.Status.ManagedIdentityProviders, api.ManagedRealmIdentityProviderReference{Alias: fmt.Sprintf("retained-%03d", i)})
	}
	prior := realm.DeepCopy()
	if err := (&HankoRealmReconciler{}).reconcileRealmIdentityProviders(ctx, realm, nil); !errors.Is(err, errStatusInventoryCapacity) || !reflect.DeepEqual(realm, prior) {
		t.Fatal("realm capacity refusal changed recovery evidence or reached a client", err)
	}
	realm.Status.ManagedIdentityProviders = []api.ManagedRealmIdentityProviderReference{{Alias: "new-broker"}}
	realm.Spec.IdentityProviders[0].Mappers = []api.RealmIdentityProviderMapper{{Name: "new-mapper"}}
	for i := range statusInventoryLimit {
		realm.Status.ManagedIdentityProviders[0].Mappers = append(realm.Status.ManagedIdentityProviders[0].Mappers, api.ManagedRealmIdentityProviderMapperReference{Name: fmt.Sprintf("retained-%03d", i), KeycloakID: "accepted"})
	}
	prior = realm.DeepCopy()
	if err := (&HankoRealmReconciler{}).reconcileRealmIdentityProviders(ctx, realm, nil); !errors.Is(err, errStatusInventoryCapacity) || !reflect.DeepEqual(realm, prior) {
		t.Fatal("nested mapper checkpoint exceeded its reservation", err)
	}
}

func TestCheckpointReservationMatchesEveryAdmissionInventory(t *testing.T) {
	data, err := os.ReadFile("../../api/schema-status-bounds.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Bounds []struct {
			Path   string
			Limits map[string]int
		}
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range policy.Bounds {
		switch entry.Path {
		case "status.managedIdentityMappings", "status.managedTokenClaims", "status.managedClientSecretProjections", "status.managedIdentityProviders", "status.managedIdentityProviders[].mappers":
			count++
			if entry.Limits["maxItems"] != statusInventoryLimit {
				t.Fatal("controller reservation differs from admission", entry.Path)
			}
		}
	}
	if count != 6 {
		t.Fatal("missing guarded recovery inventory", count)
	}
	if checkStatusInventoryCapacity(64, 64) != nil || checkStatusInventoryCapacity(128, 0) != nil || !errors.Is(checkStatusInventoryCapacity(128, 1), errStatusInventoryCapacity) {
		t.Fatal("reservation cannot retain a full previous batch or clean an exhausted one")
	}
}

func TestRealmCheckpointRetainsOldMapperIDsUntilCleanupAcknowledgement(t *testing.T) {
	old := []api.ManagedRealmIdentityProviderReference{{Alias: "broker", Mappers: []api.ManagedRealmIdentityProviderMapperReference{{Name: "claim", KeycloakID: "old-id"}, {Name: "removed", KeycloakID: "old-removed"}}}}
	current := []api.ManagedRealmIdentityProviderReference{{Alias: "broker", Mappers: []api.ManagedRealmIdentityProviderMapperReference{{Name: "claim", KeycloakID: "new-id"}}}}
	checkpoint := checkpointManagedRealmIdentityProviders(current, old)
	if len(checkpoint) != 1 || len(checkpoint[0].Mappers) != 3 || checkpoint[0].Mappers[1].KeycloakID != "old-id" || checkpoint[0].Mappers[2].KeycloakID != "old-removed" {
		t.Fatal("partial provider update dropped pre-existing cleanup identities", checkpoint)
	}
	checkpoint[0].Mappers[0].KeycloakID = "changed"
	checkpoint[0].Mappers[1].KeycloakID = "changed"
	if old[0].Mappers[0].KeycloakID != "old-id" || current[0].Mappers[0].KeycloakID != "new-id" {
		t.Fatal("checkpoint mutated immutable prior observations")
	}
}

func TestOperationDiagnosticBudgetKeepsCheckpointAndUnicode(t *testing.T) {
	for _, n := range []int{4096, 4097} {
		step := api.OperationStep{Name: "Validate", ChildUID: "accepted-child", Status: "Running"}
		message := strings.Repeat("é", n)
		now := metav1.Now()
		setStepStatus(&step, "Failed", message, &now)
		if step.Status != "Failed" || step.ChildUID != "accepted-child" || step.CompletedAt != &now {
			t.Fatal("diagnostic bound altered lifecycle checkpoint semantics")
		}
		if n == 4096 && step.Message != message || n > 4096 && step.Message != "operation diagnostic exceeds the public status size budget" {
			t.Fatal("diagnostic must preserve in-budget Unicode or publish a fixed refusal")
		}
	}
}
