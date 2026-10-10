package keycloak

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func TestAuthorizationAdoptionRejectsEveryForeignIncomingEdge(t *testing.T) {
	owned := AuthorizationManagedObjects{ResourceServerID: "client", Scopes: []AuthorizationManagedReference{{Name: "read", ID: "scope"}}, Resources: []AuthorizationManagedReference{{Name: "invoice", ID: "resource"}}, Policies: []AuthorizationManagedReference{{Name: "role-policy", ID: "policy"}}, Permissions: []AuthorizationManagedReference{{Name: "readers", ID: "permission"}}}
	for name, graph := range map[string]InventoryAuthorizationGraph{
		"resource to scope":       {Resources: []InventoryAuthorizationResource{{ID: "foreign", Scopes: []InventoryAuthorizationScope{{ID: "scope"}}}}},
		"permission to resource":  {Permissions: []InventoryAuthorizationPermission{{ID: "foreign", Resources: []string{"resource"}}}},
		"permission to scope":     {Permissions: []InventoryAuthorizationPermission{{ID: "foreign", Scopes: []string{"scope"}}}},
		"permission to policy":    {Permissions: []InventoryAuthorizationPermission{{ID: "foreign", Policies: []string{"policy"}}}},
		"aggregate to policy":     {Policies: []InventoryAuthorizationPolicy{{ID: "foreign", AssociatedPolicies: []string{"policy"}}}},
		"aggregate to permission": {Policies: []InventoryAuthorizationPolicy{{ID: "foreign", AssociatedPolicies: []string{"permission"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := authorizationIncomingDependencies(graph, owned); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
				t.Fatal("foreign edge accepted", err)
			}
		})
	}
	graph := InventoryAuthorizationGraph{Resources: []InventoryAuthorizationResource{{ID: "resource", Scopes: []InventoryAuthorizationScope{{ID: "scope"}}}}, Policies: []InventoryAuthorizationPolicy{{ID: "policy", Roles: []policyRole{{ID: "external-role"}}, AssociatedPolicies: []string{"external-policy"}}}, Permissions: []InventoryAuthorizationPermission{{ID: "permission", Resources: []string{"resource"}, Scopes: []string{"scope"}, Policies: []string{"policy"}}}}
	if err := authorizationIncomingDependencies(graph, owned); err != nil {
		t.Fatal("owned outgoing edges/external principals acquired or rejected", err)
	}
	graph.Policies[0].Incomplete = true
	if err := authorizationIncomingDependencies(graph, owned); !errors.Is(err, ErrAdoptionPrecondition) {
		t.Fatal("incomplete dependency observation accepted", err)
	}
}

func TestAuthorizationJournalV2BindsReceiptApplicationAndClosedSchema(t *testing.T) {
	proof := adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoResourceServer", TargetUID: "server-uid", CandidateHash: "sha256:" + strings.Repeat("b", 64)}
	journal := authorizationJournal{Version: 2, OwnerUID: "server-uid", RealmID: "realm-id", ApplicationUID: "app-uid", Objects: AuthorizationManagedObjects{ResourceServerID: "client-id", Scopes: []AuthorizationManagedReference{{Name: "read", ID: "scope-id"}}}, AdoptionReceipt: &proof}
	for _, scenario := range []string{"valid", "foreign application", "wrong receipt kind", "wrong receipt UID", "unknown native", "unknown receipt field", "duplicate cross-kind ID", "missing realm"} {
		t.Run(scenario, func(t *testing.T) {
			data, _ := json.Marshal(journal)
			var j map[string]any
			_ = json.Unmarshal(data, &j)
			attrs := map[string]any{adoption.ApplicationOwnerKey: "app-uid"}
			switch scenario {
			case "foreign application":
				attrs[adoption.ApplicationOwnerKey] = "foreign-uid"
			case "wrong receipt kind":
				j["adoptionReceipt"].(map[string]any)["targetKind"] = "HankoApplication"
			case "wrong receipt UID":
				j["adoptionReceipt"].(map[string]any)["targetUID"] = "foreign-uid"
			case "unknown native":
				j["private.native"] = "secret-sentinel"
			case "unknown receipt field":
				j["adoptionReceipt"].(map[string]any)["secret"] = "secret-sentinel"
			case "duplicate cross-kind ID":
				j["objects"].(map[string]any)["resources"] = []any{map[string]any{"name": "invoice", "id": "scope-id"}}
			case "missing realm":
				delete(j, "realmID")
			}
			data, _ = json.Marshal(j)
			attrs[authorizationOwnerAttribute] = string(data)
			document := map[string]any{"id": "client-id", "clientId": "api", "attributes": attrs}
			_, found, err := parseAuthorizationJournal(document, "server-uid", "client-id")
			if scenario == "valid" {
				if err != nil || !found || journalValue(document) != string(data) {
					t.Fatal("valid V2 journal refused/rewritten", err)
				}
			} else if !errors.Is(err, ErrAuthorizationOwnershipConflict) {
				t.Fatal("invalid V2 journal accepted", err)
			}
		})
	}
}
