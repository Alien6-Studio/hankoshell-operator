package roles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestSettledRoleUsesFreshSingleReadAndDriftRetainsReadBack(t *testing.T) {
	plan := rolePlan(t, Intent{RealmRef: "realm", Name: "reader", Description: "desired"}, ResolvedReferences{Realm: "realm", Owner: "owner"}, iamcontract.Preconditions{})
	role := keycloak.RealmRole{Name: "reader", Description: "desired", Attributes: map[string][]string{OwnerAttribute: {"owner"}}}
	reads, writes, persist := 0, 0, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
			return
		}
		if r.URL.Path == "/admin/realms/realm/roles/reader/composites/realm" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		if r.URL.Path != "/admin/realms/realm/roles/reader" {
			t.Error("unexpected role endpoint")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			reads++
			_ = json.NewEncoder(w).Encode(role)
		case http.MethodPut:
			writes++
			var next keycloak.RealmRole
			if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
				t.Error(err)
			}
			if persist {
				role = next
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected role mutation")
		}
	}))
	defer server.Close()
	driver := NewKeycloakDriver(keycloak.New(server.URL, "operator", "fixture-credential", keycloak.WithInsecureHTTP()))
	ctx := context.Background()
	first, err := driver.Reconcile(ctx, plan)
	if err != nil || !first.Observation.Complete || first.Drifted || reads != 1 || writes != 0 {
		t.Fatal("settled non-composite role exceeded one full read")
	}
	second, err := driver.Reconcile(ctx, plan)
	if err != nil || reads != 2 || second.Observation != first.Observation {
		t.Fatal("another attempt reused evidence or changed canonical observation")
	}
	role.Description = "external-drift"
	repaired, err := driver.Reconcile(ctx, plan)
	if err != nil || writes != 1 || reads <= 3 || repaired.Drifted || role.Description != "desired" {
		t.Fatal("external drift was cached or mutation lacked independent read-back")
	}
	persist, role.Description = false, "unpersisted-drift"
	unpersisted, err := driver.Reconcile(ctx, plan)
	if err != nil || !unpersisted.Drifted || unpersisted.Observation.StateHash == repaired.Observation.StateHash {
		t.Fatal("successful PUT without persistence was reported synchronized")
	}
	role.Attributes[OwnerAttribute] = []string{"foreign"}
	before := writes
	if _, err := driver.Reconcile(ctx, plan); err != ErrOwnershipConflict || writes != before {
		t.Fatal("fresh ownership change did not refuse mutation")
	}
}

func TestCompositeRoleStillRefusesUnreadableClosure(t *testing.T) {
	plan := rolePlan(t, Intent{RealmRef: "realm", Name: "reader"}, ResolvedReferences{Realm: "realm", Owner: "owner"}, iamcontract.Preconditions{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
		} else if r.URL.Path == "/admin/realms/realm/roles/reader" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(keycloak.RealmRole{Name: "reader", Composite: true, Attributes: map[string][]string{OwnerAttribute: {"owner"}}})
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	driver := NewKeycloakDriver(keycloak.New(server.URL, "operator", "fixture-credential", keycloak.WithInsecureHTTP()))
	if _, err := driver.Reconcile(context.Background(), plan); err == nil {
		t.Fatal("composite closure failure became a complete observation")
	}
}
