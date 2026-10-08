//go:build keycloak_integration

package controller_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

// TestRealKeycloakIAMContract runs shared behavior fixtures through the common
// least-privilege profile and HTTPS. Only bootstrap injects drift/foreign objects.
func TestRealKeycloakIAMContract(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	// Verify fixture renewal through the real token endpoint without increasing
	// token lifetimes or retrying denied administrative requests.
	f.adminToken, f.adminAt = "expired-bootstrap-fixture", time.Now().Add(-time.Minute)
	kc, credential := f.serviceClient("contract-operator")
	f.grantClientRoles("contract-operator", "managed", []string{"manage-realm", "manage-clients", "manage-events"})
	observer, observerSecret := f.serviceClient("contract-observer")
	f.grantClientRoles("contract-observer", "managed", []string{"view-realm", "view-clients", "view-authorization"})
	f.admin(http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)

		return len(events)
	}
	f.run("roles shared conformance", func(t *testing.T) {
		driver := roles.NewKeycloakDriver(kc)
		reader := roles.NewKeycloakDriver(observer)
		intent := roles.Intent{RealmRef: "managed", Name: "contract-role", Description: "desired", Composites: []string{"contract-child-b", "contract-child-a"}}
		resolved := roles.ResolvedReferences{Realm: "managed", Owner: "contract-role-uid", Attributes: map[string][]string{"team": {"platform"}}}
		for _, name := range []string{"contract-child-a", "contract-child-b", "contract-foreign"} {
			f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": name}, nil)
		}
		compile := func(reverse bool) roles.Plan {
			i := intent
			i.Composites = append([]string{}, i.Composites...)
			if reverse {
				slices.Reverse(i.Composites)
			}
			p, err := roles.Compile(i, resolved, roles.KeycloakEvidence(), iamcontract.Preconditions{})
			f.requireNoError(err)
			return p
		}
		plan := compile(false)
		iamconformance.Run(t, iamconformance.Fixture{
			Compile: func(reverse bool) iamcontract.PlanIdentity { return compile(reverse).Identity() }, Writes: writes,
			Refuse: func() error {
				e := roles.KeycloakEvidence()
				e.Supported.Composites = false
				_, err := roles.Compile(intent, resolved, e, iamcontract.Preconditions{})
				return err
			},
			Manage: func() error {
				state, err := driver.Reconcile(ctx, plan)
				if err == nil && (!state.Present || !state.Owned || state.Drifted) {
					return errors.New("role failed read-back")
				}
				return err
			},
			Observe: func() error { _, err := reader.Observe(ctx, plan); return err },
			DriftAndRepair: func() error {
				var actual map[string]any
				f.admin(http.MethodGet, "/admin/realms/managed/roles/contract-role", nil, &actual)
				actual["description"] = "drift"
				f.admin(http.MethodPut, "/admin/realms/managed/roles/contract-role", actual, nil)
				state, err := driver.Observe(ctx, plan)
				if err != nil {
					return err
				}
				if !state.Drifted {
					return errors.New("role drift not observed")
				}
				_, err = driver.Reconcile(ctx, plan)
				if err != nil {
					return err
				}
				state, err = driver.Observe(ctx, plan)
				if err == nil && state.Drifted {
					return errors.New("role drift not repaired")
				}
				return err
			},
			Foreign: func() error {
				i := intent
				i.Name = "contract-foreign"
				p, err := roles.Compile(i, resolved, roles.KeycloakEvidence(), iamcontract.Preconditions{})
				if err != nil {
					return err
				}
				_, err = driver.Reconcile(ctx, p)
				if !errors.Is(err, roles.ErrOwnershipConflict) {
					t.Fatal("foreign role refusal differs")
				}
				if err := driver.DeleteOwned(ctx, p); !errors.Is(err, roles.ErrOwnershipConflict) {
					t.Fatal("foreign role deletion accepted")
				}
				return err
			},
			DeleteOwned: func() error { return driver.DeleteOwned(ctx, plan) },
			VerifyDeleted: func() error {
				var actual map[string]any
				if f.admin(http.MethodGet, "/admin/realms/managed/roles/contract-role", nil, &actual) != http.StatusNotFound {
					return errors.New("owned role still present")
				}
				if f.admin(http.MethodGet, "/admin/realms/managed/roles/contract-foreign", nil, &actual) != http.StatusOK {
					return errors.New("foreign role removed")
				}
				return nil
			},
		})
		iamconformance.NoSecrets(t, []string{credential, f.adminToken}, plan, plan.Identity())
	})
	f.run("authorization shared conformance", func(t *testing.T) {
		driver := authorization.NewKeycloakDriver(kc)
		reader := authorization.NewKeycloakDriver(observer)
		f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "contract-api", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true}, nil)
		model := authorization.Model{Name: "contract-auth", Realm: "managed", Audience: "urn:contract-api", ApplicationRef: "contract-api", Scopes: []authorization.Scope{{Name: "read", Description: "desired"}, {Name: "write"}}, Resources: []authorization.Resource{{Name: "document", Scopes: []string{"read", "write"}, URIs: []string{"/b", "/a"}}}, Permissions: []authorization.Permission{{Name: "access", Scopes: []string{"read"}, Resources: []string{"document"}, Principals: []authorization.Principal{{Kind: "realm_role", Ref: "contract-child-a"}}}}}
		compile := func(reverse bool) authorization.Plan {
			m := model
			m.Scopes = append([]authorization.Scope{}, m.Scopes...)
			if reverse {
				slices.Reverse(m.Scopes)
			}
			i := authorization.Normalize(m)
			r, err := authorization.Resolve(i, m)
			f.requireNoError(err)
			caps, err := driver.Capabilities(ctx, m.Realm)
			f.requireNoError(err)
			p, err := authorization.Compile(i, r, authorization.KeycloakEvidence(caps), iamcontract.Preconditions{ResourceUID: "authorization-contract-owner"})
			f.requireNoError(err)
			return p
		}
		_, unprivilegedSecret := f.serviceClient("contract-unprivileged")
		plan := compile(false)
		var owned authorization.ManagedObjects
		iamconformance.Run(t, iamconformance.Fixture{
			Compile: func(reverse bool) iamcontract.PlanIdentity { return compile(reverse).Identity() }, Writes: writes,
			Refuse: func() error {
				i := authorization.Normalize(model)
				r, _ := authorization.Resolve(i, model)
				_, err := authorization.Compile(i, r, authorization.KeycloakEvidence(authorization.Capabilities{}), iamcontract.Preconditions{})
				return err
			},
			Manage: func() error {
				state, err := driver.Reconcile(ctx, plan, owned)
				if err == nil {
					owned = state.ManagedObjects
					if len(owned.Permissions) == 1 {
						path := "/admin/realms/managed/clients/" + owned.ResourceServerID + "/authz/resource-server/policy/" + owned.Permissions[0].ID + "/associatedPolicies"
						fixtureEqual(t, "observer associated-policy read succeeds", f.identityStatus("contract-observer", observerSecret, http.MethodGet, path, nil), http.StatusOK)
						fixtureEqual(t, "unprivileged associated-policy read denied", f.identityStatus("contract-unprivileged", unprivilegedSecret, http.MethodGet, path, nil), http.StatusForbidden)
					}
				}
				return err
			},
			Observe: func() error { _, err := reader.Observe(ctx, plan); return err },
			DriftAndRepair: func() error {
				base := "/admin/realms/managed/clients/" + owned.ResourceServerID + "/authz/resource-server/scope"
				var scope map[string]any
				// The Admin API has no GET-by-ID in the runtime inventory: bootstrap
				// reads the existing collection and edits the selected owned scope.
				var scopes []map[string]any
				f.admin(http.MethodGet, base, nil, &scopes)
				for _, v := range scopes {
					if v["name"] == "read" {
						scope = v
					}
				}
				f.admin(http.MethodPost, base, map[string]any{"name": "contract-foreign-scope"}, nil)
				for i := range 100 {
					f.admin(http.MethodPost, base, map[string]any{"name": "000-contract-native-" + strconv.Itoa(i)}, nil)
				}
				scope["displayName"] = "drift"
				f.admin(http.MethodPut, base+"/"+scope["id"].(string), scope, nil)
				observation, err := driver.Observe(ctx, plan)
				if err == nil && !observation.Drifted {
					return errors.New("authorization drift not observed")
				}
				if err != nil {
					return err
				}
				state, err := driver.Reconcile(ctx, plan, owned)
				if err != nil {
					return err
				}
				owned = state.ManagedObjects
				f.admin(http.MethodGet, base+"?first=0&max=1000", nil, &scopes)
				for _, v := range scopes {
					if v["name"] == "read" && v["displayName"] != "desired" {
						return errors.New("authorization drift not repaired")
					}
				}
				return nil
			},
			Foreign: func() error {
				i := authorization.Normalize(model)
				r, _ := authorization.Resolve(i, model)
				caps, _ := driver.Capabilities(ctx, model.Realm)
				foreignPlan, err := authorization.Compile(i, r, authorization.KeycloakEvidence(caps), iamcontract.Preconditions{ResourceUID: "foreign-owner"})
				if err != nil {
					return err
				}
				_, err = driver.Reconcile(ctx, foreignPlan, authorization.ManagedObjects{})
				if !errors.Is(err, authorization.ErrOwnershipConflict) {
					t.Fatal("foreign graph refusal differs")
				}
				return err
			},
			DeleteOwned: func() error { return driver.DeleteOwned(ctx, model, owned, "authorization-contract-owner") },
			VerifyDeleted: func() error {
				base := "/admin/realms/managed/clients/" + owned.ResourceServerID + "/authz/resource-server/scope"
				var scopes []map[string]any
				f.admin(http.MethodGet, base+"?first=0&max=1000", nil, &scopes)
				foreign := false
				nativeCount := 0
				for _, v := range scopes {
					if name, ok := v["name"].(string); ok && strings.HasPrefix(name, "000-contract-native-") {
						nativeCount++
					}
					if v["name"] == "contract-foreign-scope" {
						foreign = true
					}
					if v["name"] == "read" || v["name"] == "write" {
						return errors.New("owned scope still present")
					}
				}
				if !foreign || nativeCount != 100 {
					return errors.New("foreign scope removed")
				}
				return nil
			},
		})
		iamconformance.NoSecrets(t, []string{credential, f.adminToken}, plan, plan.Identity())
	})
	checkRealKeycloakEvidenceRecovery(t, f, kc, credential)
}
