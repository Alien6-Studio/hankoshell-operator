package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

type authorizationTestServer struct {
	mu sync.Mutex

	server                *httptest.Server
	enabled               bool
	serviceAccountEnabled bool
	nextID                int

	scopes      map[string]authorizationScopeRepresentation
	resources   map[string]authorizationResourceRepresentation
	policies    map[string]authorizationPolicyRepresentation
	permissions map[string]authorizationPermissionRepresentation

	mutations   int
	deleteOrder []string
}

func newAuthorizationTestServer(t *testing.T) *authorizationTestServer {
	t.Helper()
	state := &authorizationTestServer{
		scopes: map[string]authorizationScopeRepresentation{}, resources: map[string]authorizationResourceRepresentation{},
		policies: map[string]authorizationPolicyRepresentation{}, permissions: map[string]authorizationPermissionRepresentation{},
		serviceAccountEnabled: true,
	}
	state.server = httptest.NewServer(state)
	t.Cleanup(state.server.Close)
	return state
}

func (s *authorizationTestServer) client() *Client {
	return New(s.server.URL, "operator", "secret", WithInsecureHTTP())
}

func (s *authorizationTestServer) mutationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutations
}

func (s *authorizationTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { //nolint:gocognit,cyclop // Small in-memory Keycloak Authorization Services fixture.
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
		writeAuthorizationJSON(w, map[string]any{"access_token": "token", "expires_in": 300})
		return
	}
	if r.URL.Path == "/admin/realms/acme/clients" && r.Method == http.MethodGet {
		clientID := r.URL.Query().Get("clientId")
		if clientID == "missing" {
			writeAuthorizationJSON(w, []map[string]string{})
			return
		}
		uuid := clientID + "-uuid"
		if clientID == "billing-api" {
			uuid = "client-uuid"
		}
		writeAuthorizationJSON(w, []map[string]string{{"id": uuid, "clientId": clientID}})
		return
	}
	if r.URL.Path == "/admin/realms/acme/clients/client-uuid" {
		switch r.Method {
		case http.MethodGet:
			writeAuthorizationJSON(w, map[string]any{
				"id": "client-uuid", "clientId": "billing-api",
				"authorizationServicesEnabled": s.enabled,
				"serviceAccountsEnabled":       s.serviceAccountEnabled,
			})
		case http.MethodPut:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.enabled, _ = body["authorizationServicesEnabled"].(bool)
			s.mutations++
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if r.URL.Path == "/admin/realms/acme/roles/billing-reader" && r.Method == http.MethodGet {
		writeAuthorizationJSON(w, RealmRole{ID: "role-id", Name: "billing-reader"})
		return
	}

	base := "/admin/realms/acme/clients/client-uuid/authz/resource-server"
	if !strings.HasPrefix(r.URL.Path, base) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, base)
	switch {
	case strings.HasSuffix(path, "/associatedPolicies") && r.Method == http.MethodGet:
		parts := strings.Split(strings.Trim(path, "/"), "/")
		permission := s.permissions[parts[1]]
		result := make([]map[string]string, 0, len(permission.Policies))
		for _, id := range permission.Policies {
			result = append(result, map[string]string{"id": id})
		}
		writeAuthorizationJSON(w, result)
	case path == "/scope" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, sortedMapValues(s.scopes))
	case path == "/resource" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, sortedMapValues(s.resources))
	case path == "/policy" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, sortedMapValues(s.policies))
	case path == "/policy/role" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, filterPolicies(s.policies, "role"))
	case path == "/policy/client" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, filterPolicies(s.policies, "client"))
	case path == "/permission" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, sortedMapValues(s.permissions))
	case path == "/permission/scope" && r.Method == http.MethodGet:
		writeAuthorizationJSON(w, sortedMapValues(s.permissions))
	case path == "/scope" && r.Method == http.MethodPost:
		var item authorizationScopeRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID = s.newID("scope")
		s.scopes[item.ID] = item
		s.created(w, item.ID)
	case path == "/resource" && r.Method == http.MethodPost:
		var item authorizationResourceRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID = s.newID("resource")
		s.resources[item.ID] = item
		s.created(w, item.ID)
	case path == "/policy/role" && r.Method == http.MethodPost:
		var item authorizationPolicyRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = s.newID("policy"), "role"
		s.policies[item.ID] = item
		s.created(w, item.ID)
	case path == "/policy/client" && r.Method == http.MethodPost:
		var item authorizationPolicyRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = s.newID("policy"), "client"
		s.policies[item.ID] = item
		s.created(w, item.ID)
	case path == "/permission/scope" && r.Method == http.MethodPost:
		var item authorizationPermissionRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = s.newID("permission"), "scope"
		s.permissions[item.ID] = item
		s.created(w, item.ID)
	case strings.HasPrefix(path, "/scope/") && r.Method == http.MethodPut:
		id := strings.TrimPrefix(path, "/scope/")
		var item authorizationScopeRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID = id
		s.scopes[id] = item
		s.updated(w)
	case strings.HasPrefix(path, "/resource/") && r.Method == http.MethodPut:
		id := strings.TrimPrefix(path, "/resource/")
		var item authorizationResourceRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID = id
		s.resources[id] = item
		s.updated(w)
	case strings.HasPrefix(path, "/policy/role/") && r.Method == http.MethodPut:
		id := strings.TrimPrefix(path, "/policy/role/")
		var item authorizationPolicyRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = id, "role"
		s.policies[id] = item
		s.updated(w)
	case strings.HasPrefix(path, "/policy/client/") && r.Method == http.MethodPut:
		id := strings.TrimPrefix(path, "/policy/client/")
		var item authorizationPolicyRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = id, "client"
		s.policies[id] = item
		s.updated(w)
	case strings.HasPrefix(path, "/permission/scope/") && r.Method == http.MethodPut:
		id := strings.TrimPrefix(path, "/permission/scope/")
		var item authorizationPermissionRepresentation
		_ = json.NewDecoder(r.Body).Decode(&item)
		item.ID, item.Type = id, "scope"
		s.permissions[id] = item
		s.updated(w)
	case r.Method == http.MethodDelete:
		s.delete(path)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, path), http.StatusNotFound)
	}
}

func (s *authorizationTestServer) newID(kind string) string {
	s.nextID++
	return fmt.Sprintf("%s-%d", kind, s.nextID)
}

func (s *authorizationTestServer) created(w http.ResponseWriter, id string) {
	s.mutations++
	w.Header().Set("Location", s.server.URL+"/objects/"+id)
	w.WriteHeader(http.StatusCreated)
}

func (s *authorizationTestServer) updated(w http.ResponseWriter) {
	s.mutations++
	w.WriteHeader(http.StatusNoContent)
}

func (s *authorizationTestServer) delete(path string) {
	s.mutations++
	parts := strings.Split(strings.Trim(path, "/"), "/")
	id := parts[len(parts)-1]
	kind := parts[0]
	s.deleteOrder = append(s.deleteOrder, kind)
	switch kind {
	case "scope":
		delete(s.scopes, id)
	case "resource":
		delete(s.resources, id)
	case "policy":
		delete(s.policies, id)
	case "permission":
		delete(s.permissions, id)
	}
}

func writeAuthorizationJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func sortedMapValues[T any](values map[string]T) []T {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]T, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result
}

func filterPolicies(values map[string]authorizationPolicyRepresentation, policyType string) []authorizationPolicyRepresentation {
	result := make([]authorizationPolicyRepresentation, 0)
	for _, value := range sortedMapValues(values) {
		if value.Type == policyType {
			result = append(result, value)
		}
	}
	return result
}

func authorizationTestModel() AuthorizationModel {
	return AuthorizationModel{
		Name: "billing", Realm: "acme", ApplicationRef: "billing-api", Audience: "https://api.example/billing",
		Scopes:    []AuthorizationScope{{Name: "invoices:read", Description: "Read invoices"}},
		Resources: []AuthorizationResource{{Name: "invoices", DisplayName: "Invoices", URIs: []string{"/invoices/*"}, Scopes: []string{"invoices:read"}}},
		Permissions: []AuthorizationPermission{{
			Name: "readers", Resources: []string{"invoices"}, Scopes: []string{"invoices:read"},
			Principals: []AuthorizationPrincipal{{Kind: "realm_role", Ref: "billing-reader"}},
		}},
	}
}

func TestAuthorizationReconcileIsIdempotentCorrectsDriftAndCleansInDependencyOrder(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	client := provider.client()
	model := authorizationTestModel()

	state, err := client.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	if state.ResourceServerID != "client-uuid" || len(state.ManagedObjects.Scopes) != 1 || len(state.ManagedObjects.Permissions) != 1 {
		t.Fatalf("state = %+v", state)
	}
	firstMutations := provider.mutationCount()
	if _, err := client.ReconcileAuthorization(context.Background(), model, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != firstMutations {
		t.Fatalf("idempotent reconcile made %d mutation(s)", provider.mutationCount()-firstMutations)
	}

	provider.mu.Lock()
	scopeID := state.ManagedObjects.Scopes[0].ID
	drifted := provider.scopes[scopeID]
	drifted.DisplayName = "drifted"
	provider.scopes[scopeID] = drifted
	provider.mu.Unlock()
	if _, err := client.ReconcileAuthorization(context.Background(), model, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != firstMutations+1 {
		t.Fatalf("drift correction mutations = %d, want 1", provider.mutationCount()-firstMutations)
	}

	provider.mu.Lock()
	provider.scopes["native-scope"] = authorizationScopeRepresentation{ID: "native-scope", Name: "provider-native"}
	provider.deleteOrder = nil
	provider.mu.Unlock()
	empty := model
	empty.Scopes, empty.Resources, empty.Permissions = nil, nil, nil
	cleaned, err := client.ReconcileAuthorization(context.Background(), empty, state.ManagedObjects)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	deletes := append([]string(nil), provider.deleteOrder...)
	_, nativePreserved := provider.scopes["native-scope"]
	provider.mu.Unlock()
	wantOrder := []string{"permission", "policy", "resource", "scope"}
	if strings.Join(deletes, ",") != strings.Join(wantOrder, ",") || !nativePreserved {
		t.Fatalf("delete order=%v nativePreserved=%v", deletes, nativePreserved)
	}
	if len(cleaned.ManagedObjects.Scopes)+len(cleaned.ManagedObjects.Resources)+len(cleaned.ManagedObjects.Policies)+len(cleaned.ManagedObjects.Permissions) != 0 {
		t.Fatalf("cleaned ownership = %+v", cleaned.ManagedObjects)
	}
}

func TestAuthorizationReconcileRequiresServiceAccountBeforeMutation(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	provider.serviceAccountEnabled = false

	_, err := provider.client().ReconcileAuthorization(context.Background(), authorizationTestModel(), AuthorizationManagedObjects{})
	if err == nil || !strings.Contains(err.Error(), "use HankoApplication type m2m") {
		t.Fatalf("error = %v", err)
	}
	if provider.mutationCount() != 0 {
		t.Fatalf("reconcile made %d mutation(s) before rejecting the client", provider.mutationCount())
	}
}

func TestAuthorizationObserveNeverMutatesAndUnownedEnabledServerConflicts(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	provider.enabled = true
	client := provider.client()
	before := provider.mutationCount()
	if _, err := client.ObserveAuthorization(context.Background(), authorizationTestModel()); err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != before {
		t.Fatal("ObserveAuthorization mutated provider state")
	}
	_, err := client.ReconcileAuthorization(context.Background(), authorizationTestModel(), AuthorizationManagedObjects{})
	if !errors.Is(err, ErrAuthorizationOwnershipConflict) || provider.mutationCount() != before {
		t.Fatalf("unowned reconcile err=%v mutations=%d", err, provider.mutationCount()-before)
	}
}

func TestAuthorizationDeleteUsesOnlyRecordedOwnership(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	client := provider.client()
	model := authorizationTestModel()
	state, err := client.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.scopes["native-scope"] = authorizationScopeRepresentation{ID: "native-scope", Name: "provider-native"}
	provider.mu.Unlock()
	if err := client.DeleteAuthorizationOwned(context.Background(), model, state.ResourceServerID, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if !provider.enabled || len(provider.permissions) != 0 || len(provider.policies) != 0 || len(provider.resources) != 0 {
		t.Fatalf("provider state remains enabled=%v permissions=%d policies=%d resources=%d", provider.enabled, len(provider.permissions), len(provider.policies), len(provider.resources))
	}
	if len(provider.scopes) != 1 || provider.scopes["native-scope"].Name != "provider-native" {
		t.Fatalf("unowned scopes changed: %+v", provider.scopes)
	}
}

func TestAuthorizationSupportsPortableClientPrincipals(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	model := authorizationTestModel()
	model.Permissions[0].Principals = []AuthorizationPrincipal{
		{Kind: "application", Ref: "portal"},
		{Kind: "service_account", Ref: "automation"},
	}
	state, err := provider.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatalf("reconcile portable client principals: %v", err)
	}
	if len(state.ManagedObjects.Policies) != 1 || len(state.ManagedObjects.Permissions) != 1 {
		t.Fatalf("portable client ownership = %#v", state.ManagedObjects)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	clients := map[string]bool{}
	for _, policy := range provider.policies {
		if policy.Type != "client" || len(policy.Clients) != 2 {
			t.Fatalf("client policy = %#v", policy)
		}
		for _, clientID := range policy.Clients {
			clients[clientID] = true
		}
	}
	if !clients["portal-uuid"] || !clients["automation-uuid"] {
		t.Fatalf("resolved client policy IDs = %#v", clients)
	}
}

func TestAuthorizationRejectsMissingPrincipalsBeforePermissionCreation(t *testing.T) {
	for _, principal := range []AuthorizationPrincipal{
		{Kind: "realm_role", Ref: "missing"},
		{Kind: "application", Ref: "missing"},
	} {
		provider := newAuthorizationTestServer(t)
		model := authorizationTestModel()
		model.Permissions[0].Principals = []AuthorizationPrincipal{principal}
		if _, err := provider.client().ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{}); err == nil {
			t.Fatalf("missing principal %s/%s must be rejected", principal.Kind, principal.Ref)
		}
		provider.mu.Lock()
		permissionCount := len(provider.permissions)
		provider.mu.Unlock()
		if permissionCount != 0 {
			t.Fatalf("missing principal created %d permission(s)", permissionCount)
		}
	}
}

func TestAuthorizationDeleteWithoutForeignObjectsDisablesOnlyOnce(t *testing.T) {
	provider := newAuthorizationTestServer(t)
	kc := provider.client()
	model := authorizationTestModel()
	state, err := kc.ReconcileAuthorization(context.Background(), model, AuthorizationManagedObjects{})
	if err != nil {
		t.Fatal(err)
	}
	if err := kc.DeleteAuthorizationOwned(context.Background(), model, state.ResourceServerID, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if provider.enabled {
		t.Fatal("empty owned graph remained enabled")
	}
	count := provider.mutationCount()
	if err := kc.DeleteAuthorizationOwned(context.Background(), model, state.ResourceServerID, state.ManagedObjects); err != nil {
		t.Fatal(err)
	}
	if provider.mutationCount() != count {
		t.Fatal("repeated cleanup mutated disabled graph")
	}
}
