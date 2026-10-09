package controller_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

var (
	reClientsCollection    = regexp.MustCompile(`^/admin/realms/[^/]+/clients$`)
	reRealmByName          = regexp.MustCompile(`^/admin/realms/([^/]+)$`)
	reClientByID           = regexp.MustCompile(`^/admin/realms/[^/]+/clients/[^/]+$`)
	reClientRoles          = regexp.MustCompile(`^/admin/realms/[^/]+/clients/[^/]+/roles$`)
	reClientRoleByName     = regexp.MustCompile(`^/admin/realms/([^/]+)/clients/([^/]+)/roles/([^/]+)$`)
	reClientRoleComposites = regexp.MustCompile(`^/admin/realms/([^/]+)/clients/([^/]+)/roles/([^/]+)/composites$`)
	reClientSecret         = regexp.MustCompile(`^/admin/realms/[^/]+/clients/[^/]+/client-secret$`)
	reRealmFromClients     = regexp.MustCompile(`^/admin/realms/([^/]+)/clients`)
	reIDPProviders         = regexp.MustCompile(`^/admin/realms/([^/]+)/identity-provider/instances$`)
	reIDPProviderByAlias   = regexp.MustCompile(`^/admin/realms/([^/]+)/identity-provider/instances/([^/]+)$`)
	reIDPMappersCollection = regexp.MustCompile(`^/admin/realms/([^/]+)/identity-provider/instances/([^/]+)/mappers$`)
	reIDPMapperByID        = regexp.MustCompile(`^/admin/realms/([^/]+)/identity-provider/instances/([^/]+)/mappers/([^/]+)$`)
	reProtocolCollection   = regexp.MustCompile(`^/admin/realms/([^/]+)/clients/([^/]+)/protocol-mappers/models$`)
	reProtocolMapperByID   = regexp.MustCompile(`^/admin/realms/([^/]+)/clients/([^/]+)/protocol-mappers/models/([^/]+)$`)
	reRealmRolesCollection = regexp.MustCompile(`^/admin/realms/([^/]+)/roles$`)
	reRealmRoleByName      = regexp.MustCompile(`^/admin/realms/([^/]+)/roles/([^/]+)$`)
	reRealmRoleComposites  = regexp.MustCompile(`^/admin/realms/([^/]+)/roles/([^/]+)/composites$`)
	reRealmRoleCompositesR = regexp.MustCompile(`^/admin/realms/([^/]+)/roles/([^/]+)/composites/realm$`)
	reGroupByPath          = regexp.MustCompile(`^/admin/realms/([^/]+)/group-by-path/(.+)$`)
	reGroupByID            = regexp.MustCompile(`^/admin/realms/([^/]+)/groups/([^/]+)$`)
	reGroupRoleMappings    = regexp.MustCompile(`^/admin/realms/([^/]+)/groups/([^/]+)/role-mappings$`)
	reGroupsCollection     = regexp.MustCompile(`^/admin/realms/([^/]+)/groups$`)
	reGroupChildren        = regexp.MustCompile(`^/admin/realms/([^/]+)/groups/([^/]+)/children$`)
	reOrganizations        = regexp.MustCompile(`^/admin/realms/([^/]+)/organizations$`)
	reOrganizationByID     = regexp.MustCompile(`^/admin/realms/([^/]+)/organizations/([^/]+)$`)
)

// mockKeycloak is a minimal, in-memory stand-in for the Keycloak Admin REST API,
// used to observe exactly which mutating endpoints a reconcile call touches
// (CreateApp/UpdateApp/DeleteApp/secret retrieval must never fire in Observe
// or Conflict paths).
type mockKeycloak struct {
	mu sync.Mutex
	t  *testing.T

	server *httptest.Server

	realms          []keycloak.Realm
	appsByRealm     map[string][]keycloak.App
	clientUUID      map[string]string         // "realm|clientID" -> uuid
	clientState     map[string]map[string]any // complete non-secret client representation
	idpsByRealm     map[string][]keycloak.IdentityProvider
	idpMappers      map[string][]keycloak.IdentityProviderMapper
	protocolMappers map[string][]keycloak.ProtocolMapper
	nextMapperID    int

	realmRoles               map[string]map[string]keycloak.RealmRole // realm -> role name -> role
	realmComposite           map[string][]string                      // "realm|parent" -> child role names
	clientRoles              map[string]map[string]keycloak.RealmRole // "realm|client UUID" -> role name -> role
	clientComposite          map[string][]keycloak.RealmRole          // "realm|client UUID|parent" -> child roles
	roleLookupStatus         int
	groupsByPath             map[string]keycloak.Group           // "realm|path" -> group
	groupRealmRoles          map[string][]string                 // "realm|group ID" -> direct realm role names
	groupClientRoles         map[string][]mockGroupClientRoleSet // "realm|group ID" -> direct client roles
	groupLookupStatus        int
	organizations            map[string][]keycloak.Organization // realm -> organizations
	organizationLookupStatus int

	// discoveryStatus is returned by the OIDC discovery well-known endpoint.
	// Defaults to 200 when zero.
	discoveryStatus int

	counts map[string]int
}

func newMockKeycloak(t *testing.T) *mockKeycloak {
	m := &mockKeycloak{
		t:                t,
		appsByRealm:      map[string][]keycloak.App{},
		clientUUID:       map[string]string{},
		clientState:      map[string]map[string]any{},
		idpsByRealm:      map[string][]keycloak.IdentityProvider{},
		idpMappers:       map[string][]keycloak.IdentityProviderMapper{},
		protocolMappers:  map[string][]keycloak.ProtocolMapper{},
		counts:           map[string]int{},
		realmRoles:       map[string]map[string]keycloak.RealmRole{},
		realmComposite:   map[string][]string{},
		clientRoles:      map[string]map[string]keycloak.RealmRole{},
		clientComposite:  map[string][]keycloak.RealmRole{},
		groupsByPath:     map[string]keycloak.Group{},
		groupRealmRoles:  map[string][]string{},
		groupClientRoles: map[string][]mockGroupClientRoleSet{},
		organizations:    map[string][]keycloak.Organization{},
	}
	m.server = httptest.NewServer(m)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockKeycloak) addOrganization(realm string, organization keycloak.Organization) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.organizations[realm] = append(m.organizations[realm], organization)
}

type mockGroupClientRoleSet struct {
	clientID string
	uuid     string
	roles    []string
}

func (m *mockKeycloak) addGroup(realm string, group keycloak.Group, realmRoles ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groupsByPath[realm+"|"+group.Path] = group
	m.groupRealmRoles[realm+"|"+group.ID] = append([]string(nil), realmRoles...)
}

func (m *mockKeycloak) addGroupClientRoles(realm, groupID, clientID, uuid string, roles ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := realm + "|" + groupID
	m.groupClientRoles[key] = append(m.groupClientRoles[key], mockGroupClientRoleSet{
		clientID: clientID,
		uuid:     uuid,
		roles:    append([]string(nil), roles...),
	})
}

func (m *mockKeycloak) client() *keycloak.Client {
	return keycloak.New(m.server.URL, "test-client", "test-secret", keycloak.WithInsecureHTTP())
}

func (m *mockKeycloak) addClient(realm, clientID, uuid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientUUID[realm+"|"+clientID] = uuid
	m.clientState[realm+"|"+uuid] = map[string]any{"id": uuid, "clientId": clientID, "protocol": "openid-connect", "enabled": true, "attributes": map[string]any{}}
}

// ownApplication explicitly provisions an already UID-owned client for existing
// Manage regression tests. Foreign-client tests deliberately do not call it.
func (m *mockKeycloak) ownApplication(app *hankoshv1alpha1.HankoApplication) {
	if app.Spec.Mode == controller.ExportModeObserve || app.Labels["hanko.sh/imported-by"] != "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.clientUUID[app.Spec.RealmRef+"|"+app.Spec.ClientID]
	if id == "" {
		return
	}
	attrs := m.clientState[app.Spec.RealmRef+"|"+id]["attributes"].(map[string]any)
	attrs["hanko.sh/application-owner"] = string(app.UID)
}

func (m *mockKeycloak) addRealm(realm keycloak.Realm) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.realms = append(m.realms, realm)
}

func (m *mockKeycloak) addRealmRole(realm string, role keycloak.RealmRole) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.realmRoles[realm] == nil {
		m.realmRoles[realm] = map[string]keycloak.RealmRole{}
	}
	if role.ID == "" {
		role.ID = role.Name
	}
	m.realmRoles[realm][role.Name] = role
}

func (m *mockKeycloak) addRealmRoleComposite(realm, parent string, child keycloak.RealmRole) {
	m.addRealmRole(realm, child)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.realmComposite[realm+"|"+parent] = append(m.realmComposite[realm+"|"+parent], child.Name)
}

func (m *mockKeycloak) addClientRole(realm, clientUUID string, role keycloak.RealmRole) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := realm + "|" + clientUUID
	if m.clientRoles[key] == nil {
		m.clientRoles[key] = map[string]keycloak.RealmRole{}
	}
	role.ClientRole = true
	role.ContainerID = clientUUID
	if role.ID == "" {
		role.ID = role.Name
	}
	m.clientRoles[key][role.Name] = role
}

func (m *mockKeycloak) addClientRoleComposite(realm, clientUUID, parent string, child keycloak.RealmRole) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := realm + "|" + clientUUID + "|" + parent
	m.clientComposite[key] = append(m.clientComposite[key], child)
}

func (m *mockKeycloak) addIdentityMapper(realm, alias string, mapper keycloak.IdentityProviderMapper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idpMappers[realm+"|"+alias] = append(m.idpMappers[realm+"|"+alias], mapper)
}

func (m *mockKeycloak) addIdentityProvider(realm string, provider keycloak.IdentityProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idpsByRealm[realm] = append(m.idpsByRealm[realm], provider)
}

func (m *mockKeycloak) count(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

func (m *mockKeycloak) identityMappers(realm, alias string) []keycloak.IdentityProviderMapper {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]keycloak.IdentityProviderMapper(nil), m.idpMappers[realm+"|"+alias]...)
}

func (m *mockKeycloak) clientProtocolMappers(realm, uuid string) []keycloak.ProtocolMapper {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]keycloak.ProtocolMapper(nil), m.protocolMappers[realm+"|"+uuid]...)
}

func (m *mockKeycloak) getRealmRole(realm, name string) (keycloak.RealmRole, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.realmRoles[realm][name]
	return role, ok
}

func (m *mockKeycloak) realmRoleComposites(realm, name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.realmComposite[realm+"|"+name]...)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (m *mockKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := r.URL.Path

	switch {
	case r.Method == http.MethodPost && path == "/realms/master/protocol/openid-connect/token":
		writeJSON(w, map[string]any{"access_token": "test-token", "expires_in": 300})

	case strings.HasSuffix(path, "/.well-known/openid-configuration"):
		status := m.discoveryStatus
		if status == 0 {
			status = http.StatusOK
		}
		m.counts["discovery"]++
		w.WriteHeader(status)

	case path == "/admin/realms" && r.Method == http.MethodGet:
		m.counts["listRealms"]++
		writeJSON(w, m.realms)

	case path == "/admin/realms" && r.Method == http.MethodPost:
		m.counts["createRealm"]++
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodGet && reOrganizations.MatchString(path):
		if m.organizationLookupStatus != 0 {
			w.WriteHeader(m.organizationLookupStatus)
			return
		}
		parts := reOrganizations.FindStringSubmatch(path)
		m.counts["listOrganizations"]++
		writeJSON(w, m.organizations[parts[1]])

	case r.Method == http.MethodPost && reOrganizations.MatchString(path):
		m.counts["createOrganization"]++
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodGet && reOrganizationByID.MatchString(path):
		if m.organizationLookupStatus != 0 {
			w.WriteHeader(m.organizationLookupStatus)
			return
		}
		parts := reOrganizationByID.FindStringSubmatch(path)
		m.counts["getOrganization"]++
		for _, organization := range m.organizations[parts[1]] {
			if organization.ID == parts[2] {
				writeJSON(w, organization)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)

	case r.Method == http.MethodPut && reOrganizationByID.MatchString(path):
		m.counts["updateOrganization"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reOrganizationByID.MatchString(path):
		parts := reOrganizationByID.FindStringSubmatch(path)
		remaining := []keycloak.Organization{}
		for _, native := range m.organizations[parts[1]] {
			if native.ID != parts[2] {
				remaining = append(remaining, native)
			}
		}
		m.organizations[parts[1]] = remaining
		m.counts["deleteOrganization"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reRealmByName.MatchString(path):
		m.counts["getRealm"]++
		name := reRealmByName.FindStringSubmatch(path)[1]
		for _, realm := range m.realms {
			if realm.URLName() == name {
				writeJSON(w, realm)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)

	case r.Method == http.MethodGet && reGroupByPath.MatchString(path):
		if m.groupLookupStatus != 0 {
			w.WriteHeader(m.groupLookupStatus)
			return
		}
		parts := reGroupByPath.FindStringSubmatch(path)
		groupPath := "/" + strings.TrimPrefix(parts[2], "/")
		group, ok := m.groupsByPath[parts[1]+"|"+groupPath]
		m.counts["getGroupByPath"]++
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, group)

	case r.Method == http.MethodGet && reGroupRoleMappings.MatchString(path):
		if m.groupLookupStatus != 0 {
			w.WriteHeader(m.groupLookupStatus)
			return
		}
		parts := reGroupRoleMappings.FindStringSubmatch(path)
		roles := make([]keycloak.RealmRole, 0, len(m.groupRealmRoles[parts[1]+"|"+parts[2]]))
		for _, name := range m.groupRealmRoles[parts[1]+"|"+parts[2]] {
			roles = append(roles, keycloak.RealmRole{Name: name})
		}
		clientMappings := make(map[string]any)
		for _, mapping := range m.groupClientRoles[parts[1]+"|"+parts[2]] {
			clientRoles := make([]keycloak.RealmRole, 0, len(mapping.roles))
			for _, name := range mapping.roles {
				clientRoles = append(clientRoles, keycloak.RealmRole{Name: name, ClientRole: true, ContainerID: mapping.uuid})
			}
			clientMappings[mapping.clientID] = map[string]any{
				"id": mapping.uuid, "client": mapping.clientID, "mappings": clientRoles,
			}
		}
		m.counts["getGroupRoleMappings"]++
		writeJSON(w, map[string]any{"realmMappings": roles, "clientMappings": clientMappings})

	case r.Method == http.MethodGet && reGroupByID.MatchString(path):
		if m.groupLookupStatus != 0 {
			w.WriteHeader(m.groupLookupStatus)
			return
		}
		parts := reGroupByID.FindStringSubmatch(path)
		m.counts["getGroup"]++
		for key, group := range m.groupsByPath {
			if strings.HasPrefix(key, parts[1]+"|") && group.ID == parts[2] {
				writeJSON(w, group)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)

	case r.Method == http.MethodGet && reGroupChildren.MatchString(path):
		parts := reGroupChildren.FindStringSubmatch(path)
		children := []keycloak.Group{}
		for _, parent := range m.groupsByPath {
			if parent.ID == parts[2] {
				for _, child := range m.groupsByPath {
					if strings.HasPrefix(child.Path, parent.Path+"/") && !strings.Contains(strings.TrimPrefix(child.Path, parent.Path+"/"), "/") {
						children = append(children, child)
					}
				}
			}
		}
		if len(children) > 1 {
			children = children[:1]
		}
		writeJSON(w, children)

	case r.Method == http.MethodPost && (reGroupsCollection.MatchString(path) || reGroupChildren.MatchString(path)):
		m.counts["createGroup"]++
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodDelete && reGroupByID.MatchString(path):
		parts := reGroupByID.FindStringSubmatch(path)
		for key, group := range m.groupsByPath {
			if strings.HasPrefix(key, parts[1]+"|") && group.ID == parts[2] {
				delete(m.groupsByPath, key)
			}
		}
		m.counts["deleteGroup"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut && reRealmByName.MatchString(path):
		m.counts["updateRealm"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reRealmByName.MatchString(path):
		m.counts["deleteRealm"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reClientsCollection.MatchString(path) && r.URL.Query().Get("clientId") == "":
		m.counts["listApps"]++
		realm := reRealmFromClients.FindStringSubmatch(path)[1]
		writeJSON(w, m.appsByRealm[realm])

	case r.Method == http.MethodGet && reClientsCollection.MatchString(path):
		m.counts["lookup"]++
		realm := reRealmFromClients.FindStringSubmatch(path)[1]
		clientID := r.URL.Query().Get("clientId")
		uuid, ok := m.clientUUID[realm+"|"+clientID]
		if !ok {
			writeJSON(w, []map[string]string{})
			return
		}
		writeJSON(w, []map[string]string{{"id": uuid, "clientId": clientID}})

	case r.Method == http.MethodPost && reClientsCollection.MatchString(path):
		m.counts["create"]++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			m.t.Fatal(err)
		}
		realm := reRealmFromClients.FindStringSubmatch(path)[1]
		clientID := payload["clientId"].(string)
		if m.clientUUID[realm+"|"+clientID] != "" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		id := "uuid-" + clientID
		payload["id"] = id
		m.clientUUID[realm+"|"+clientID] = id
		m.clientState[realm+"|"+id] = payload
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodGet && reClientRoles.MatchString(path):
		m.counts["listRoles"]++
		parts := strings.Split(path, "/")
		roles := []keycloak.ClientRole{}
		for _, role := range m.clientRoles[parts[3]+"|"+parts[5]] {
			roles = append(roles, keycloak.ClientRole{Name: role.Name, Description: role.Description})
		}
		writeJSON(w, roles)

	case r.Method == http.MethodPost && reClientRoles.MatchString(path):
		m.counts["createRole"]++
		parts := strings.Split(path, "/")
		var role keycloak.RealmRole
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			m.t.Fatal(err)
		}
		key := parts[3] + "|" + parts[5]
		if m.clientRoles[key] == nil {
			m.clientRoles[key] = map[string]keycloak.RealmRole{}
		}
		if _, ok := m.clientRoles[key][role.Name]; ok {
			w.WriteHeader(http.StatusConflict)
			return
		}
		m.clientRoles[key][role.Name] = role
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodGet && reClientRoleComposites.MatchString(path):
		parts := reClientRoleComposites.FindStringSubmatch(path)
		m.counts["listClientRoleComposites"]++
		writeJSON(w, m.clientComposite[parts[1]+"|"+parts[2]+"|"+parts[3]])

	case r.Method == http.MethodGet && reClientRoleByName.MatchString(path):
		parts := reClientRoleByName.FindStringSubmatch(path)
		if m.roleLookupStatus != 0 {
			w.WriteHeader(m.roleLookupStatus)
			return
		}
		role, ok := m.clientRoles[parts[1]+"|"+parts[2]][parts[3]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.counts["getClientRole"]++
		writeJSON(w, role)

	case r.Method == http.MethodGet && reClientByID.MatchString(path):
		m.counts["getClient"]++
		parts := strings.Split(path, "/")
		state := m.clientState[parts[3]+"|"+parts[5]]
		if state == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, state)

	case r.Method == http.MethodPut && reClientByID.MatchString(path):
		m.counts["update"]++
		parts := strings.Split(path, "/")
		var state map[string]any
		if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
			m.t.Fatal(err)
		}
		m.clientState[parts[3]+"|"+parts[5]] = state
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reClientByID.MatchString(path):
		m.counts["delete"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reClientSecret.MatchString(path):
		m.counts["getSecret"]++
		writeJSON(w, map[string]string{"value": "mock-secret"})

	case r.Method == http.MethodPost && reClientSecret.MatchString(path):
		m.counts["rotateSecret"]++
		writeJSON(w, map[string]string{"value": "rotated-secret"})

	case r.Method == http.MethodGet && reIDPProviders.MatchString(path):
		parts := reIDPProviders.FindStringSubmatch(path)
		m.counts["listIDPs"]++
		writeJSON(w, m.idpsByRealm[parts[1]])

	case r.Method == http.MethodPost && reIDPProviders.MatchString(path):
		parts := reIDPProviders.FindStringSubmatch(path)
		var provider keycloak.IdentityProvider
		if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
			m.t.Fatalf("decode identity provider: %v", err)
		}
		m.idpsByRealm[parts[1]] = append(m.idpsByRealm[parts[1]], provider)
		m.counts["createIDP"]++
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodPut && reIDPProviderByAlias.MatchString(path):
		parts := reIDPProviderByAlias.FindStringSubmatch(path)
		var provider keycloak.IdentityProvider
		if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
			m.t.Fatalf("decode identity provider update: %v", err)
		}
		for i := range m.idpsByRealm[parts[1]] {
			if m.idpsByRealm[parts[1]][i].Alias == parts[2] {
				m.idpsByRealm[parts[1]][i] = provider
			}
		}
		m.counts["updateIDP"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reIDPProviderByAlias.MatchString(path):
		parts := reIDPProviderByAlias.FindStringSubmatch(path)
		providers := m.idpsByRealm[parts[1]]
		kept := providers[:0]
		for _, provider := range providers {
			if provider.Alias != parts[2] {
				kept = append(kept, provider)
			}
		}
		m.idpsByRealm[parts[1]] = kept
		m.counts["deleteIDP"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reIDPMappersCollection.MatchString(path):
		parts := reIDPMappersCollection.FindStringSubmatch(path)
		m.counts["listIDPMappers"]++
		writeJSON(w, m.idpMappers[parts[1]+"|"+parts[2]])

	case r.Method == http.MethodPost && reIDPMappersCollection.MatchString(path):
		parts := reIDPMappersCollection.FindStringSubmatch(path)
		var mapper keycloak.IdentityProviderMapper
		if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
			m.t.Fatalf("decode identity mapper: %v", err)
		}
		m.nextMapperID++
		mapper.ID = fmt.Sprintf("idp-%d", m.nextMapperID)
		key := parts[1] + "|" + parts[2]
		m.idpMappers[key] = append(m.idpMappers[key], mapper)
		m.counts["createIDPMapper"]++
		w.Header().Set("Location", m.server.URL+path+"/"+mapper.ID)
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodPut && reIDPMapperByID.MatchString(path):
		parts := reIDPMapperByID.FindStringSubmatch(path)
		var mapper keycloak.IdentityProviderMapper
		if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
			m.t.Fatalf("decode identity mapper update: %v", err)
		}
		key := parts[1] + "|" + parts[2]
		for i := range m.idpMappers[key] {
			if m.idpMappers[key][i].ID == parts[3] {
				mapper.ID = parts[3]
				m.idpMappers[key][i] = mapper
			}
		}
		m.counts["updateIDPMapper"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reIDPMapperByID.MatchString(path):
		parts := reIDPMapperByID.FindStringSubmatch(path)
		key := parts[1] + "|" + parts[2]
		m.idpMappers[key] = deleteIdentityMapper(m.idpMappers[key], parts[3])
		m.counts["deleteIDPMapper"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reProtocolCollection.MatchString(path):
		parts := reProtocolCollection.FindStringSubmatch(path)
		m.counts["listProtocolMappers"]++
		writeJSON(w, m.protocolMappers[parts[1]+"|"+parts[2]])

	case r.Method == http.MethodPost && reProtocolCollection.MatchString(path):
		parts := reProtocolCollection.FindStringSubmatch(path)
		var mapper keycloak.ProtocolMapper
		if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
			m.t.Fatalf("decode protocol mapper: %v", err)
		}
		m.nextMapperID++
		mapper.ID = fmt.Sprintf("protocol-%d", m.nextMapperID)
		key := parts[1] + "|" + parts[2]
		m.protocolMappers[key] = append(m.protocolMappers[key], mapper)
		m.counts["createProtocolMapper"]++
		w.Header().Set("Location", m.server.URL+path+"/"+mapper.ID)
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodPut && reProtocolMapperByID.MatchString(path):
		parts := reProtocolMapperByID.FindStringSubmatch(path)
		var mapper keycloak.ProtocolMapper
		if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
			m.t.Fatalf("decode protocol mapper update: %v", err)
		}
		key := parts[1] + "|" + parts[2]
		for i := range m.protocolMappers[key] {
			if m.protocolMappers[key][i].ID == parts[3] {
				mapper.ID = parts[3]
				m.protocolMappers[key][i] = mapper
			}
		}
		m.counts["updateProtocolMapper"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reProtocolMapperByID.MatchString(path):
		parts := reProtocolMapperByID.FindStringSubmatch(path)
		key := parts[1] + "|" + parts[2]
		m.protocolMappers[key] = deleteProtocolMapper(m.protocolMappers[key], parts[3])
		m.counts["deleteProtocolMapper"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && reRealmRolesCollection.MatchString(path):
		parts := reRealmRolesCollection.FindStringSubmatch(path)
		var role keycloak.RealmRole
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			m.t.Fatalf("decode realm role: %v", err)
		}
		realm := parts[1]
		if m.realmRoles[realm] == nil {
			m.realmRoles[realm] = map[string]keycloak.RealmRole{}
		}
		if _, exists := m.realmRoles[realm][role.Name]; exists {
			m.counts["createRealmRoleConflict"]++
			w.WriteHeader(http.StatusConflict)
			return
		}
		role.ID = role.Name
		m.realmRoles[realm][role.Name] = role
		m.counts["createRealmRole"]++
		w.WriteHeader(http.StatusCreated)

	case r.Method == http.MethodGet && reRealmRoleByName.MatchString(path):
		parts := reRealmRoleByName.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		if m.roleLookupStatus != 0 {
			w.WriteHeader(m.roleLookupStatus)
			return
		}
		role, ok := m.realmRoles[realm][name]
		if !ok {
			m.counts["getRealmRoleNotFound"]++
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.counts["getRealmRole"]++
		writeJSON(w, role)

	case r.Method == http.MethodPut && reRealmRoleByName.MatchString(path):
		parts := reRealmRoleByName.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		var role keycloak.RealmRole
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			m.t.Fatalf("decode realm role update: %v", err)
		}
		if m.realmRoles[realm] == nil {
			m.realmRoles[realm] = map[string]keycloak.RealmRole{}
		}
		m.realmRoles[realm][name] = role
		m.counts["updateRealmRole"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && reRealmRoleByName.MatchString(path):
		parts := reRealmRoleByName.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		delete(m.realmRoles[realm], name)
		m.counts["deleteRealmRole"]++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && reRealmRoleCompositesR.MatchString(path):
		parts := reRealmRoleCompositesR.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		children := m.realmComposite[realm+"|"+name]
		roles := make([]keycloak.RealmRole, 0, len(children))
		for _, child := range children {
			roles = append(roles, m.realmRoles[realm][child])
		}
		m.counts["listRealmRoleComposites"]++
		writeJSON(w, roles)

	case r.Method == http.MethodGet && reRealmRoleComposites.MatchString(path):
		parts := reRealmRoleComposites.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		children := m.realmComposite[realm+"|"+name]
		roles := make([]keycloak.RealmRole, 0, len(children))
		for _, child := range children {
			roles = append(roles, m.realmRoles[realm][child])
		}
		m.counts["listRealmRoleComposites"]++
		writeJSON(w, roles)

	case r.Method == http.MethodPost && reRealmRoleComposites.MatchString(path):
		parts := reRealmRoleComposites.FindStringSubmatch(path)
		realm, name := parts[1], parts[2]
		var added []keycloak.RealmRole
		if err := json.NewDecoder(r.Body).Decode(&added); err != nil {
			m.t.Fatalf("decode realm role composites: %v", err)
		}
		key := realm + "|" + name
		for _, child := range added {
			m.realmComposite[key] = append(m.realmComposite[key], child.Name)
		}
		m.counts["addRealmRoleComposites"]++
		w.WriteHeader(http.StatusNoContent)

	default:
		m.t.Fatalf("mock keycloak: unhandled request %s %s", r.Method, path)
	}
}

func deleteIdentityMapper(items []keycloak.IdentityProviderMapper, id string) []keycloak.IdentityProviderMapper {
	result := items[:0]
	for _, item := range items {
		if item.ID != id {
			result = append(result, item)
		}
	}
	return result
}

func deleteProtocolMapper(items []keycloak.ProtocolMapper, id string) []keycloak.ProtocolMapper {
	result := items[:0]
	for _, item := range items {
		if item.ID != id {
			result = append(result, item)
		}
	}
	return result
}
