package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mapperAPIFixture struct {
	t               *testing.T
	identityMappers []IdentityProviderMapper
	protocolMappers []ProtocolMapper
	mutations       []string
	omitLocation    bool
	omitPersistence bool
	duplicateCreate bool
	rejectCreate    bool
	failFallbackGet bool
	identityGets    int
	protocolGets    int
}

func newMapperAPIFixture(t *testing.T) (*mapperAPIFixture, *Client) {
	t.Helper()
	fixture := &mapperAPIFixture{t: t}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	return fixture, New(server.URL, "operator", "secret")
}

func (fixture *mapperAPIFixture) serveHTTP(w http.ResponseWriter, request *http.Request) {
	const (
		identityPath = "/admin/realms/acme/identity-provider/instances/entra/mappers"
		protocolPath = "/admin/realms/acme/clients/client-uuid/protocol-mappers/models"
	)
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
		if request.URL.Query().Get("clientId") == "web" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "web"}})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	case request.Method == http.MethodGet && request.URL.Path == identityPath:
		fixture.identityGets++
		if fixture.failFallbackGet && fixture.identityGets > 1 {
			http.Error(w, "identity mapper list unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(fixture.identityMappers)
	case request.Method == http.MethodPost && request.URL.Path == identityPath:
		if fixture.rejectCreate {
			http.Error(w, "identity mapper create denied", http.StatusForbidden)
			return
		}
		var mapper IdentityProviderMapper
		fixture.decode(request, &mapper)
		mapper.ID = "identity-uuid"
		if !fixture.omitPersistence {
			fixture.identityMappers = append(fixture.identityMappers, mapper)
			if fixture.duplicateCreate {
				fixture.identityMappers = append(fixture.identityMappers, mapper)
			}
		}
		fixture.mutations = append(fixture.mutations, "create-identity")
		if !fixture.omitLocation {
			w.Header().Set("Location", "/admin/realms/acme/identity-provider/instances/entra/mappers/"+mapper.ID)
		}
		w.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, identityPath+"/"):
		var mapper IdentityProviderMapper
		fixture.decode(request, &mapper)
		fixture.identityMappers = []IdentityProviderMapper{mapper}
		fixture.mutations = append(fixture.mutations, "update-identity")
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, identityPath+"/"):
		fixture.identityMappers = nil
		fixture.mutations = append(fixture.mutations, "delete-identity")
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && request.URL.Path == protocolPath:
		fixture.protocolGets++
		if fixture.failFallbackGet && fixture.protocolGets > 1 {
			http.Error(w, "protocol mapper list unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(fixture.protocolMappers)
	case request.Method == http.MethodPost && request.URL.Path == protocolPath:
		if fixture.rejectCreate {
			http.Error(w, "protocol mapper create denied", http.StatusForbidden)
			return
		}
		var mapper ProtocolMapper
		fixture.decode(request, &mapper)
		mapper.ID = "protocol-uuid"
		if !fixture.omitPersistence {
			fixture.protocolMappers = append(fixture.protocolMappers, mapper)
			if fixture.duplicateCreate {
				fixture.protocolMappers = append(fixture.protocolMappers, mapper)
			}
		}
		fixture.mutations = append(fixture.mutations, "create-protocol")
		if !fixture.omitLocation {
			w.Header().Set("Location", "/admin/realms/acme/clients/client-uuid/protocol-mappers/models/"+mapper.ID)
		}
		w.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, protocolPath+"/"):
		var mapper ProtocolMapper
		fixture.decode(request, &mapper)
		fixture.protocolMappers = []ProtocolMapper{mapper}
		fixture.mutations = append(fixture.mutations, "update-protocol")
		w.WriteHeader(http.StatusOK)
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, protocolPath+"/"):
		fixture.protocolMappers = nil
		fixture.mutations = append(fixture.mutations, "delete-protocol")
		w.WriteHeader(http.StatusNotFound)
	default:
		fixture.t.Errorf("unexpected mapper API request: %s %s", request.Method, request.URL.String())
		http.NotFound(w, request)
	}
}

func (fixture *mapperAPIFixture) decode(request *http.Request, target any) {
	fixture.t.Helper()
	if got := request.Header.Get(authorizationHeader); got != bearerPrefix+"token" {
		fixture.t.Errorf("authorization header = %q", got)
	}
	if got := request.Header.Get(forwardedProtoHeader); got != httpsScheme {
		fixture.t.Errorf("forwarded protocol = %q", got)
	}
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		fixture.t.Fatalf("decode mapper request: %v", err)
	}
}

func TestIdentityProviderMapperLifecycleIsIdempotent(t *testing.T) {
	fixture, client := newMapperAPIFixture(t)
	ctx := context.Background()
	desired := IdentityProviderMapper{
		Name: "department", IdentityProviderAlias: "entra",
		IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
		Config:                 map[string]string{"claim": "department", "user.attribute": "department"},
	}

	created, err := client.EnsureIdentityProviderMapper(ctx, "acme", desired)
	if err != nil || created.ID != "identity-uuid" {
		t.Fatalf("create identity mapper: mapper=%#v err=%v", created, err)
	}
	if _, err := client.EnsureIdentityProviderMapper(ctx, "acme", desired); err != nil {
		t.Fatalf("idempotent identity mapper reconcile: %v", err)
	}
	desired.Config["claim"] = "division"
	updated, err := client.EnsureIdentityProviderMapper(ctx, "acme", desired)
	if err != nil || updated.Config["claim"] != "division" {
		t.Fatalf("update identity mapper: mapper=%#v err=%v", updated, err)
	}
	listed, err := client.ListIdentityProviderMappers(ctx, "acme", "entra")
	if err != nil || len(listed) != 1 || listed[0].ID != "identity-uuid" {
		t.Fatalf("list identity mappers: mappers=%#v err=%v", listed, err)
	}
	if err := client.DeleteIdentityProviderMapper(ctx, "acme", "entra", created.ID); err != nil {
		t.Fatalf("delete identity mapper: %v", err)
	}
	if err := client.DeleteIdentityProviderMapper(ctx, "acme", "entra", ""); err != nil {
		t.Fatalf("empty identity mapper deletion must be idempotent: %v", err)
	}
	if got := strings.Join(fixture.mutations, ","); got != "create-identity,update-identity,delete-identity" {
		t.Fatalf("identity mapper mutations = %q", got)
	}
}

func TestClientProtocolMapperLifecycleIsIdempotent(t *testing.T) {
	fixture, client := newMapperAPIFixture(t)
	ctx := context.Background()
	desired := ProtocolMapper{
		Name: "tenant", ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config: map[string]string{"claim.name": "tenant", "claim.value": "acme"},
	}

	created, err := client.EnsureClientProtocolMapper(ctx, "acme", "web", desired)
	if err != nil || created.ID != "protocol-uuid" || created.Protocol != openIDConnectProtocol {
		t.Fatalf("create protocol mapper: mapper=%#v err=%v", created, err)
	}
	if _, err := client.EnsureClientProtocolMapper(ctx, "acme", "web", desired); err != nil {
		t.Fatalf("idempotent protocol mapper reconcile: %v", err)
	}
	desired.Config["claim.value"] = "regulated"
	updated, err := client.EnsureClientProtocolMapper(ctx, "acme", "web", desired)
	if err != nil || updated.Config["claim.value"] != "regulated" {
		t.Fatalf("update protocol mapper: mapper=%#v err=%v", updated, err)
	}
	listed, err := client.ListClientProtocolMappers(ctx, "acme", "web")
	if err != nil || len(listed) != 1 {
		t.Fatalf("list protocol mappers: mappers=%#v err=%v", listed, err)
	}
	if err := client.DeleteClientProtocolMapper(ctx, "acme", "web", created.ID); err != nil {
		t.Fatalf("delete protocol mapper: %v", err)
	}
	if err := client.DeleteClientProtocolMapper(ctx, "acme", "missing", created.ID); err != nil {
		t.Fatalf("missing client deletion must be idempotent: %v", err)
	}
	if err := client.DeleteClientProtocolMapper(ctx, "acme", "web", ""); err != nil {
		t.Fatalf("empty protocol mapper deletion must be idempotent: %v", err)
	}
	if got := strings.Join(fixture.mutations, ","); got != "create-protocol,update-protocol,delete-protocol" {
		t.Fatalf("protocol mapper mutations = %q", got)
	}
}

func TestMapperValidationAndDuplicateOwnershipFailClosed(t *testing.T) {
	_, client := newMapperAPIFixture(t)
	ctx := context.Background()
	if _, err := client.EnsureIdentityProviderMapper(ctx, "acme", IdentityProviderMapper{}); err == nil {
		t.Fatal("invalid identity-provider mapper must be rejected before API access")
	}
	if _, err := client.EnsureClientProtocolMapper(ctx, "acme", "web", ProtocolMapper{}); err == nil {
		t.Fatal("invalid protocol mapper must be rejected before API access")
	}
	identity := IdentityProviderMapper{Name: "duplicate"}
	if _, _, err := findIdentityProviderMapper([]IdentityProviderMapper{identity, identity}, identity.Name); err == nil {
		t.Fatal("duplicate identity-provider mapper names must be rejected")
	}
	protocol := ProtocolMapper{Name: "duplicate"}
	if _, _, err := findProtocolMapper([]ProtocolMapper{protocol, protocol}, protocol.Name); err == nil {
		t.Fatal("duplicate protocol mapper names must be rejected")
	}
}

func TestMapperCreationRecoversIDsWhenKeycloakOmitsLocation(t *testing.T) {
	fixture, client := newMapperAPIFixture(t)
	fixture.omitLocation = true
	ctx := context.Background()
	identity, err := client.EnsureIdentityProviderMapper(ctx, "acme", IdentityProviderMapper{
		Name: "department", IdentityProviderAlias: "entra", IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
	})
	if err != nil || identity.ID != "identity-uuid" {
		t.Fatalf("recover identity mapper ID: mapper=%#v err=%v", identity, err)
	}
	protocol, err := client.EnsureClientProtocolMapper(ctx, "acme", "web", ProtocolMapper{
		Name: "tenant", ProtocolMapper: "oidc-hardcoded-claim-mapper",
	})
	if err != nil || protocol.ID != "protocol-uuid" {
		t.Fatalf("recover protocol mapper ID: mapper=%#v err=%v", protocol, err)
	}
}

func TestMapperCreationFallbacksFailClosed(t *testing.T) {
	identity := IdentityProviderMapper{Name: "department", IdentityProviderAlias: "entra", IdentityProviderMapper: "oidc-user-attribute-idp-mapper"}
	protocol := ProtocolMapper{Name: "tenant", ProtocolMapper: "oidc-hardcoded-claim-mapper"}
	for _, test := range []struct {
		name      string
		configure func(*mapperAPIFixture)
	}{
		{name: "provider rejects create", configure: func(fixture *mapperAPIFixture) { fixture.rejectCreate = true }},
		{name: "created mapper missing", configure: func(fixture *mapperAPIFixture) { fixture.omitLocation, fixture.omitPersistence = true, true }},
		{name: "fallback list unavailable", configure: func(fixture *mapperAPIFixture) { fixture.omitLocation, fixture.failFallbackGet = true, true }},
		{name: "fallback ownership ambiguous", configure: func(fixture *mapperAPIFixture) { fixture.omitLocation, fixture.duplicateCreate = true, true }},
	} {
		t.Run(test.name+" identity", func(t *testing.T) {
			fixture, client := newMapperAPIFixture(t)
			test.configure(fixture)
			if _, err := client.EnsureIdentityProviderMapper(context.Background(), "acme", identity); err == nil {
				t.Fatal("unsafe identity mapper creation fallback was accepted")
			}
		})
		t.Run(test.name+" protocol", func(t *testing.T) {
			fixture, client := newMapperAPIFixture(t)
			test.configure(fixture)
			if _, err := client.EnsureClientProtocolMapper(context.Background(), "acme", "web", protocol); err == nil {
				t.Fatal("unsafe protocol mapper creation fallback was accepted")
			}
		})
	}
}
