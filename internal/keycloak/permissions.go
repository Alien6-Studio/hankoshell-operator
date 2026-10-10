package keycloak

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// AdminOperation is the reviewed permission contract, not a replacement for
// Keycloak authorization. Permission describes full reads/writes; Keycloak may
// return a reduced representation to an identity without full read authority.
type AdminOperation struct {
	Capability string
	Methods    string
	Path       string
	Permission string
}

var adminOperations = []AdminOperation{
	{"discovery", "GET", "/admin/serverinfo", "any administrative role; version visibility is version-dependent"},
	{"realms", "GET", "/admin/realms", "view-realm (each target; filtered representations)"},
	{"realm-creation", "POST", "/admin/realms", "master realm role create-realm; native creator grants"},
	{"realms", "GET", "/admin/realms/{realm}", "view-realm or manage-realm"},
	{"realms", "PUT,DELETE", "/admin/realms/{realm}", "manage-realm"},
	{"sessions", "POST", "/admin/realms/{realm}/logout-all", "manage-users"},
	{"realm-policy", "GET,PUT", "/admin/realms/{realm}/authentication/required-actions/CONFIGURE_TOTP", "view-realm / manage-realm"},
	{"events", "PUT", "/admin/realms/{realm}/events/config", "manage-events"},
	{"realm-roles", "GET,POST", "/admin/realms/{realm}/roles", "view-realm / manage-realm"},
	{"realm-roles", "GET,PUT,DELETE", "/admin/realms/{realm}/roles/{role}", "view-realm / manage-realm"},
	{"realm-roles", "GET,POST", "/admin/realms/{realm}/roles/{role}/composites", "view-realm / manage-realm"},
	{"realm-roles", "GET", "/admin/realms/{realm}/roles/{role}/composites/realm", "view-realm or manage-realm"},
	{"clients", "GET,POST", "/admin/realms/{realm}/clients", "view-clients / manage-clients"},
	{"clients", "GET,PUT,DELETE", "/admin/realms/{realm}/clients/{client}", "view-clients / manage-clients"},
	{"credentials", "GET", "/admin/realms/{realm}/clients/{client}/client-secret", "26.8.0: manage-clients; 26.7.5: view-clients also exposes secrets"},
	{"credentials", "POST", "/admin/realms/{realm}/clients/{client}/client-secret", "manage-clients"},
	{"client-roles", "GET,POST", "/admin/realms/{realm}/clients/{client}/roles", "view-clients / manage-clients"},
	{"client-roles", "GET,PUT,DELETE", "/admin/realms/{realm}/clients/{client}/roles/{role}", "view-clients / manage-clients"},
	{"client-roles", "GET", "/admin/realms/{realm}/clients/{client}/roles/{role}/composites", "view-clients"},
	{"client-scopes", "GET,POST,DELETE", "/admin/realms/{realm}/clients/{client}/scope-mappings/realm", "view-clients / manage-clients and permission to map the realm role"},
	{"protocol-mappers", "GET,POST", "/admin/realms/{realm}/clients/{client}/protocol-mappers/models", "view-clients / manage-clients"},
	{"protocol-mappers", "PUT,DELETE", "/admin/realms/{realm}/clients/{client}/protocol-mappers/models/{mapper}", "manage-clients"},
	{"identity-providers", "GET,POST", "/admin/realms/{realm}/identity-provider/instances", "view-identity-providers / manage-identity-providers"},
	{"identity-providers", "PUT,DELETE", "/admin/realms/{realm}/identity-provider/instances/{alias}", "manage-identity-providers"},
	{"identity-provider-mappers", "GET,POST", "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers", "view-identity-providers / manage-identity-providers"},
	{"identity-provider-mappers", "PUT,DELETE", "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper}", "manage-identity-providers"},
	{"groups", "GET", "/admin/realms/{realm}/group-by-path/{path...}", "view-users or manage-users"},
	{"groups", "GET,POST", "/admin/realms/{realm}/groups", "view-users / manage-users"},
	{"groups", "GET,PUT,DELETE", "/admin/realms/{realm}/groups/{group}", "view-users / manage-users"},
	{"group-cleanup-members", "GET", "/admin/realms/{realm}/groups/{group}/members", "view-users or manage-users; cleanup existence only, max=1"},
	{"groups", "GET,POST", "/admin/realms/{realm}/groups/{group}/children", "view-users / manage-users"},
	{"group-roles", "GET", "/admin/realms/{realm}/groups/{group}/role-mappings", "view-users"},
	{"group-roles", "GET,POST", "/admin/realms/{realm}/groups/{group}/role-mappings/realm", "view-users / manage-users and permission to map the realm role"},
	{"group-roles", "GET,POST", "/admin/realms/{realm}/groups/{group}/role-mappings/clients/{client}", "view-users / manage-users and permission to map the client role"},
	{"organizations", "GET,POST", "/admin/realms/{realm}/organizations", "view-organizations / manage-organizations or manage-realm"},
	{"organizations", "GET,PUT,DELETE", "/admin/realms/{realm}/organizations/{organization}", "view-organizations / manage-organizations or manage-realm"},
	{"organization-cleanup-members", "GET", "/admin/realms/{realm}/organizations/{organization}/members", "view-organizations or manage-organizations; cleanup existence only, max=1"},
	{"organization-idps", "GET,POST", "/admin/realms/{realm}/organizations/{organization}/identity-providers", "view-organizations / manage-organizations (or manage-realm) and manage-identity-providers"},
	{"organization-idps", "DELETE", "/admin/realms/{realm}/organizations/{organization}/identity-providers/{alias}", "manage-organizations (or manage-realm) and manage-identity-providers"},
	{"authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/scope", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,PUT,DELETE", "/admin/realms/{realm}/clients/{client}/authz/resource-server/scope/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/resource", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,PUT,DELETE", "/admin/realms/{realm}/clients/{client}/authz/resource-server/resource/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}/associatedPolicies", "view-authorization or manage-authorization or manage-clients"},
	{"authorization", "GET", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy", "view-authorization or manage-authorization or manage-clients"},
	{"authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client", "view-authorization / manage-authorization or manage-clients"},
	{"organization-authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group", "view-authorization / manage-authorization or manage-clients; strict group resolution additionally requires view-users"},
	{"organization-authorization", "GET,PUT", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,PUT", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,PUT", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "DELETE", "/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}", "manage-authorization or manage-clients"},
	{"authorization", "GET", "/admin/realms/{realm}/clients/{client}/authz/resource-server/permission", "view-authorization or manage-authorization or manage-clients"},
	{"authorization", "GET,POST", "/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope", "view-authorization / manage-authorization or manage-clients"},
	{"authorization", "GET,PUT", "/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope/{object}", "view-authorization / manage-authorization or manage-clients"},
	{"authorization-native-dependencies", "GET", "/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/resource", "view-authorization or manage-authorization or manage-clients"},
	{"authorization", "DELETE", "/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/{object}", "manage-authorization or manage-clients"},
}

// AdminOperations returns an independent copy for documentation and regression
// checks. A new route/method must be reviewed here before it can reach Keycloak.
func AdminOperations() []AdminOperation {
	return append([]AdminOperation(nil), adminOperations...)
}

// Redirects must not execute a method/route outside the reviewed gateway or
// forward credentials. Configure the canonical Keycloak URL instead.
func rejectKeycloakRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func matchAdminPath(pattern, path string) bool {
	want, actual := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, segment := range want {
		if i >= len(actual) || actual[i] == "" && segment != "" {
			return false
		}
		if segment == "{path...}" {
			for _, part := range actual[i:] {
				if part == "" {
					return false
				}
			}
			return true
		}
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			continue
		}
		if actual[i] != segment {
			return false
		}
	}
	return len(want) == len(actual)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	limit, err := c.responseBudget(req)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	// Callers receive only a complete bounded buffer, never the network stream.
	// Validate even bodies ignored by success/Location handlers before returning.
	return boundedKeycloakResponse(response, limit)
}

func (c *Client) responseBudget(req *http.Request) (int64, error) {
	if c.endpointError != nil {
		return 0, c.endpointError
	}
	if err := ValidateEndpoint(c.baseURL, c.allowInsecureHTTP); err != nil {
		return 0, err
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return 0, fmt.Errorf("invalid Keycloak base URL: %w", err)
	}
	prefix := strings.TrimRight(base.EscapedPath(), "/")
	path, found := strings.CutPrefix(req.URL.EscapedPath(), prefix)
	if !found || req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || req.URL.User != nil {
		return 0, fmt.Errorf("keycloak operation outside configured endpoint")
	}
	if isBootstrapTokenRequest(req.Method, path) {
		return maxKeycloakCredentialResponseBytes, nil
	}
	// Public protocol documents: no administrative authority and no token.
	if isPublicProtocolDocument(req.Method, path) {
		if req.Header.Get(authorizationHeader) != "" {
			return 0, fmt.Errorf("protocol metadata must not carry administrative credentials")
		}
		return maxKeycloakAdminResponseBytes, nil
	}
	if matchAdminPath("/admin/realms/{realm}/groups/{group}/members", path) || matchAdminPath("/admin/realms/{realm}/organizations/{organization}/members", path) {
		if err := validateCleanupMembershipQuery(req.URL.Query()); err != nil {
			return 0, err
		}
	}
	return c.adminResponseBudget(req.Method, path)
}

func validateCleanupMembershipQuery(query url.Values) error {
	if !slices.Equal(query["first"], []string{"0"}) || !slices.Equal(query["max"], []string{"1"}) {
		return fmt.Errorf("membership reads require bounded cleanup existence queries")
	}
	for key, values := range query {
		if key != "first" && key != "max" && (key != "briefRepresentation" || len(values) != 1 || values[0] != "true") {
			return fmt.Errorf("membership reads are cleanup existence only")
		}
	}
	return nil
}

func (c *Client) adminResponseBudget(method, path string) (int64, error) {
	for _, operation := range adminOperations {
		if matchAdminPath(operation.Path, path) && strings.Contains(","+operation.Methods+",", ","+method+",") {
			if c.inventoryOnly && (method != http.MethodGet || !inventoryOperation(operation.Path)) {
				return 0, fmt.Errorf("operation is outside the read-only inventory contract")
			}
			if operation.Capability == "credentials" {
				return maxKeycloakCredentialResponseBytes, nil
			}
			return maxKeycloakAdminResponseBytes, nil
		}
	}
	return 0, fmt.Errorf("unclassified Keycloak operation: %s %s; update the permission contract", method, path)
}

// This separate read contract cannot grow merely because an existing broad
// capability gains a new Admin route. User/member/credential routes stay absent.
func inventoryOperation(path string) bool {
	switch path {
	case "/admin/realms", "/admin/realms/{realm}",
		"/admin/realms/{realm}/roles", "/admin/realms/{realm}/roles/{role}",
		"/admin/realms/{realm}/roles/{role}/composites", "/admin/realms/{realm}/roles/{role}/composites/realm",
		"/admin/realms/{realm}/clients", "/admin/realms/{realm}/clients/{client}",
		"/admin/realms/{realm}/clients/{client}/roles", "/admin/realms/{realm}/clients/{client}/roles/{role}",
		"/admin/realms/{realm}/clients/{client}/roles/{role}/composites",
		"/admin/realms/{realm}/clients/{client}/scope-mappings/realm",
		"/admin/realms/{realm}/clients/{client}/protocol-mappers/models",
		"/admin/realms/{realm}/identity-provider/instances", "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
		"/admin/realms/{realm}/groups", "/admin/realms/{realm}/groups/{group}/children", "/admin/realms/{realm}/groups/{group}/role-mappings",
		"/admin/realms/{realm}/groups/{group}", "/admin/realms/{realm}/group-by-path/{path...}",
		"/admin/realms/{realm}/organizations", "/admin/realms/{realm}/organizations/{organization}", "/admin/realms/{realm}/organizations/{organization}/identity-providers",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/scope",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/resource",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}/associatedPolicies",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/permission",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/scope/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/resource/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope/{object}",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/resource",
		"/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope":
		return true
	default:
		return false
	}
}

func isPublicProtocolDocument(method, path string) bool {
	return method == http.MethodGet && (matchAdminPath("/realms/{realm}/.well-known/openid-configuration", path) || matchAdminPath("/realms/{realm}/protocol/saml/descriptor", path))
}

func isBootstrapTokenRequest(method, path string) bool {
	return method == http.MethodPost && path == "/realms/master/protocol/openid-connect/token"
}
