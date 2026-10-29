package keycloak

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloakversion"
)

const BoundedDelegationAttribute = "oauth.bounded-delegation.v1"
const BoundedDelegationActorAttribute = "oauth.bounded-delegation.actor.v1"

var ErrBoundedDelegationUnsupported = errors.New("bounded-delegation software profile unavailable")

type BoundedDelegationExcessError struct{ Permission, Resource, Scope string }

func (BoundedDelegationExcessError) Error() string {
	return "delegation exceeds actor and subject authority"
}
func (BoundedDelegationExcessError) Unwrap() error { return ErrBoundedDelegationUnsupported }

type BoundedDelegationCapability struct {
	Contract         string `json:"contract"`
	ExtensionVersion string `json:"extensionVersion"`
	KeycloakVersion  string `json:"keycloakVersion"`
	Experimental     bool   `json:"experimental"`
	Enabled          bool   `json:"enabled"`
	MaxDepth         int32  `json:"maxDepth"`
	MaxTTLSeconds    int32  `json:"maxTTLSeconds"`
}

// BoundedDelegationCapability is deliberately requested only for delegation.
// Stock installations retain their ordinary adapter capability/read behavior.
func (c *Client) BoundedDelegationCapability(ctx context.Context, realm string) (BoundedDelegationCapability, error) {
	var capability BoundedDelegationCapability
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/realms/"+url.PathEscape(realm)+"/bounded-delegation", nil)
	if err != nil {
		return capability, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.do(request)
	if err != nil {
		return capability, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return capability, ErrBoundedDelegationUnsupported
	}
	if response.StatusCode != http.StatusOK {
		return capability, &StatusError{Code: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return capability, err
	}
	if len(data) > 8192 || httpsecurity.ValidateJSON(data) != nil {
		return capability, ErrBoundedDelegationUnsupported
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&capability) != nil || !validBoundedCapability(capability) {
		return BoundedDelegationCapability{}, ErrBoundedDelegationUnsupported
	}
	return capability, nil
}

func validBoundedCapability(capability BoundedDelegationCapability) bool {
	return capability.Contract == "bounded-delegation/software-v1" &&
		slices.Contains([]string{"0.1.0-rc.2", "0.1.0"}, capability.ExtensionVersion) && capability.Experimental && capability.Enabled && capability.MaxDepth == 4 && capability.MaxTTLSeconds == 600 &&
		keycloakversion.BoundedDelegation(capability.KeycloakVersion)
}

type BoundedDelegationBinding struct {
	ID        string `json:"id"`
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
}

type BoundedDelegationIdentity struct{ Kind, ClientID, UID string }

type BoundedDelegationPrincipal struct {
	Kind, Ref, UID string
	Groups         []BoundedDelegationBinding
}

type BoundedDelegationPermission struct {
	Name                    string
	Actor, Subject          BoundedDelegationIdentity
	Resources, Scopes       []string
	Principals              []BoundedDelegationPrincipal
	MaxDepth, MaxTTLSeconds int32
	TaskAuthorization       string
}

type BoundedDelegationCondition struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Attribute string `json:"attribute,omitempty"`
	Value     string `json:"value,omitempty"`
}

type BoundedDelegationAuthority struct {
	Scopes      []string            `json:"scopes"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
	Permissions map[string][]string `json:"permissions"`
}

type BoundedDelegationGrant struct {
	Name          string                       `json:"name"`
	Actor         BoundedDelegationBinding     `json:"actor"`
	Subject       BoundedDelegationBinding     `json:"subject"`
	Authority     BoundedDelegationAuthority   `json:"authority"`
	Conditions    []BoundedDelegationCondition `json:"conditions"`
	MaxDepth      int32                        `json:"maxDepth"`
	MaxTTLSeconds int32                        `json:"maxTTLSeconds"`
}

type BoundedDelegationDocument struct {
	Version       int                        `json:"version"`
	Profile       string                     `json:"profile,omitempty"`
	Phase         string                     `json:"phase"`
	OwnerUID      string                     `json:"ownerUID"`
	Revision      string                     `json:"revision"`
	RealmID       string                     `json:"realmID"`
	Audience      BoundedDelegationBinding   `json:"audience"`
	Grants        []BoundedDelegationGrant   `json:"grants"`
	RetiredActors []BoundedDelegationBinding `json:"retiredActors,omitempty"`
}

// BoundedDelegationPreparation contains public native bindings and an opaque
// digest of private, current software role/group reads. It contains no tokens.
// Resource names are replaced with owned IDs only after native resource apply.
type BoundedDelegationPreparation struct {
	Document BoundedDelegationDocument
	Runtime  string
}

type boundedDelegationMember struct {
	identity BoundedDelegationIdentity
	binding  BoundedDelegationBinding
	userID   string
	roles    []string
	groups   []string
}

type boundedDelegationReadKey struct{}
type boundedDelegationRead struct{ realm, clientID, userID string }

type boundedDelegationRealm struct {
	ID                  string `json:"id"`
	Enabled             bool   `json:"enabled"`
	AccessTokenLifespan int32  `json:"accessTokenLifespan"`
}

func validBoundedPreparation(model AuthorizationModel, realm boundedDelegationRealm, permissions []BoundedDelegationPermission) bool {
	return realm.ID != "" && realm.Enabled && realm.AccessTokenLifespan > 0 && model.OwnerUID != "" && len(permissions) > 0 && len(permissions) <= 128
}

func validateBoundedDelegationRead(request *http.Request, path string) error {
	clientRead := matchAdminPath("/admin/realms/{realm}/clients/{client}/service-account-user", path)
	rolesRead := matchAdminPath("/admin/realms/{realm}/users/{user}/role-mappings/realm/composite", path)
	groupsRead := matchAdminPath("/admin/realms/{realm}/users/{user}/groups", path)
	if !clientRead && !rolesRead && !groupsRead {
		return nil
	}
	witness, ok := request.Context().Value(boundedDelegationReadKey{}).(boundedDelegationRead)
	if !ok || request.Method != http.MethodGet || witness.realm == "" || witness.clientID == "" {
		return errors.New("delegation reads require a verified owned software identity")
	}
	base := adminRealmsPath + url.PathEscape(witness.realm)
	expected := base + clientsPath + url.PathEscape(witness.clientID) + "/service-account-user"
	if !clientRead {
		if witness.userID == "" {
			return errors.New("delegation read lacks a verified service account")
		}
		expected = base + "/users/" + url.PathEscape(witness.userID) + "/role-mappings/realm/composite"
		if groupsRead {
			expected = base + "/users/" + url.PathEscape(witness.userID) + "/groups"
		}
	}
	if path != expected {
		return errors.New("delegation read is outside the verified software identity")
	}
	return validateBoundedIdentityQuery(request.URL.Query(), groupsRead)
}

func validateBoundedIdentityQuery(query url.Values, groupsRead bool) error {
	if groupsRead {
		if len(query) != 3 || !slices.Equal(query["first"], []string{"0"}) || !slices.Equal(query["max"], []string{"129"}) || !slices.Equal(query["briefRepresentation"], []string{"true"}) {
			return errors.New("delegation group reads require the bounded software membership query")
		}
	} else if len(query) != 0 {
		return errors.New("unexpected delegation identity query")
	}
	return nil
}

// PrepareBoundedDelegation proves every requested resource/scope against both
// identities and the ordinary declared grants, without a provider mutation.
func (c *Client) PrepareBoundedDelegation(ctx context.Context, model AuthorizationModel, audienceUID string,
	permissions []BoundedDelegationPermission, ordinary map[string][]BoundedDelegationPrincipal,
) (BoundedDelegationPreparation, error) {
	var result BoundedDelegationPreparation
	capability, err := c.BoundedDelegationCapability(ctx, model.Realm)
	if err != nil {
		return result, err
	}
	var realm boundedDelegationRealm
	if err := c.get(ctx, adminRealmsPath+url.PathEscape(model.Realm), &realm); err != nil {
		return result, err
	}
	if !validBoundedPreparation(model, realm, permissions) {
		return result, ErrBoundedDelegationUnsupported
	}
	audience, err := c.boundedDelegationMember(ctx, model.Realm, BoundedDelegationIdentity{Kind: "application", ClientID: model.ApplicationRef, UID: audienceUID}, false)
	if err != nil {
		return result, err
	}
	result.Document = BoundedDelegationDocument{Version: 1, Phase: "Prepared", OwnerUID: model.OwnerUID, RealmID: realm.ID,
		Audience: audience.binding, Grants: []BoundedDelegationGrant{}}
	taskCapability, err := c.requestedTaskCapability(ctx, model.Realm, permissions)
	if err != nil {
		return result, err
	}
	if taskCapability != nil {
		result.Document.Version, result.Document.Profile = 2, "task-bound-software"
	}
	members := map[BoundedDelegationIdentity]boundedDelegationMember{}
	resolve := func(identity BoundedDelegationIdentity) (boundedDelegationMember, error) {
		if member, found := members[identity]; found {
			return member, nil
		}
		member, err := c.boundedDelegationMember(ctx, model.Realm, identity, true)
		if err == nil {
			members[identity] = member
		}
		return member, err
	}
	conditions := map[string][]BoundedDelegationCondition{}
	for name, principals := range ordinary {
		value, err := c.boundedDelegationConditions(ctx, model.Realm, principals)
		if err != nil {
			return result, err
		}
		conditions[name] = value
	}
	for _, permission := range permissions {
		grant, err := c.prepareBoundedGrant(ctx, model, audience.binding, permission, conditions, realm.AccessTokenLifespan, resolve)
		if err != nil {
			return result, err
		}
		result.Document.Grants = append(result.Document.Grants, grant)
	}
	// Two permissions for one pair require an explicit combined policy; do not
	// choose one opportunistically at exchange time or silently union conditions.
	slices.SortFunc(result.Document.Grants, func(a, b BoundedDelegationGrant) int { return strings.Compare(a.Name, b.Name) })
	if err := uniqueBoundedPairs(result.Document.Grants); err != nil {
		return result, err
	}
	closures, err := c.boundedRoleClosures(ctx, model.Realm, ordinary, permissions)
	if err != nil {
		return result, err
	}
	data, _ := json.Marshal([]any{capability, realm, boundedMemberSnapshots(members), conditions, closures, result.Document})
	result.Runtime = boundedTaskRuntime(data, taskCapability)
	return result, nil
}

func uniqueBoundedPairs(grants []BoundedDelegationGrant) error {
	pairs := map[string]bool{}
	for _, grant := range grants {
		pair := grant.Actor.ID + "\x00" + grant.Subject.ID
		if pairs[pair] {
			return ErrBoundedDelegationUnsupported
		}
		pairs[pair] = true
	}
	return nil
}

func (c *Client) prepareBoundedGrant(ctx context.Context, model AuthorizationModel, audience BoundedDelegationBinding,
	permission BoundedDelegationPermission, conditions map[string][]BoundedDelegationCondition, realmTTL int32,
	resolve func(BoundedDelegationIdentity) (boundedDelegationMember, error),
) (BoundedDelegationGrant, error) {
	var result BoundedDelegationGrant
	if !validBoundedPermission(permission, realmTTL) {
		return result, ErrBoundedDelegationUnsupported
	}
	actor, err := resolve(permission.Actor)
	if err != nil {
		return result, err
	}
	subject, err := resolve(permission.Subject)
	if err != nil {
		return result, err
	}
	if actor.binding.ID == subject.binding.ID || actor.binding.ID == audience.ID || subject.binding.ID == audience.ID {
		return result, ErrBoundedDelegationUnsupported
	}
	condition, err := c.boundedDelegationConditions(ctx, model.Realm, permission.Principals)
	if err != nil {
		return result, err
	}
	if !boundedMemberMatches(actor, condition) || !boundedMemberMatches(subject, condition) {
		return result, BoundedDelegationExcessError{Permission: permission.Name}
	}
	granted, err := boundedGrantedPermissions(model, conditions, actor, subject, permission)
	if err != nil {
		return result, err
	}
	return BoundedDelegationGrant{Name: permission.Name, Actor: actor.binding, Subject: subject.binding,
		Authority:  BoundedDelegationAuthority{Scopes: []string{}, RealmRoles: []string{}, ClientRoles: map[string][]string{}, Permissions: granted},
		Conditions: condition, MaxDepth: permission.MaxDepth, MaxTTLSeconds: permission.MaxTTLSeconds}, nil
}

func validBoundedPermission(permission BoundedDelegationPermission, realmTTL int32) bool {
	return permission.Name != "" && permission.Actor != permission.Subject && len(permission.Resources) > 0 && len(permission.Scopes) > 0 &&
		(permission.TaskAuthorization == "" || permission.TaskAuthorization == "required" && permission.MaxDepth == 1) &&
		permission.MaxDepth >= 1 && permission.MaxDepth <= 4 && permission.MaxTTLSeconds >= 1 && permission.MaxTTLSeconds <= 600 && permission.MaxTTLSeconds <= realmTTL
}

func boundedGrantedPermissions(model AuthorizationModel, conditions map[string][]BoundedDelegationCondition,
	actor, subject boundedDelegationMember, permission BoundedDelegationPermission,
) (map[string][]string, error) {
	granted := map[string][]string{}
	for _, resource := range permission.Resources {
		for _, scope := range permission.Scopes {
			if !boundedMemberGranted(model, conditions, actor, resource, scope) || !boundedMemberGranted(model, conditions, subject, resource, scope) {
				return nil, BoundedDelegationExcessError{Permission: permission.Name, Resource: resource, Scope: scope}
			}
		}
		granted[resource] = boundedDelegationStrings(permission.Scopes)
	}
	return granted, nil
}

func boundedMemberSnapshots(members map[BoundedDelegationIdentity]boundedDelegationMember) []any {
	var snapshots []any
	for _, member := range members {
		snapshots = append(snapshots, struct {
			Identity BoundedDelegationIdentity
			Binding  BoundedDelegationBinding
			UserID   string
			Roles    []string
			Groups   []string
		}{member.identity, member.binding, member.userID, member.roles, member.groups})
	}
	slices.SortFunc(snapshots, func(a, b any) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})
	return snapshots
}

func (c *Client) boundedRoleClosures(ctx context.Context, realm string, ordinary map[string][]BoundedDelegationPrincipal, permissions []BoundedDelegationPermission) (map[string][]RealmRole, error) {
	closures := map[string][]RealmRole{}
	allPrincipals := []BoundedDelegationPrincipal{}
	for _, principals := range ordinary {
		allPrincipals = append(allPrincipals, principals...)
	}
	for _, permission := range permissions {
		allPrincipals = append(allPrincipals, permission.Principals...)
	}
	for _, principal := range allPrincipals {
		if principal.Kind != "realm_role" || closures[principal.Ref] != nil {
			continue
		}
		closure, err := c.GetRealmRoleClosure(ctx, realm, principal.Ref)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(closure, func(a, b RealmRole) int { return strings.Compare(a.ID, b.ID) })
		closures[principal.Ref] = closure
	}
	return closures, nil
}

func (c *Client) boundedDelegationMember(ctx context.Context, realm string, identity BoundedDelegationIdentity, authority bool) (boundedDelegationMember, error) {
	member := boundedDelegationMember{identity: identity}
	app, err := c.GetApplication(ctx, realm, identity.ClientID)
	if err != nil {
		return member, err
	}
	if app == nil || identity.UID == "" || !app.Enabled || app.PublicClient || app.Protocol != "openid-connect" || !app.ServiceAccountsEnabled || app.Attributes[adoption.ReceiptKey] != "" {
		return member, ErrBoundedDelegationUnsupported
	}
	key := adoption.ApplicationOwnerKey
	switch identity.Kind {
	case "application":
		if !ApplicationOwned(app, identity.UID) {
			return member, ErrAuthorizationOwnershipConflict
		}
	case "service_account":
		key = adoption.ClientOwnerUIDKey
		if !ServiceAccountOwned(app, identity.UID) {
			return member, ErrAuthorizationOwnershipConflict
		}
	default:
		return member, ErrBoundedDelegationUnsupported
	}
	member.binding = BoundedDelegationBinding{ID: app.ID, Attribute: key, Value: identity.UID}
	if !authority {
		return member, nil
	}
	return c.boundedSoftwareAuthority(ctx, realm, member)
}

func (c *Client) boundedSoftwareAuthority(ctx context.Context, realm string, member boundedDelegationMember) (boundedDelegationMember, error) {
	clientID := member.binding.ID
	ctx = context.WithValue(ctx, boundedDelegationReadKey{}, boundedDelegationRead{realm: realm, clientID: clientID})
	var user struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.get(ctx, applicationPath(realm, clientID)+"/service-account-user", &user); err != nil {
		return member, err
	}
	if user.ID == "" || !user.Enabled {
		return member, ErrBoundedDelegationUnsupported
	}
	member.userID = user.ID
	ctx = context.WithValue(ctx, boundedDelegationReadKey{}, boundedDelegationRead{realm: realm, clientID: clientID, userID: user.ID})
	base := adminRealmsPath + url.PathEscape(realm) + "/users/" + url.PathEscape(user.ID)
	var roles []RealmRole
	if err := c.get(ctx, base+"/role-mappings/realm/composite", &roles); err != nil {
		return member, err
	}
	if len(roles) > 4096 {
		return member, ErrAuthorizationReadLimit
	}
	for _, role := range roles {
		if role.ID == "" || role.Name == "" {
			return member, ErrBoundedDelegationUnsupported
		}
		member.roles = append(member.roles, role.ID)
	}
	var groups []struct {
		ID string `json:"id"`
	}
	if err := c.get(ctx, base+"/groups?first=0&max=129&briefRepresentation=true", &groups); err != nil {
		return member, err
	}
	if len(groups) > 128 {
		return member, ErrAuthorizationReadLimit
	}
	for _, group := range groups {
		if group.ID == "" {
			return member, ErrBoundedDelegationUnsupported
		}
		member.groups = append(member.groups, group.ID)
	}
	member.roles, member.groups = boundedDelegationStrings(member.roles), boundedDelegationStrings(member.groups)
	return member, nil
}

func (c *Client) boundedDelegationConditions(ctx context.Context, realm string, principals []BoundedDelegationPrincipal) ([]BoundedDelegationCondition, error) {
	if len(principals) == 0 || len(principals) > 128 {
		return nil, ErrBoundedDelegationUnsupported
	}
	conditions := []BoundedDelegationCondition{}
	for _, principal := range principals {
		selected, err := c.boundedPrincipalConditions(ctx, realm, principal)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, selected...)
	}
	if len(conditions) == 0 || len(conditions) > 128 {
		return nil, ErrBoundedDelegationUnsupported
	}
	slices.SortFunc(conditions, func(a, b BoundedDelegationCondition) int { return strings.Compare(a.Kind+"/"+a.ID, b.Kind+"/"+b.ID) })
	return conditions, nil
}

func (c *Client) boundedPrincipalConditions(ctx context.Context, realm string, principal BoundedDelegationPrincipal) ([]BoundedDelegationCondition, error) {
	switch principal.Kind {
	case "application", "service_account":
		member, err := c.boundedDelegationMember(ctx, realm, BoundedDelegationIdentity{Kind: principal.Kind, ClientID: principal.Ref, UID: principal.UID}, false)
		if err != nil {
			return nil, err
		}
		return []BoundedDelegationCondition{{Kind: "client", ID: member.binding.ID, Attribute: member.binding.Attribute, Value: member.binding.Value}}, nil
	case "realm_role":
		role, err := c.GetRealmRole(ctx, realm, principal.Ref)
		if err != nil {
			return nil, err
		}
		if role == nil || role.ID == "" {
			return nil, ErrBoundedDelegationUnsupported
		}
		return []BoundedDelegationCondition{{Kind: "role", ID: role.ID}}, nil
	case "organization":
		conditions := []BoundedDelegationCondition{}
		for _, binding := range principal.Groups {
			var group struct {
				ID         string              `json:"id"`
				Attributes map[string][]string `json:"attributes"`
			}
			if err := c.get(ctx, adminRealmsPath+url.PathEscape(realm)+"/groups/"+url.PathEscape(binding.ID), &group); err != nil {
				return nil, err
			}
			if binding.Attribute != "hanko.sh/organization-uid" || binding.Value == "" || group.ID != binding.ID || !slices.Equal(group.Attributes[binding.Attribute], []string{binding.Value}) {
				return nil, ErrAuthorizationOwnershipConflict
			}
			conditions = append(conditions, BoundedDelegationCondition{Kind: "group", ID: binding.ID, Attribute: binding.Attribute, Value: binding.Value})
		}
		return conditions, nil
	default:
		return nil, ErrBoundedDelegationUnsupported
	}
}

func boundedMemberMatches(member boundedDelegationMember, conditions []BoundedDelegationCondition) bool {
	for _, condition := range conditions {
		if condition.Kind == "client" && condition.ID == member.binding.ID || condition.Kind == "role" && slices.Contains(member.roles, condition.ID) || condition.Kind == "group" && slices.Contains(member.groups, condition.ID) {
			return true
		}
	}
	return false
}

func boundedMemberGranted(model AuthorizationModel, conditions map[string][]BoundedDelegationCondition, member boundedDelegationMember, resource, scope string) bool {
	for _, permission := range model.Permissions {
		if (len(permission.Resources) == 0 || slices.Contains(permission.Resources, resource)) && slices.Contains(permission.Scopes, scope) && boundedMemberMatches(member, conditions[permission.Name]) {
			return true
		}
	}
	return false
}

func boundedDelegationStrings(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func boundedDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
