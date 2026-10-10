package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

type realmAdoptionInventory struct {
	limit               int
	provider            adoption.ProviderIdentity
	items               []*adoptionInventoryItem
	complete, truncated bool
	findings            []adoption.Finding
	roles               []keycloak.RealmRole
	clients             []keycloak.InventoryClient
}
type adoptionInventoryItem struct {
	kind, realm, id, name string
	ownerID               string
	mapperOwners          map[string]string
	observation           adoption.Observation
	ids                   []string
	app                   *api.HankoApplicationSpec
	account               *api.HankoServiceAccountSpec
	role                  *api.HankoRoleSpec
}

func inventoryFact(domain, id, name, field string, value adoption.Value) adoption.Fact {
	return adoption.Fact{Domain: domain, Identity: id, Object: name, Field: field, Value: value, Classification: adoption.Supported, RoundTrip: adoption.Lossless}
}
func textValue(s string) adoption.Value  { return adoption.Value{Text: s} }
func setValue(s []string) adoption.Value { return adoption.Value{Set: s} }
func flagValue(b bool) adoption.Value    { return adoption.Value{Flag: &b} }
func (item *adoptionInventoryItem) fact(field string, v adoption.Value) {
	item.observation.Facts = append(item.observation.Facts, inventoryFact(item.kind, item.id, item.name, field, v))
}
func (item *adoptionInventoryItem) finding(code, message string, blocking bool) {
	item.observation.Findings = append(item.observation.Findings, adoption.Finding{Code: code, Domain: item.kind, Message: message, Blocking: blocking})
}
func inventoryReadTruncated(err error) bool {
	return errors.Is(err, keycloak.ErrAuthorizationReadLimit) || errors.Is(err, keycloak.ErrResponseTooLarge)
}
func (item *adoptionInventoryItem) failedRead(code string, err error) {
	item.failed(code)
	item.observation.Truncated = item.observation.Truncated || inventoryReadTruncated(err)
}
func (item *adoptionInventoryItem) failed(code string) {
	item.observation.Complete = false
	item.finding(code, "required bounded provider read failed", true)
}
func (item *adoptionInventoryItem) native(field, presence string, blocking bool) {
	f := inventoryFact(item.kind, item.id, item.name, field, textValue(presence))
	f.Classification = adoption.Preserved
	f.RoundTrip = adoption.PreservedNative
	if blocking {
		f.RoundTrip = adoption.Lossy
		item.finding("native_roundtrip_lossy", "current Manage mapping cannot prove preservation of provider-native semantics", true)
	}
	for i, existing := range item.observation.Facts {
		if existing.Domain == f.Domain && existing.Identity == f.Identity && existing.Field == f.Field {
			if blocking {
				item.observation.Facts[i] = f
			}
			return
		}
	}
	item.observation.Facts = append(item.observation.Facts, f)
}
func (item *adoptionInventoryItem) credential(present bool) {
	if !present {
		return
	}
	f := inventoryFact(item.kind, item.id, item.name, "credentialPresence", flagValue(true))
	f.Classification = adoption.SecurityExcluded
	f.RoundTrip = adoption.PreservedNative
	for _, existing := range item.observation.Facts {
		if existing.Field == "credentialPresence" && existing.Domain == item.kind {
			return
		}
	}
	item.observation.Facts = append(item.observation.Facts, f)
}
func newInventoryItem(kind, realm, id, name string) *adoptionInventoryItem {
	return &adoptionInventoryItem{kind: kind, realm: realm, id: id, name: name, ids: []string{id}, observation: adoption.Observation{Complete: true}}
}
func (inventory *realmAdoptionInventory) add(item *adoptionInventoryItem) {
	if inventory.full() {
		return
	}
	inventory.items = append(inventory.items, item)
	if !item.observation.Complete {
		inventory.complete = false
	}
}
func (inventory *realmAdoptionInventory) full() bool {
	if inventory.limit > 0 && len(inventory.items) >= inventory.limit {
		inventory.complete = false
		inventory.truncated = true
		return true
	}
	return false
}
func safeBrokerConfig(config map[string]string) map[string]string {
	// Typed allowlist, not a suffix heuristic. Unknown options (including tokens
	// under innocent names) never enter a manifest, status, hash, event or log.
	result := map[string]string{}
	for key, value := range config {
		switch key {
		case "authorizationUrl", "tokenUrl", "userInfoUrl", "issuer", "jwksUrl":
			u, err := url.Parse(value)
			if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && len(value) <= adoption.MaxTextBytes {
				result[key] = value
			}
		case "clientId":
			if len(value) <= 255 && !strings.ContainsAny(value, " \t\r\n") {
				result[key] = value
			}
		case "privateKeySignatureAlgorithm":
			if value == "RS256" || value == "ES256" {
				result[key] = value
			}
		case "syncMode":
			if value == "IMPORT" || value == "FORCE" || value == "LEGACY" {
				result[key] = value
			}
		case "validateSignature", "useJwksUrl", "backchannelSupported", "disableUserInfo":
			if value == "true" || value == "false" {
				result[key] = value
			}
		}
	}
	return result
}
func adoptionSourceIdentity(ctx context.Context, reader client.Reader, source *api.HankoKeycloakInstance, kc *keycloak.Client, realmID string) (adoption.ProviderIdentity, error) {
	u, err := url.Parse(kc.BaseURL())
	if err != nil {
		return adoption.ProviderIdentity{}, fmt.Errorf("parse current verified endpoint: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	p := adoption.ProviderIdentity{Instance: adoption.TargetIdentity{Kind: "HankoKeycloakInstance", Namespace: source.Namespace, Name: source.Name, UID: string(source.UID)}, Origin: u.String(), Trust: "public-ca", RealmID: realmID}
	if u.Scheme == "http" {
		p.Trust = "explicit-http"
	}
	if source.Spec.TLSCARef != "" {
		var ca corev1.Secret
		if err := reader.Get(ctx, types.NamespacedName{Namespace: source.Namespace, Name: source.Spec.TLSCARef}, &ca); err != nil {
			return p, err
		}
		certificates := []string{}
		remaining := ca.Data["ca.crt"]
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			remaining = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return p, fmt.Errorf("invalid public trust certificate")
			}
			sum := sha256.Sum256(cert.Raw)
			certificates = append(certificates, hex.EncodeToString(sum[:]))
		}
		if len(certificates) == 0 {
			return p, fmt.Errorf("public trust certificate missing")
		}
		slices.Sort(certificates)
		certificates = slices.Compact(certificates)
		canonical, _ := json.Marshal(certificates)
		sum := sha256.Sum256(canonical)
		p.Trust = "private-ca"
		p.CAReference = source.Namespace + "/" + source.Spec.TLSCARef
		p.CAIdentity = string(ca.UID) + ":sha256:" + hex.EncodeToString(sum[:])
	}
	return p, nil
}
func (r *HankoImportReconciler) discoverRealmAdoption(ctx context.Context, operation *api.HankoImport, kc *keycloak.Client, realm keycloak.Realm, includeBrokers bool, limit int) *realmAdoptionInventory {
	inventory := &realmAdoptionInventory{complete: true, limit: limit}
	var source api.HankoKeycloakInstance
	if err := r.importReader().Get(ctx, types.NamespacedName{Namespace: operation.Namespace, Name: operation.Spec.SourceRef}, &source); err != nil {
		inventory.complete = false
		return inventory
	}
	p, err := adoptionSourceIdentity(ctx, r.importReader(), &source, kc, realm.ID)
	inventory.provider = p
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "source_identity_unreadable", Domain: "identity", Message: "current source trust identity could not be read", Blocking: true})
	}
	realmItem := newInventoryItem("realm", realm.URLName(), realm.ID, realm.URLName())
	realmItem.fact("name", textValue(realm.URLName()))
	realmItem.fact("enabled", flagValue(realm.Enabled))
	realmItem.native("nativePresence", "realm lifecycle and undeclared children", false)
	realmItem.finding("realm_lifecycle_observe_only", "arbitrary existing realm lifecycle adoption is not qualified", true)
	realmItem.credential(len(realm.SMTPServer) > 0)
	inventory.add(realmItem)
	clients, err := kc.InventoryClients(ctx, realm.URLName())
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "client_inventory_unreadable", Domain: "application", Message: "complete paginated client inventory could not be read", Blocking: true})
	} else {
		inventory.clients = clients
		r.discoverInventoryClients(ctx, kc, inventory, realm.URLName())
	}
	inventory.roles, err = kc.InventoryRealmRoles(ctx, realm.URLName())
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "role_inventory_unreadable", Domain: "role", Message: "complete paginated realm-role inventory could not be read", Blocking: true})
	} else {
		r.discoverInventoryRoles(ctx, kc, inventory, realm.URLName())
	}
	r.discoverInventoryGroups(ctx, kc, inventory, realm.URLName(), "", 0, map[string]bool{})
	enabled, err := kc.InventoryOrganizationsEnabled(ctx, realm.URLName())
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "organization_capability_unreadable", Domain: "organization", Message: "optional organization capability could not be observed", Blocking: true})
	} else if enabled {
		r.discoverInventoryOrganizations(ctx, kc, inventory, realm.URLName())
	}
	if includeBrokers {
		r.discoverInventoryBrokers(ctx, kc, inventory, realm.URLName())
	}
	r.verifyInventoryIdentity(ctx, inventory, &source, kc, realm)
	slices.SortFunc(inventory.items, func(a, b *adoptionInventoryItem) int { return strings.Compare(a.kind+"\x00"+a.id, a.kind+"\x00"+b.id) })
	if len(inventory.items) > adoption.MaxInventory {
		inventory.items = inventory.items[:adoption.MaxInventory]
		inventory.complete = false
		inventory.truncated = true
	}
	return inventory
}
func (r *HankoImportReconciler) discoverInventoryClients(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm string) {
	for _, c := range inventory.clients {
		if inventory.full() {
			return
		}
		if keycloakInternalClients[c.ClientID] {
			continue
		}
		kind := "application"
		if c.ServiceAccountsEnabled && c.Protocol == "openid-connect" {
			kind = "service-account"
		}
		item := newInventoryItem(kind, realm, c.ID, c.ClientID)
		item.fact("name", textValue(c.ClientID))
		item.fact("protocol", textValue(c.Protocol))
		item.fact("enabled", flagValue(c.Enabled))
		item.fact("publicClient", flagValue(c.PublicClient))
		item.fact("standardFlow", flagValue(c.StandardFlowEnabled))
		item.fact("serviceAccounts", flagValue(c.ServiceAccountsEnabled))
		item.fact("directAccessGrants", flagValue(c.DirectAccessGrantsEnabled))
		item.fact("implicitFlow", flagValue(c.ImplicitFlowEnabled))
		item.fact("fullScopeAllowed", flagValue(c.FullScopeAllowed))
		pattern := "web"
		if c.PublicClient {
			pattern = "spa"
		}
		if c.ServiceAccountsEnabled {
			pattern = "m2m"
		}
		if c.Protocol != "saml" {
			item.fact("pattern", textValue(pattern))
		}
		if safeInventoryURLs(c.RedirectURIs) {
			item.fact("redirectURIs", setValue(c.RedirectURIs))
		} else {
			item.native("nativePresence", "callback URL is outside the public safe projection", true)
			item.credential(true)
		}
		if safeInventoryURLs(c.WebOrigins) {
			item.fact("webOrigins", setValue(c.WebOrigins))
		} else {
			item.native("nativePresence", "web origin is outside the public safe projection", true)
			item.credential(true)
		}
		item.credential(!c.PublicClient)
		owner := "unmarked"
		class := adoption.Supported
		item.ownerID = c.Attributes[applications.OwnerAttribute]
		if c.Attributes[applications.OwnerAttribute] != "" {
			owner = "application-marked"
			class = adoption.Conflicting
		}
		for k := range c.Attributes {
			if strings.Contains(k, "owner") && k != applications.OwnerAttribute && k != "hanko.sh/resource-server-ownership" {
				owner = "unknown-owner"
				class = adoption.Conflicting
			}
		}
		f := inventoryFact(kind, c.ID, c.ClientID, "owner", textValue(owner))
		f.Classification = class
		item.observation.Facts = append(item.observation.Facts, f)
		rs, err := kc.InventoryClientRoles(ctx, realm, c.ID)
		if err != nil {
			item.failedRead("client_roles_unreadable", err)
		} else {
			for _, role := range sortedRoles(rs) {
				r.observeInventoryRole(ctx, kc, item, realm, role, "client-role")
			}
		}
		mappers, err := kc.ListClientProtocolMappers(ctx, realm, c.ClientID)
		if err != nil {
			item.failedRead("protocol_mappers_unreadable", err)
		} else {
			observeInventoryMappers(item, mappers)
		}
		scopes, err := kc.GetClientRealmRoleScopes(ctx, realm, c.ClientID)
		if err != nil {
			item.failedRead("client_scopes_unreadable", err)
		} else {
			ids := []string{}
			for _, role := range scopes {
				ids = append(ids, role.Name)
				item.ids = append(item.ids, role.ID)
			}
			item.fact("realmRoles", setValue(ids))
		}
		spec, qualified := importedApplicationSpec(realm, c, rs, mappers)
		if qualified {
			if kind == "service-account" {
				item.account = &api.HankoServiceAccountSpec{RealmRef: realm, ClientID: c.ClientID, TokenClaims: spec.TokenClaims, Attributes: spec.Attributes}
			} else {
				item.app = &spec
			}
		} else {
			item.finding("application_mapping_unsupported", "client semantics cannot be represented by a qualified Observe declaration", true)
		}
		observeClientAttributes(item, c)
		current, err := kc.GetApplication(ctx, realm, c.ClientID)
		if err != nil || current == nil || current.ID != c.ID {
			item.failed("provider_identity_changed")
		}
		inventory.add(item)
		if c.AuthorizationServicesEnabled {
			r.discoverInventoryAuthorization(ctx, kc, inventory, realm, c)
		}
	}
}
func sortedRoles(values []keycloak.RealmRole) []keycloak.RealmRole {
	slices.SortFunc(values, func(a, b keycloak.RealmRole) int { return strings.Compare(a.ID, b.ID) })
	return values
}
func (r *HankoImportReconciler) observeInventoryRole(ctx context.Context, kc *keycloak.Client, item *adoptionInventoryItem, realm string, role keycloak.RealmRole, domain string) {
	if role.ID == "" || role.ContainerID == "" {
		item.failed("role_identity_incomplete")
		return
	}
	item.ids = append(item.ids, role.ID, role.ContainerID)
	item.observation.Facts = append(item.observation.Facts, inventoryFact(domain, role.ID, role.Name, "description", textValue(role.Description)), inventoryFact(domain, role.ID, role.Name, "container", textValue(role.ContainerID)))
	direct, closure, err := inventoryRoleClosure(ctx, kc, realm, role)
	if err != nil {
		item.failedRead("role_closure_unreadable", err)
		return
	}
	item.observation.Facts = append(item.observation.Facts, inventoryFact(domain, role.ID, role.Name, "composites", setValue(direct)), inventoryFact(domain, role.ID, role.Name, "effectiveComposites", setValue(closure)))
	native := false
	for key, values := range role.Attributes {
		if key == roles.OwnerAttribute {
			if len(values) == 1 && role.ID == item.id {
				item.ownerID = values[0]
			} else if len(values) > 0 {
				item.finding("foreign_role_owner", "role has an ambiguous or child owner marker", true)
			}
			continue
		}
		native = true
	}
	if native {
		item.native("nativePresence", "role attributes present", true)
	}
}
func inventoryRoleClosure(ctx context.Context, kc *keycloak.Client, realm string, root keycloak.RealmRole) ([]string, []string, error) {
	type queuedRole struct {
		role  keycloak.RealmRole
		depth int
	}
	queue := []queuedRole{{root, 0}}
	seen := map[string]bool{}
	direct, closure := []string{}, []string{}
	edges := 0
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node.role.ID] {
			continue
		}
		seen[node.role.ID] = true
		if node.depth > adoption.MaxDepth || len(seen) > adoption.MaxNodes {
			return direct, closure, keycloak.ErrAuthorizationReadLimit
		}
		if !node.role.Composite {
			continue
		}
		children, err := kc.InventoryRoleChildren(ctx, realm, node.role)
		if err != nil {
			return nil, nil, err
		}
		for _, child := range sortedRoles(children) {
			edges++
			if edges > adoption.MaxEdges || child.ID == "" {
				return direct, closure, keycloak.ErrAuthorizationReadLimit
			}
			identity := child.ContainerID + "/" + child.ID + "/" + child.Name
			closure = append(closure, identity)
			if node.depth == 0 {
				direct = append(direct, child.Name)
			}
			queue = append(queue, queuedRole{child, node.depth + 1})
		}
	}
	return direct, closure, nil
}
func (r *HankoImportReconciler) discoverInventoryRoles(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm string) {
	for _, role := range sortedRoles(inventory.roles) {
		if inventory.full() {
			return
		}
		item := newInventoryItem("role", realm, role.ID, role.Name)
		r.observeInventoryRole(ctx, kc, item, realm, role, "role")
		item.fact("name", textValue(role.Name))
		item.fact("owner", textValue("unmarked"))
		if isReservedAuthorityRole(role.Name) || strings.HasPrefix(role.Name, "default-roles-") || role.Name == "offline_access" || role.Name == "uma_authorization" {
			item.finding("reserved_role_native", "internal roles remain provider-native inventory", true)
		} else {
			direct, err := kc.GetRealmRoleCompositeNames(ctx, realm, role.Name)
			if err != nil {
				item.failedRead("direct_realm_composites_unreadable", err)
			} else {
				item.role = &api.HankoRoleSpec{RealmRef: realm, Name: role.Name, Description: role.Description, Composite: role.Composite, Composites: direct}
			}
		}
		inventory.add(item)
	}
}
func (r *HankoImportReconciler) discoverInventoryGroups(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm, parent string, depth int, seen map[string]bool) {
	if depth > adoption.MaxDepth || len(seen) >= adoption.MaxNodes {
		inventory.complete = false
		inventory.truncated = true
		return
	}
	groups, err := kc.InventoryGroups(ctx, realm, parent)
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "group_page_unreadable", Domain: "group", Message: "group hierarchy could not be read completely", Blocking: true})
		return
	}
	slices.SortFunc(groups, func(a, b keycloak.Group) int { return strings.Compare(a.ID, b.ID) })
	for _, group := range groups {
		if inventory.full() {
			return
		}
		if seen[group.ID] {
			inventory.complete = false
			continue
		}
		seen[group.ID] = true
		if len(seen) > adoption.MaxNodes {
			inventory.complete = false
			inventory.truncated = true
			return
		}
		item := newInventoryItem("group", realm, group.ID, group.Name)
		item.fact("path", textValue(group.Path))
		item.fact("parent", textValue(parent))
		item.native("owner", ownershipAttributesClass(group.Attributes), false)
		item.finding("group_inventory_only", "groups are inventory only; no HankoOrganization or membership is generated", true)
		mappings, err := kc.InventoryGroupRoles(ctx, realm, group.ID)
		if err != nil {
			item.failedRead("group_role_mappings_unreadable", err)
		} else {
			ids := []string{}
			for _, role := range mappings {
				ids = append(ids, role.ContainerID+"/"+role.ID)
				item.ids = append(item.ids, role.ID)
			}
			item.fact("realmRoles", setValue(ids))
		}
		inventory.add(item)
		r.discoverInventoryGroups(ctx, kc, inventory, realm, group.ID, depth+1, seen)
	}
}
func ownershipAttributesClass(attrs map[string][]string) string {
	for key := range attrs {
		if strings.Contains(key, "hanko") && strings.Contains(key, "owner") {
			return "marked"
		}
	}
	return "unmarked"
}
func (r *HankoImportReconciler) discoverInventoryOrganizations(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm string) {
	organizations, err := kc.InventoryOrganizations(ctx, realm)
	if err != nil {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "organization_inventory_unreadable", Domain: "organization", Message: "native organization inventory could not be read completely", Blocking: true})
		return
	}
	for _, o := range organizations {
		if inventory.full() {
			return
		}
		item := newInventoryItem("organization", realm, o.ID, o.Name)
		item.fact("alias", textValue(o.Alias))
		domains := []string{}
		for _, d := range o.Domains {
			domains = append(domains, d.Name+"/verified="+strconv.FormatBool(d.Verified))
		}
		item.fact("domains", setValue(domains))
		item.native("owner", ownershipAttributesClass(o.Attributes), false)
		item.finding("organization_inventory_only", "native organizations are inventory only; members are never read", true)
		inventory.add(item)
	}
}
func (r *HankoImportReconciler) discoverInventoryBrokers(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm string) {
	providers, err := kc.ListIdentityProviders(ctx, realm)
	if err != nil {
		inventory.complete = false
		return
	}
	for _, p := range providers {
		if inventory.full() {
			return
		}
		item := newInventoryItem("identity-provider", realm, p.InternalID, p.Alias)
		item.fact("providerType", textValue(p.ProviderID))
		item.fact("alias", textValue(p.Alias))
		item.fact("enabled", flagValue(p.Enabled))
		config := safeBrokerConfig(p.Config)
		values := []string{}
		for k, v := range config {
			values = append(values, k+"="+v)
		}
		item.fact("brokerEndpoints", setValue(values))
		item.credential(len(p.Config) > len(config))
		item.finding("opaque_broker_observe_only", "broker login and credential preservation are not adoption-qualified", true)
		mappers, err := kc.ListIdentityProviderMappers(ctx, realm, p.Alias)
		if err != nil {
			item.failedRead("identity_provider_mappers_unreadable", err)
		} else {
			for _, m := range mappers {
				item.ids = append(item.ids, m.ID)
				f := inventoryFact("identity-provider-mapper", m.ID, m.Name, "mapperType", textValue(m.IdentityProviderMapper))
				f.Classification = adoption.Preserved
				f.RoundTrip = adoption.PreservedNative
				item.observation.Facts = append(item.observation.Facts, f)
				config := safeInventoryIDPMapper(m)
				if len(config) > 0 {
					item.observation.Facts = append(item.observation.Facts, inventoryFact("identity-provider-mapper", m.ID, m.Name, "mapperFlags", setValue(config)))
				}
				item.credential(len(m.Config) > len(config))
			}
		}
		inventory.add(item)
	}
}
func (r *HankoImportReconciler) discoverInventoryAuthorization(ctx context.Context, kc *keycloak.Client, inventory *realmAdoptionInventory, realm string, c keycloak.InventoryClient) {
	item := newInventoryItem("resource-server", realm, c.ID, c.ClientID)
	graph, err := kc.InventoryAuthorization(ctx, realm, c.ID)
	if err != nil {
		item.failedRead("authorization_graph_unreadable", err)
		inventory.add(item)
		return
	}
	for _, s := range graph.Scopes {
		item.ids = append(item.ids, s.ID)
		item.observation.Facts = append(item.observation.Facts, inventoryFact("authorization-scope", s.ID, s.Name, "description", textValue(s.DisplayName)))
	}
	for _, v := range graph.Resources {
		item.ids = append(item.ids, v.ID)
		scopeIDs := []string{}
		for _, s := range v.Scopes {
			scopeIDs = append(scopeIDs, s.ID)
		}
		item.observation.Facts = append(item.observation.Facts, inventoryFact("authorization-resource", v.ID, v.Name, "scopes", setValue(scopeIDs)), inventoryFact("authorization-resource", v.ID, v.Name, "uris", setValue(v.URIs)), inventoryFact("authorization-resource", v.ID, v.Name, "type", textValue(v.Type)))
	}
	for _, p := range graph.Policies {
		item.ids = append(item.ids, p.ID)
		principals := []string{}
		for _, role := range p.Roles {
			principals = append(principals, "role/"+role.ID+"/required="+strconv.FormatBool(role.Required))
		}
		for _, cl := range p.Clients {
			principals = append(principals, "client/"+cl)
		}
		for _, g := range p.Groups {
			principals = append(principals, "group/"+g.ID+"/descendants="+strconv.FormatBool(g.ExtendChildren))
		}
		f := inventoryFact("authorization-policy", p.ID, p.Name, "principals", setValue(principals))
		f.Classification = adoption.Preserved
		f.RoundTrip = adoption.PreservedNative
		item.observation.Facts = append(item.observation.Facts, inventoryFact("authorization-policy", p.ID, p.Name, "policies", setValue(p.AssociatedPolicies)), f, inventoryFact("authorization-policy", p.ID, p.Name, "type", textValue(p.Type)), inventoryFact("authorization-policy", p.ID, p.Name, "logic", textValue(p.Logic)), inventoryFact("authorization-policy", p.ID, p.Name, "decisionStrategy", textValue(p.DecisionStrategy)))
		if p.Incomplete {
			item.failed("authorization_policy_incomplete")
		}
		if len(p.Config) > 0 {
			item.native("nativePresence", "opaque policy configuration", false)
		}
	}
	for _, p := range graph.Permissions {
		item.ids = append(item.ids, p.ID)
		item.observation.Facts = append(item.observation.Facts, inventoryFact("authorization-permission", p.ID, p.Name, "scopes", setValue(p.Scopes)), inventoryFact("authorization-permission", p.ID, p.Name, "resources", setValue(p.Resources)), inventoryFact("authorization-permission", p.ID, p.Name, "policies", setValue(p.Policies)))
	}
	// Provider identities are not portable Hanko refs. Never invent a reference
	// or assume blanket ownership over native/shared policy dependencies.
	item.finding("authorization_refs_unresolved", "native authorization graph requires reviewed unambiguous portable principal references; no aggregate is generated", true)
	item.observation.Complete = false
	inventory.add(item)
}
func candidateStatus(c adoption.Candidate) *api.AdoptionCandidateStatus {
	b, _ := json.Marshal(c)
	var result api.AdoptionCandidateStatus
	_ = json.Unmarshal(b, &result)
	return &result
}
func (r *HankoImportReconciler) publishImportEvidence(ctx context.Context, operation *api.HankoImport, realms []importedRealmData) {
	coverage := operation.Status.Coverage
	operation.Status.Inventory = nil
	coverage.InventoryCount = 0
	coverage.CandidateCount = 0
	coverage.UnsupportedCount = 0
	summaries := []api.ImportInventoryReference{}
	for _, realm := range realms {
		inventory := realm.inventory
		if inventory == nil {
			coverage.Complete = false
			continue
		}
		coverage.Complete = coverage.Complete && inventory.complete
		coverage.Truncated = coverage.Truncated || inventory.truncated
		for _, item := range inventory.items {
			coverage.InventoryCount++
			target, desired := r.currentInventoryTarget(ctx, operation, item)
			p := inventory.provider
			p.ObjectIDs = item.ids
			obs := item.observation
			obs.Complete = obs.Complete && inventory.complete
			obs.Truncated = obs.Truncated || inventory.truncated
			obs.Findings = append(obs.Findings, inventory.findings...)
			c := adoption.Build(target, p, obs, desired)
			coverage.Complete = coverage.Complete && c.Complete
			coverage.Truncated = coverage.Truncated || c.Truncated
			summary := api.ImportInventoryReference{Kind: item.kind, Realm: item.realm, ProviderID: item.id, Complete: c.Complete, Approvable: c.Approvable, Findings: candidateStatus(c).Findings}
			if len(summary.Realm) > adoption.MaxReferenceBytes || len(summary.ProviderID) > adoption.MaxProviderIDBytes {
				summary.Realm = ""
				summary.ProviderID = ""
				summary.Complete = false
				summary.Approvable = false
				coverage.Complete = false
				coverage.Truncated = true
				if len(summary.Findings) >= adoption.MaxFindings {
					summary.Findings = summary.Findings[:adoption.MaxFindings-1]
				}
				summary.Findings = append(summary.Findings, api.AdoptionFinding{Code: "identity_budget_exceeded", Domain: "identity", Message: "inventory identity omitted outside its public byte budget", Blocking: true})
			}
			if target.UID != "" {
				coverage.CandidateCount++
				summary.Target = &candidateStatus(c).Target
				summary.CandidateHash = c.CandidateHash
				if !r.patchInventoryCandidate(ctx, target, c) {
					coverage.Complete = false
					summary.Complete = false
					summary.Approvable = false
					if len(summary.Findings) >= 32 {
						summary.Findings = summary.Findings[:31]
					}
					summary.Findings = append(summary.Findings, api.AdoptionFinding{Code: "candidate_status_unpublished", Domain: item.kind, Message: "current target changed or evidence status could not be published", Blocking: true})
				}
			}
			if !c.Approvable {
				coverage.UnsupportedCount++
			}
			summaries = append(summaries, summary)
		}
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Realm+"\x00"+summaries[i].Kind+"\x00"+summaries[i].ProviderID < summaries[j].Realm+"\x00"+summaries[j].Kind+"\x00"+summaries[j].ProviderID
	})
	if coverage.InventoryCount > adoption.MaxInventory {
		coverage.Complete = false
		coverage.Truncated = true
	}
	if len(summaries) > 128 {
		summaries = summaries[:128]
		coverage.Complete = false
		coverage.Truncated = true
	}
	for {
		b, _ := json.Marshal(summaries)
		if len(b) < adoption.MaxSummaryBytes-2048 || len(summaries) == 0 {
			break
		}
		summaries = summaries[:len(summaries)-1]
		coverage.Complete = false
		coverage.Truncated = true
	}
	b, _ := json.Marshal(summaries)
	coverage.ObservationHash = string(iamcontract.Hash(iamcontract.ContractVersion(adoption.Version), "adoption-observation", "inventory-coverage", b))
	operation.Status.Inventory = summaries
	operation.Status.Coverage = coverage
	reason := "Complete"
	status := metav1.ConditionTrue
	if !coverage.Complete {
		status = metav1.ConditionFalse
		reason = "Partial"
	}
	if coverage.Truncated {
		reason = "Truncated"
	}
	if coverage.InventoryCount == 0 && !coverage.Complete {
		reason = "Incomplete"
	}
	setCondition(&operation.Status.Conditions, "InventoryComplete", status, reason, "discovery coverage is independent of terminal import completion")
}

func (r *HankoImportReconciler) verifyInventoryIdentity(ctx context.Context, inventory *realmAdoptionInventory, source *api.HankoKeycloakInstance, kc *keycloak.Client, realm keycloak.Realm) {
	// A changed realm UUID cannot be associated with the first observation.
	current, err := kc.GetRealm(ctx, realm.URLName())
	if err != nil || current.ID != realm.ID {
		inventory.complete = false
		inventory.truncated = inventory.truncated || inventoryReadTruncated(err)
		inventory.findings = append(inventory.findings, adoption.Finding{Code: "provider_identity_changed", Domain: "identity", Message: "realm identity changed or could not be verified after discovery", Blocking: true})
	}
	// Verify source/trust again without binding credential bytes to evidence.
	var sourceNow api.HankoKeycloakInstance
	if r.importReader().Get(ctx, client.ObjectKeyFromObject(source), &sourceNow) != nil {
		inventory.complete = false
	} else {
		currentClient, err := buildKCClientForInstance(ctx, r.importReader(), &sourceNow, r.RequireHTTPS)
		if err != nil {
			inventory.complete = false
		} else {
			identity, err := adoptionSourceIdentity(ctx, r.importReader(), &sourceNow, currentClient, realm.ID)
			a, _ := json.Marshal(identity)
			b, _ := json.Marshal(inventory.provider)
			if err != nil || string(a) != string(b) {
				inventory.complete = false
				inventory.findings = append(inventory.findings, adoption.Finding{Code: "provider_identity_changed", Domain: "identity", Message: "source instance, endpoint or public trust identity changed during observation", Blocking: true})
			}
		}
	}
}

func safeInventoryIDPMapper(mapper keycloak.IdentityProviderMapper) []string {
	// Only structural mapping options are public; unknown types and fixed
	// values remain opaque even when stored under innocent config keys.
	result := []string{}
	if mapper.IdentityProviderMapper != "oidc-user-attribute-idp-mapper" {
		return result
	}
	for key, value := range mapper.Config {
		switch key {
		case "claim", "user.attribute":
			if len(value) <= adoption.MaxReferenceBytes && value != "" {
				result = append(result, key+"="+value)
			}
		case "syncMode":
			if value == "IMPORT" || value == "FORCE" || value == "INHERIT" || value == "LEGACY" {
				result = append(result, key+"="+value)
			}
		}
	}
	return result
}
