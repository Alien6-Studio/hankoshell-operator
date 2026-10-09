package applications

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

type KeycloakDriver struct{ client *keycloak.Client }

func NewKeycloakDriver(c *keycloak.Client) *KeycloakDriver { return &KeycloakDriver{client: c} }
func (*KeycloakDriver) Capabilities(context.Context) (CapabilityEvidence, error) {
	return KeycloakEvidence(), nil
}
func providerProtocol(protocol string) string {
	if protocol == "oidc" {
		return "openid-connect"
	}
	return protocol
}
func publicProtocol(protocol string) string {
	switch protocol {
	case "openid-connect":
		return "oidc"
	case "saml":
		return "saml"
	default:
		return "unsupported"
	}
}
func samlAttributes(s SAML) map[string]string {
	nameID := s.NameIDFormat
	if nameID == "unspecified" {
		nameID = "username"
	}
	return map[string]string{
		"saml.server.signature": "true", "saml.assertion.signature": "true",
		"saml.client.signature": "false", "saml.signature.algorithm": "RSA_SHA256",
		"saml_name_id_format": nameID, "saml_force_name_id_format": "true",
		"saml.force.post.binding": "true", "saml.authnstatement": "true",
		"saml.encrypt": "false", "saml.artifact.binding": "false",
		"saml.allow.ecp.flow": "false", "saml_assertion_consumer_url_post": s.ACS[0],
		"saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
	}
}
func desired(p Plan) keycloak.Application {
	i := p.intent
	attrs := cloneAttributes(p.resolved.Attributes)
	attrs[OwnerAttribute] = p.resolved.Owner
	attrs["login_theme"] = i.Theme
	result := keycloak.Application{ClientID: i.ClientID, Name: i.ClientID, Protocol: providerProtocol(i.Protocol), Enabled: true,
		PublicClient: i.Pattern == "spa", StandardFlowEnabled: i.Pattern != "m2m", ServiceAccountsEnabled: i.Pattern == "m2m",
		RedirectURIs: i.RedirectURIs, WebOrigins: []string{"+"}, Attributes: attrs}
	if i.Pattern == "m2m" {
		attrs["hanko.service"] = "true"
	} else {
		attrs["hanko.app"] = "true"
	}
	if len(i.PostLogoutURIs) > 0 {
		attrs["post.logout.redirect.uris"] = strings.Join(i.PostLogoutURIs, "##")
	}
	if i.Protocol == "saml" {
		for k, v := range samlAttributes(*i.SAML) {
			attrs[k] = v
		}
		result.RedirectURIs = i.SAML.ACS
		result.WebOrigins = []string{}
	}
	return result
}

// Observe reads only non-secret client semantics and declared dependencies.
// Provider UUIDs stay out of canonical state. Ownership is a classification,
// never a copied provider owner UID. Extra mapper IDs/defaults are excluded.
func (d *KeycloakDriver) Observe(ctx context.Context, p Plan) (State, error) {
	if err := p.Validate(p); err != nil {
		return State{}, err
	}
	got, err := d.client.GetApplication(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return State{}, iamcontract.SafeError(err)
	}
	return d.observe(ctx, p, got)
}

type observedApplication struct {
	Present             bool
	Protocol, Ownership string
	Client              keycloak.Application
	Roles               []Role
	ScopesManaged       bool
	Scopes              []string
	Mappers             []keycloak.ProtocolMapper
	IdentityMappers     []keycloak.IdentityProviderMapper
	Complete            bool
}

func (d *KeycloakDriver) observe(ctx context.Context, p Plan, got *keycloak.Application) (State, error) {
	o := observedApplication{Ownership: "absent", Roles: []Role{}, Scopes: []string{}, Mappers: []keycloak.ProtocolMapper{}, IdentityMappers: []keycloak.IdentityProviderMapper{}, Complete: true}
	state := State{Observation: iamcontract.Observation{Complete: true, Drifted: true}}
	if got != nil {
		state = State{Present: true, ProviderID: got.ID, Owned: got.Attributes[OwnerAttribute] == p.resolved.Owner, Protocol: publicProtocol(got.Protocol)}
		o.Present, o.Protocol = true, state.Protocol
		o.Ownership = ownershipClass(got.Attributes[OwnerAttribute], p.resolved.Owner)
		o.Client, o.Complete = observedClient(*got, p)
		if err := d.observeRoles(ctx, p, &o); err != nil {
			return State{}, iamcontract.SafeError(err)
		}
		if state.Protocol == "oidc" {
			if err := d.observeMappers(ctx, p, &o); err != nil {
				return State{}, iamcontract.SafeError(err)
			}
		}
		state.Observation.Drifted = applicationDrift(p, o)
		if !o.Complete {
			state.Findings = []iamcontract.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "application", Code: "native_metadata_not_observed", Message: "credential-shaped native metadata is excluded from observation", ReadOnly: true}}
		}
	}
	data, _ := json.Marshal(o)
	state.Observation.StateHash = iamcontract.Hash(iamcontract.Version, "applications", "observation", data)
	state.Observation.Complete = o.Complete
	return state, nil
}
func ownershipClass(uid, owner string) string {
	if uid == "" {
		return "unmarked"
	}
	if uid == owner {
		return "owned"
	}
	return "foreign"
}
func observedClient(got keycloak.Application, p Plan) (keycloak.Application, bool) {
	got.ID = ""
	got.RedirectURIs = stringSet(got.RedirectURIs)
	got.WebOrigins = stringSet(got.WebOrigins)
	got.Attributes = cloneAttributes(got.Attributes)
	delete(got.Attributes, OwnerAttribute)
	delete(got.Attributes, "hanko.sh/resource-server-ownership")
	// Generated artifact identity is irrelevant to the supported POST-only contract.
	if p.intent.Protocol == "saml" {
		delete(got.Attributes, "saml.artifact.binding.identifier")
	}
	delete(got.Attributes, "client.secret.creation.time")
	complete := sanitizeObservedConfig(got.Attributes)
	normalizeObservedAttributes(got.Attributes, p)
	return got, complete
}
func sanitizeObservedConfig(config map[string]string) bool {
	complete := true
	for key := range config {
		if sensitiveMetadata(key) {
			delete(config, key)
			complete = false
		}
	}
	return complete
}
func (d *KeycloakDriver) observeRoles(ctx context.Context, p Plan, o *observedApplication) error {
	roles, err := d.client.ListClientRoles(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		o.Roles = append(o.Roles, Role{role.Name, role.Description})
	}
	slices.SortFunc(o.Roles, func(a, b Role) int { return strings.Compare(a.Name, b.Name) })
	if !p.intent.ScopesManaged {
		return nil
	}
	scopes, err := d.client.GetClientRealmRoleScopes(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return err
	}
	for _, role := range scopes {
		o.Scopes = append(o.Scopes, role.Name)
	}
	o.Scopes, o.ScopesManaged = stringSet(o.Scopes), true
	return nil
}
func (d *KeycloakDriver) observeMappers(ctx context.Context, p Plan, o *observedApplication) error {
	mappers, err := d.client.ListClientProtocolMappers(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return err
	}
	for _, mapper := range mappers {
		mapper = keycloak.CanonicalProtocolMapper(mapper)
		mapper.ID = ""
		mapper.Config = observedMapperConfig(mapper.Config, p.resolved.Owner)
		if !sanitizeObservedConfig(mapper.Config) {
			o.Complete = false
		}
		o.Mappers = append(o.Mappers, mapper)
	}
	slices.SortFunc(o.Mappers, func(a, b keycloak.ProtocolMapper) int { return strings.Compare(a.Name, b.Name) })
	for _, expected := range p.resolved.IdentityMappers {
		if err := d.observeIdentityMapper(ctx, p, o, expected); err != nil {
			return err
		}
	}
	slices.SortFunc(o.IdentityMappers, func(a, b keycloak.IdentityProviderMapper) int {
		return strings.Compare(a.IdentityProviderAlias+"/"+a.Name, b.IdentityProviderAlias+"/"+b.Name)
	})
	return nil
}
func (d *KeycloakDriver) observeIdentityMapper(ctx context.Context, p Plan, o *observedApplication, expected keycloak.IdentityProviderMapper) error {
	found, err := d.client.ListIdentityProviderMappers(ctx, p.resolved.Realm, expected.IdentityProviderAlias)
	if err != nil {
		return err
	}
	for _, mapper := range found {
		if mapper.Name != expected.Name {
			continue
		}
		mapper.ID = ""
		mapper.Config = observedMapperConfig(mapper.Config, p.resolved.Owner)
		if !sanitizeObservedConfig(mapper.Config) {
			o.Complete = false
		}
		o.IdentityMappers = append(o.IdentityMappers, mapper)
	}
	return nil
}
func sensitiveMetadata(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "private") || strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "credential") || strings.Contains(k, "access_token") || strings.Contains(k, "bearer")
}
func applicationDrift(p Plan, o observedApplication) bool {
	want := desired(p)
	attrs := cloneAttributes(want.Attributes)
	delete(attrs, OwnerAttribute)
	if attrs["login_theme"] == "" {
		delete(attrs, "login_theme")
	}
	if !o.Complete || clientFlagsDrift(o.Client, want) || clientEndpointsDrift(o.Client, want) || !maps.Equal(o.Client.Attributes, attrs) {
		return true
	}
	if len(p.intent.Roles) > 0 && !slices.Equal(o.Roles, p.intent.Roles) {
		return true
	}
	if p.intent.ScopesManaged && !slices.Equal(o.Scopes, p.intent.RealmRoleScopes) {
		return true
	}
	return protocolMappersDrift(p, o.Mappers) || identityMappersDrift(p, o.IdentityMappers)
}
func clientFlagsDrift(actual, want keycloak.Application) bool {
	return actual.Protocol != want.Protocol || actual.Name != want.Name || actual.Enabled != want.Enabled || actual.PublicClient != want.PublicClient || actual.StandardFlowEnabled != want.StandardFlowEnabled || actual.ServiceAccountsEnabled != want.ServiceAccountsEnabled || actual.DirectAccessGrantsEnabled || actual.ImplicitFlowEnabled || actual.FullScopeAllowed
}
func clientEndpointsDrift(actual, want keycloak.Application) bool {
	return !slices.Equal(actual.RedirectURIs, stringSet(want.RedirectURIs)) || !slices.Equal(actual.WebOrigins, stringSet(want.WebOrigins))
}
func protocolMappersDrift(p Plan, observed []keycloak.ProtocolMapper) bool {
	for _, expected := range p.resolved.Mappers {
		expected = keycloak.CanonicalProtocolMapper(expected)
		expected.Config = observedMapperConfig(expected.Config, p.resolved.Owner)
		matches := 0
		for _, actual := range observed {
			if actual.Name != expected.Name {
				continue
			}
			matches++
			if actual.Protocol != expected.Protocol || actual.ProtocolMapper != expected.ProtocolMapper || !maps.Equal(actual.Config, expected.Config) {
				return true
			}
		}
		if matches != 1 {
			return true
		}
	}
	return false
}
func identityMappersDrift(p Plan, observed []keycloak.IdentityProviderMapper) bool {
	for _, expected := range p.resolved.IdentityMappers {
		expected.Config = observedMapperConfig(expected.Config, p.resolved.Owner)
		matches := 0
		for _, actual := range observed {
			if actual.IdentityProviderAlias != expected.IdentityProviderAlias || actual.Name != expected.Name {
				continue
			}
			matches++
			if actual.IdentityProviderMapper != expected.IdentityProviderMapper || !maps.Equal(actual.Config, expected.Config) {
				return true
			}
		}
		if matches != 1 {
			return true
		}
	}
	return false
}

// Keycloak inserts these harmless defaults on create and removes empty themes.
// They are observed when explicitly requested as native attributes, otherwise
// only a non-default value is semantic drift. Generated defaults are not intent.
func normalizeObservedAttributes(attrs map[string]string, p Plan) {
	if attrs["login_theme"] == "" {
		delete(attrs, "login_theme")
	}
	for key, value := range map[string]string{"realm_client": "false", "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "false"} {
		if _, managed := p.resolved.Attributes[key]; !managed && attrs[key] == value {
			delete(attrs, key)
		}
	}
}
func (d *KeycloakDriver) Ensure(ctx context.Context, p Plan) (State, error) {
	state, err := d.Observe(ctx, p)
	if err != nil {
		return state, err
	}
	if state.Present && state.Protocol != p.intent.Protocol {
		if state.Owned {
			return state, ErrProtocolChange
		}
		return state, ErrProtocolMismatch
	}
	if state.Present && !state.Owned {
		state, err = d.adoptApproved(ctx, p, state)
		if err != nil {
			return state, err
		}
	}

	want := desired(p)
	created := !state.Present
	if !state.Present {
		err = d.client.CreateApplication(ctx, p.resolved.Realm, want)
	} else {
		want.ID = state.ProviderID
		err = d.client.UpdateApplication(ctx, p.resolved.Realm, want, OwnerAttribute, p.resolved.Owner)
	}
	if errors.Is(err, keycloak.ErrApplicationPrecondition) {
		return state, ErrOwnershipConflict
	}
	if err != nil {
		return state, iamcontract.SafeError(err)
	}
	result, err := d.Observe(ctx, p)
	result.Created = created
	return result, err
}
func (d *KeycloakDriver) adoptApproved(ctx context.Context, p Plan, state State) (State, error) {
	if !state.Observation.Complete || state.ProviderID != p.resolved.MigrationUUID || state.Observation.StateHash != p.resolved.MigrationObservation {
		return state, ErrOwnershipConflict
	}
	got, err := d.client.GetApplication(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return state, iamcontract.SafeError(err)
	}
	if got == nil || got.Attributes[OwnerAttribute] != "" {
		return state, ErrOwnershipConflict
	}
	fresh, err := d.observe(ctx, p, got)
	if err != nil {
		return state, err
	}
	if !fresh.Observation.Complete || fresh.ProviderID != p.resolved.MigrationUUID || fresh.Observation.StateHash != p.resolved.MigrationObservation {
		return fresh, iamcontract.ErrStale
	}
	if err := d.client.MarkApplicationOwner(ctx, p.resolved.Realm, *got, OwnerAttribute, p.resolved.Owner); err != nil {
		return fresh, iamcontract.SafeError(err)
	}
	next, err := d.Observe(ctx, p)
	if err != nil {
		return next, err
	}
	if !next.Owned {
		return next, ErrOwnershipConflict
	}
	return next, nil
}
func (d *KeycloakDriver) CheckOwned(ctx context.Context, p Plan) (State, error) {
	if err := p.Validate(p); err != nil {
		return State{}, err
	}
	got, err := d.client.GetApplication(ctx, p.resolved.Realm, p.intent.ClientID)
	if err != nil {
		return State{}, iamcontract.SafeError(err)
	}
	if got == nil {
		return State{}, nil
	}
	return State{Present: true, Owned: got.Attributes[OwnerAttribute] == p.resolved.Owner, ProviderID: got.ID, Protocol: publicProtocol(got.Protocol)}, nil
}
func (d *KeycloakDriver) DeleteOwned(ctx context.Context, p Plan) error {
	state, err := d.CheckOwned(ctx, p)
	if err != nil || !state.Present {
		return err
	}
	if !state.Owned {
		return ErrOwnershipConflict
	}
	return iamcontract.SafeError(d.client.DeleteApplicationIfOwned(ctx, p.resolved.Realm, state.ProviderID, p.intent.ClientID, OwnerAttribute, p.resolved.Owner))
}

func observedMapperConfig(config map[string]string, owner string) map[string]string {
	result := maps.Clone(config)
	if uid, found := result[OwnerAttribute]; found {
		result[OwnerAttribute] = "foreign"
		if uid == owner {
			result[OwnerAttribute] = "owned"
		}
	}
	return result
}
