package keycloak

import (
	"net/url"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// QualifiedNativeLocale is a closed public metadata schema, qualified per
// provider resource family. Other arbitrary native attributes remain opaque.
func QualifiedNativeLocale(key string, values []string) bool {
	return key == "locale" && len(values) == 1 && (values[0] == "en" || values[0] == "fr")
}

func QualifiedClientAttribute(key, value string) bool {
	if adoption.KeycloakDefault(key, value) || adoption.ReservedAttribute(key) {
		return true
	}
	if QualifiedNativeLocale(key, []string{value}) {
		return true
	}
	switch key {
	case "hanko.app", "hanko.service":
		return value == "true"
	case "client.secret.creation.time", "saml.artifact.binding.identifier":
		return true // Excluded generated metadata, never canonicalized.
	case "pkce.code.challenge.method":
		return value == "S256" || value == "plain"
	case "post.logout.redirect.uris":
		return qualifiedClientURLs(strings.Split(value, "##"))
	case "login_theme":
		return value == "" || value == "keycloak" || value == "keycloak.v2"
	}
	return qualifiedSAMLAttribute(key, value)
}
func qualifiedSAMLAttribute(key, value string) bool {
	switch key {
	case "saml.assertion.signature", "saml.server.signature":
		return value == "true" || value == "false"
	case "saml_name_id_format":
		return slices.Contains([]string{"username", "persistent", "transient", "email", "unspecified"}, value)
	case "saml_assertion_consumer_url_post":
		return qualifiedClientURLs([]string{value})
	case "saml.client.signature", "saml.encrypt", "saml.artifact.binding", "saml.allow.ecp.flow":
		return value == "false"
	case "saml.signature.algorithm":
		return value == "RSA_SHA256"
	case "saml.force.post.binding", "saml_force_name_id_format", "saml.authnstatement":
		return value == "true"
	case "saml_signature_canonicalization_method":
		return value == "http://www.w3.org/2001/10/xml-exc-c14n#"
	}
	return false
}

func qualifiedClientURLs(values []string) bool {
	for _, value := range values {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
	}
	return true
}

func QualifiedClientAttributes(attrs map[string]string) bool {
	for key, value := range attrs {
		if !QualifiedClientAttribute(key, value) {
			return false
		}
	}
	return true
}

// PreservationQualified refuses masked, opaque or unknown native settings.
// A successful result grants no ownership: the caller must verify the receipt.
func (s *ClientOwnershipSnapshot) PreservationQualified() bool {
	if s == nil || !s.QualifiedLeaf() || !QualifiedClientAttributes(s.Application.Attributes) {
		return false
	}
	return qualifiedMapperDocuments(s.mappers, s.mappers, &s.Application)
}

// Mappers created by explicit Manage keep the existing closed token-claim
// schema. A parent receipt never grants authority over an unmarked mapper.
func qualifiedLiveClientMapper(mapper ProtocolMapper, app *Application) bool {
	if QualifiedAdoptionMapper(mapper) {
		return true
	}
	if app == nil || mapper.Protocol != "openid-connect" || !qualifiedMapperReference(mapper.Name) || !liveMapperOwnerMatches(mapper, app) {
		return false
	}
	if !slices.Contains([]string{"oidc-hardcoded-claim-mapper", "oidc-audience-mapper", "oidc-usermodel-attribute-mapper", "oidc-usermodel-realm-role-mapper"}, mapper.ProtocolMapper) {
		return false
	}
	for key, value := range mapper.Config {
		if !qualifiedManagedMapperField(mapper.ProtocolMapper, key, value) {
			return false
		}
	}
	return true
}

func liveMapperOwnerMatches(mapper ProtocolMapper, app *Application) bool {
	uid := app.Attributes[adoption.ApplicationOwnerKey]
	if validClientAdoptionReceipt(app, "HankoApplication", uid) && uid != "" {
		return mapper.Config[adoption.ApplicationOwnerKey] == uid && mapper.Config[adoption.ClientOwnerKindKey] == "" && mapper.Config[adoption.ClientOwnerUIDKey] == ""
	}
	uid = app.Attributes[adoption.ClientOwnerUIDKey]
	return uid != "" && validClientAdoptionReceipt(app, "HankoServiceAccount", uid) && serviceMapperOwned(mapper.Config, uid)
}

func qualifiedManagedMapperField(implementation, key, value string) bool {
	switch key {
	case adoption.ApplicationOwnerKey, adoption.ClientOwnerKindKey, adoption.ClientOwnerUIDKey:
		return true // Exact kind/UID checked separately, never a wildcard schema.
	case "claim.value":
		return implementation == "oidc-hardcoded-claim-mapper" && len(value) <= 4096
	case "included.custom.audience":
		return implementation == "oidc-audience-mapper" && qualifiedMapperReference(value)
	case "included.client.audience":
		return implementation == "oidc-audience-mapper" && value == ""
	case "aggregate.attrs":
		return implementation == "oidc-usermodel-attribute-mapper" && value == "false"
	case "usermodel.realmRoleMapping.rolePrefix":
		return implementation == "oidc-usermodel-realm-role-mapper" && (value == "" || qualifiedMapperReference(value))
	default:
		return QualifiedAdoptionMapper(ProtocolMapper{Protocol: "openid-connect", ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{key: value}})
	}
}

func QualifiedAdoptionMapper(mapper ProtocolMapper) bool {
	if !qualifiedMapperImplementation(mapper) {
		return false
	}
	for key, value := range mapper.Config {
		switch key {
		case "claim.name", "user.attribute":
			if !qualifiedMapperReference(value) {
				return false
			}
		case "jsonType.label":
			if !slices.Contains([]string{"String", "long", "int", "boolean", "JSON"}, value) {
				return false
			}
		case "access.token.claim", "id.token.claim", "userinfo.token.claim", "introspection.token.claim", "multivalued":
			if value != "true" && value != "false" {
				return false
			}
		case "usermodel.realmRoleMapping.rolePrefix":
			if value != "" {
				return false
			}
		case adoption.ApplicationOwnerKey:
		default:
			return false
		}
	}
	return true
}

func QualifiedRoleAttributes(attrs map[string][]string) bool {
	for key, values := range attrs {
		if adoption.ReservedAttribute(key) {
			continue
		}
		if !QualifiedNativeLocale(key, values) {
			return false
		}
	}
	return true
}

func validClientAdoptionReceipt(a *Application, kind, uid string) bool {
	if a == nil {
		return false
	}
	proof, err := adoption.ParseReceipt(a.Attributes[adoption.ReceiptKey])
	if err != nil || proof.TargetKind != kind || proof.TargetUID != uid {
		return false
	}
	if kind == "HankoApplication" {
		return ApplicationOwned(a, uid)
	}
	return kind == "HankoServiceAccount" && ServiceAccountOwned(a, uid)
}

func ValidRoleAdoptionReceipt(role *RealmRole, uid string) bool {
	if role == nil || len(role.Attributes[adoption.ReceiptKey]) != 1 || len(role.Attributes[adoption.RoleOwnerKey]) != 1 || role.Attributes[adoption.RoleOwnerKey][0] != uid {
		return false
	}
	for key := range role.Attributes {
		if adoption.ReservedAttribute(key) && key != adoption.ReceiptKey && key != adoption.RoleOwnerKey {
			return false
		}
	}
	proof, err := adoption.ParseReceipt(role.Attributes[adoption.ReceiptKey][0])
	return err == nil && proof.TargetKind == "HankoRole" && proof.TargetUID == uid
}
func cloneRoleAttributes(attrs map[string][]string) map[string][]string {
	result := make(map[string][]string, len(attrs))
	for key, values := range attrs {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func qualifiedMapperReference(value string) bool {
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, " \t\r\n\x00")
}

func qualifiedMapperImplementation(mapper ProtocolMapper) bool {
	return mapper.Protocol == "openid-connect" && slices.Contains([]string{"oidc-usermodel-attribute-mapper", "oidc-usermodel-realm-role-mapper"}, mapper.ProtocolMapper)
}
