package applications

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const maxProtocolDocument = 1 << 20

// CheckXMLBounds rejects DTD/entity instructions, multiple roots, duplicate ID
// attributes and excessive depth/elements before any XML tree is allocated.
// Go's decoder does not fetch external entities; unknown entities are errors.
func CheckXMLBounds(data []byte) error {
	if len(data) == 0 || len(data) > maxProtocolDocument {
		return fmt.Errorf("XML document exceeds bounded protocol contract")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	bounds := xmlBounds{ids: map[string]bool{}}
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid XML protocol document")
		}
		if err := bounds.accept(token); err != nil {
			return err
		}
	}
	if bounds.roots != 1 || bounds.depth != 0 {
		return fmt.Errorf("invalid XML root")
	}
	return nil
}

type xmlBounds struct {
	depth, roots, elements int
	ids                    map[string]bool
}

func (b *xmlBounds) accept(token xml.Token) error {
	switch v := token.(type) {
	case xml.StartElement:
		if b.depth == 0 {
			b.roots++
		}
		b.depth++
		b.elements++
		if b.roots > 1 || b.depth > 32 || b.elements > 4096 {
			return fmt.Errorf("XML structure exceeds bounded protocol contract")
		}
		return b.attributes(v.Attr)
	case xml.EndElement:
		b.depth--
	case xml.Directive:
		return fmt.Errorf("XML directives are forbidden")
	case xml.ProcInst:
		if v.Target != "xml" || b.elements != 0 {
			return fmt.Errorf("XML processing instructions are forbidden")
		}
	case xml.CharData:
		if b.depth == 0 && strings.TrimSpace(string(v)) != "" {
			return fmt.Errorf("XML data outside root")
		}
	}
	return nil
}
func (b *xmlBounds) attributes(attrs []xml.Attr) error {
	seen := map[xml.Name]bool{}
	for _, attr := range attrs {
		if seen[attr.Name] {
			return fmt.Errorf("duplicate XML attribute")
		}
		seen[attr.Name] = true
		if !strings.EqualFold(attr.Name.Local, "id") {
			continue
		}
		if attr.Name.Local != "ID" || attr.Name.Space != "" || attr.Value == "" || b.ids[attr.Value] {
			return fmt.Errorf("ambiguous XML ID")
		}
		b.ids[attr.Value] = true
	}
	return nil
}

type samlDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	Entity  string   `xml:"entityID,attr"`
	IDP     []struct {
		Protocols string            `xml:"protocolSupportEnumeration,attr"`
		Keys      []samlMetadataKey `xml:"KeyDescriptor"`
		SSO       []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
	} `xml:"IDPSSODescriptor"`
}

type samlMetadataKey struct {
	Use          string   `xml:"use,attr"`
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

func validateMetadataCertificates(keys []samlMetadataKey) error {
	count := 0
	for _, key := range keys {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, encoded := range key.Certificates {
			count++
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
			if err != nil || len(der) > 16384 || count > 8 {
				return fmt.Errorf("invalid bounded SAML signing certificate")
			}
			if _, err := x509.ParseCertificate(der); err != nil {
				return fmt.Errorf("invalid SAML signing certificate")
			}
		}
	}
	if count == 0 {
		return fmt.Errorf("missing SAML signing certificates")
	}
	return nil
}

// ParseSAMLMetadata consumes public TLS-authenticated realm metadata. It is not
// an XMLDSig verifier or an SP response validator. No full XML is returned.
func ParseSAMLMetadata(data []byte, expectedIssuer string) (Metadata, error) {
	if err := CheckXMLBounds(data); err != nil {
		return Metadata{}, err
	}
	if err := validateMetadataNamespaces(data); err != nil {
		return Metadata{}, err
	}
	var descriptor samlDescriptor
	if err := xml.Unmarshal(data, &descriptor); err != nil || descriptor.Entity != expectedIssuer || len(descriptor.IDP) != 1 {
		return Metadata{}, fmt.Errorf("SAML metadata identity mismatch")
	}
	idp := descriptor.IDP[0]
	if idp.Protocols != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return Metadata{}, fmt.Errorf("unsupported SAML metadata protocol")
	}
	if err := validateMetadataCertificates(idp.Keys); err != nil {
		return Metadata{}, err
	}

	result := Metadata{Issuer: descriptor.Entity, URL: expectedIssuer + "/protocol/saml/descriptor"}
	for _, service := range idp.SSO {
		if service.Binding == POSTBinding {
			if result.SSO != "" || service.Location != expectedIssuer+"/protocol/saml" {
				return Metadata{}, fmt.Errorf("SAML SSO endpoint mismatch")
			}
			result.SSO = service.Location
		}
	}
	if result.SSO == "" {
		return Metadata{}, fmt.Errorf("missing HTTP-POST SAML SSO endpoint")
	}
	return result, nil
}

func validateMetadataNamespaces(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid XML metadata")
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		var expected string
		switch element.Name.Local {
		case "EntityDescriptor", "IDPSSODescriptor", "KeyDescriptor", "SingleSignOnService":
			expected = "urn:oasis:names:tc:SAML:2.0:metadata"
		case "KeyInfo", "X509Data", "X509Certificate":
			expected = "http://www.w3.org/2000/09/xmldsig#"
		}
		if expected != "" && element.Name.Space != expected {
			return fmt.Errorf("ambiguous SAML metadata namespace")
		}
	}
}

func (d *KeycloakDriver) Metadata(ctx context.Context, p Plan) (Metadata, error) {
	if err := p.Validate(p); err != nil {
		return Metadata{}, err
	}
	base := p.resolved.PublicBase
	if base == "" {
		base = d.client.BaseURL()
	}
	expected := strings.TrimRight(base, "/") + "/realms/" + url.PathEscape(p.resolved.Realm)
	fallback := Metadata{}
	if p.intent.Protocol == "oidc" {
		fallback = expectedOIDCMetadata(expected)
	}
	data, err := d.client.ProtocolDocument(ctx, p.resolved.Realm, p.intent.Protocol)
	if err != nil {
		return fallback, iamcontract.SafeError(err)
	}
	if p.intent.Protocol == "saml" {
		return ParseSAMLMetadata(data, expected)
	}
	var doc struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		JWKS          string `json:"jwks_uri"`
		UserInfo      string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Issuer != expected {
		return fallback, fmt.Errorf("OIDC discovery identity mismatch")
	}
	prefix := expected + "/protocol/openid-connect"
	if doc.Authorization != prefix+"/auth" || doc.Token != prefix+"/token" || doc.JWKS != prefix+"/certs" || doc.UserInfo != prefix+"/userinfo" {
		return fallback, fmt.Errorf("OIDC discovery endpoint mismatch")
	}
	return Metadata{Issuer: doc.Issuer, Authorization: doc.Authorization, Token: doc.Token, JWKS: doc.JWKS, UserInfo: doc.UserInfo, URL: expected + "/.well-known/openid-configuration"}, nil
}

func expectedOIDCMetadata(issuer string) Metadata {
	prefix := issuer + "/protocol/openid-connect"
	return Metadata{Issuer: issuer, Authorization: prefix + "/auth", Token: prefix + "/token", JWKS: prefix + "/certs", UserInfo: prefix + "/userinfo", URL: issuer + "/.well-known/openid-configuration"}
}
