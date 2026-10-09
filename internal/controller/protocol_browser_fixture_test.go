//go:build keycloak_integration

package controller_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html"
)

func protocolBrowser(f *keycloakFixture) *http.Client {
	jar, err := cookiejar.New(nil)
	f.requireNoError(err)
	c := *f.http
	c.Jar = jar
	return &c
}
func protocolHTTP(f *keycloakFixture, c *http.Client, method, endpoint string, form url.Values) (int, http.Header, []byte) {
	f.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequest(method, endpoint, body)
	f.requireNoError(err)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.Do(request)
	f.requireNoError(err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	f.requireNoError(err)
	if len(data) > 1<<20 {
		f.t.Fatal("protocol fixture response exceeds 1 MiB")
	}
	return response.StatusCode, response.Header, data
}
func protocolHTMLForm(data []byte, field string) (string, url.Values, bool) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return "", nil, false
	}
	var action string
	var values url.Values
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			current := url.Values{}
			var collect func(*html.Node)
			collect = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "input" {
					name, value := "", ""
					for _, attr := range n.Attr {
						if attr.Key == "name" {
							name = attr.Val
						}
						if attr.Key == "value" {
							value = attr.Val
						}
					}
					if name != "" {
						current.Add(name, value)
					}
				}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					collect(child)
				}
			}
			collect(node)
			if _, found := current[field]; found {
				values = current
				for _, attr := range node.Attr {
					if attr.Key == "action" {
						action = attr.Val
					}
				}
				return
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	return action, values, values != nil
}

// loginProtocol sends fixture credentials only to the verified Keycloak origin
// and never follows the final application redirect/POST. Sessions are disposable.
func loginProtocol(f *keycloakFixture, c *http.Client, method, endpoint string, form url.Values, username, password, acs string) (http.Header, []byte) {
	f.t.Helper()
	for attempt := 0; attempt < 8; attempt++ {
		status, headers, data := protocolHTTP(f, c, method, endpoint, form)
		if status == http.StatusFound || status == http.StatusSeeOther {
			location := headers.Get("Location")
			u, err := url.Parse(location)
			f.requireNoError(err)
			base, _ := url.Parse(endpoint)
			u = base.ResolveReference(u)
			if strings.HasPrefix(u.String(), acs+"?") {
				return headers, data
			}
			if u.Scheme != base.Scheme || u.Host != base.Host {
				f.t.Fatal("fixture refuses to forward login/session to another origin")
			}
			method, endpoint, form = http.MethodGet, u.String(), nil
			continue
		}
		if status != http.StatusOK {
			f.t.Fatalf("browser protocol HTTP %d (body withheld)", status)
		}
		if action, _, ok := protocolHTMLForm(data, "SAMLResponse"); ok {
			if action != acs {
				f.t.Fatal("SAML POST action is not the exact ACS")
			}
			return headers, data
		}
		action, values, ok := protocolHTMLForm(data, "username")
		if !ok {
			f.t.Fatal("expected disposable Keycloak login form (body withheld)")
		}
		base, _ := url.Parse(endpoint)
		u, err := url.Parse(action)
		f.requireNoError(err)
		u = base.ResolveReference(u)
		if u.Scheme != base.Scheme || u.Host != base.Host || !strings.HasPrefix(u.Path, "/realms/managed/login-actions/authenticate") {
			f.t.Fatal("untrusted credential form target")
		}
		values.Set("username", username)
		values.Set("password", password)
		values.Set("credentialId", "")
		method, endpoint, form = http.MethodPost, u.String(), values
	}
	f.t.Fatal("browser protocol did not complete within bounded redirects")
	return nil, nil
}

func fixtureProtocolUser(f *keycloakFixture) (string, string) {
	username, password := "protocol-user", fixtureSecret(f.t)
	f.secrets = append(f.secrets, password)
	f.admin(http.MethodPost, "/admin/realms/managed/users", map[string]any{
		"username": username, "email": "protocol-user@example.test", "emailVerified": true, "enabled": true,
		"firstName": "Protocol", "lastName": "Fixture",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	}, nil)
	return username, password
}

func samlAuthnRequest(entity, acs, endpoint, requestID string) url.Values {
	doc := etree.NewDocument()
	request := doc.CreateElement("samlp:AuthnRequest")
	request.CreateAttr("xmlns:samlp", samlProtocolNS)
	request.CreateAttr("xmlns:saml", samlAssertionNS)
	for key, value := range map[string]string{"ID": requestID, "Version": "2.0", "IssueInstant": time.Now().UTC().Format(time.RFC3339Nano), "Destination": endpoint, "AssertionConsumerServiceURL": acs, "ProtocolBinding": applications.POSTBinding} {
		request.CreateAttr(key, value)
	}
	request.CreateElement("saml:Issuer").SetText(entity)
	data, _ := doc.WriteToBytes()
	return url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(data)}, "RelayState": {"qualification"}}
}
func fixtureSAMLResponse(f *keycloakFixture, c *http.Client, entity, acs, endpoint, username, password string) ([]byte, string) {
	requestID := "_" + fixtureSecret(f.t)[:24]
	_, body := loginProtocol(f, c, http.MethodPost, endpoint, samlAuthnRequest(entity, acs, endpoint, requestID), username, password, acs)
	_, form, ok := protocolHTMLForm(body, "SAMLResponse")
	if !ok || form.Get("RelayState") != "qualification" {
		f.t.Fatal("SAML POST/RelayState missing")
	}
	encoded := form.Get("SAMLResponse")
	if len(encoded) > ((1<<20)*4/3)+8 {
		f.t.Fatal("SAML response exceeds encoded budget")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	f.requireNoError(err)
	return data, requestID
}
func samlMetadataCertificates(f *keycloakFixture, data []byte) []*x509.Certificate {
	f.requireNoError(applications.CheckXMLBounds(data))
	var metadata struct {
		IDP struct {
			Keys []struct {
				Use          string   `xml:"use,attr"`
				Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
			} `xml:"KeyDescriptor"`
		} `xml:"IDPSSODescriptor"`
	}
	f.requireNoError(xml.Unmarshal(data, &metadata))
	var result []*x509.Certificate
	for _, key := range metadata.IDP.Keys {
		if key.Use != "signing" && key.Use != "" {
			continue
		}
		for _, encoded := range key.Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
			f.requireNoError(err)
			cert, err := x509.ParseCertificate(der)
			f.requireNoError(err)
			result = append(result, cert)
		}
	}
	if len(result) == 0 {
		f.t.Fatal("metadata contains no trusted signing certificates")
	}
	return result
}

func fixtureVerifyJWT(f *keycloakFixture, token, issuer, audience string) jwt.MapClaims {
	f.t.Helper()
	f.secrets = append(f.secrets, token)
	status, _, data := protocolHTTP(f, f.http, http.MethodGet, f.baseURL+"/realms/managed/protocol/openid-connect/certs", nil)
	fixtureEqual(f.t, "JWKS status", status, http.StatusOK)
	var jwks struct {
		Keys []struct{ Kid, Kty, Use, Alg, N, E string }
	}
	f.requireNoError(json.Unmarshal(data, &jwks))
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing token key ID")
		}
		for _, key := range jwks.Keys {
			if key.Kid == kid && key.Kty == "RSA" && key.Use == "sig" && key.Alg == "RS256" {
				n, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return nil, err
				}
				e, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil || len(e) > 4 {
					return nil, fmt.Errorf("invalid RSA exponent")
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
			}
		}
		return nil, fmt.Errorf("unknown signing key")
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	f.requireNoError(err)
	if !parsed.Valid {
		f.t.Fatal("JWT signature/claims invalid (token withheld)")
	}
	return parsed.Claims.(jwt.MapClaims)
}
