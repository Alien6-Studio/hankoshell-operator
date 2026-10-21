package applications

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const fuzzIssuer = "https://provider.example.test/realms/managed"

func FuzzOIDCDiscovery(f *testing.F) {
	p := fuzzIssuer + "/protocol/openid-connect"
	seed, _ := json.Marshal(map[string]string{"issuer": fuzzIssuer, "authorization_endpoint": p + "/auth", "token_endpoint": p + "/token", "jwks_uri": p + "/certs", "userinfo_endpoint": p + "/userinfo"})
	for _, data := range [][]byte{seed, []byte(`{}`), []byte(`{"issuer":"a","issuer":"b"}`), []byte(strings.Repeat(" ", maxProtocolDocument+1))} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		metadata, err := parseOIDCMetadata(data, fuzzIssuer)
		if err == nil && metadata != expectedOIDCMetadata(fuzzIssuer) {
			t.Fatal("accepted foreign discovery endpoints")
		}
		if err == nil && len(data) > maxProtocolDocument {
			t.Fatal("discovery byte budget bypassed")
		}
		if err == nil && func() bool { _, e := parseOIDCMetadata(data, fuzzIssuer+"/foreign"); return e == nil }() {
			t.Fatal("issuer binding bypassed")
		}
	})
}

func FuzzSAMLMetadata(f *testing.F) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		f.Fatal(err)
	}
	seed := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + fuzzIssuer + `"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="` + POSTBinding + `" Location="` + fuzzIssuer + `/protocol/saml"/></IDPSSODescriptor></EntityDescriptor>`
	if _, err := ParseSAMLMetadata([]byte(seed), fuzzIssuer); err != nil {
		f.Fatal(err)
	}
	for _, data := range []string{seed, `<a/>`, `<!DOCTYPE x [<!ENTITY x SYSTEM "file:///synthetic">]><x>&x;</x>`, `<a ID="x"><b ID="x"/></a>`, strings.Repeat("<a>", 33) + strings.Repeat("</a>", 33), strings.Repeat(" ", maxProtocolDocument+1)} {
		f.Add([]byte(data))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		metadata, err := ParseSAMLMetadata(data, fuzzIssuer)
		if err != nil {
			return
		}
		if metadata.Issuer != fuzzIssuer || metadata.SSO != fuzzIssuer+"/protocol/saml" || CheckXMLBounds(data) != nil {
			t.Fatal("accepted unbound SAML metadata")
		}
		if _, err := ParseSAMLMetadata(data, fuzzIssuer+"/foreign"); err == nil {
			t.Fatal("SAML issuer binding bypassed")
		}
		if CheckXMLBounds(append(append([]byte{}, data...), []byte("<foreign/>")...)) == nil {
			t.Fatal("accepted multiple XML roots")
		}
	})
}

func FuzzSAMLACS(f *testing.F) {
	prefix := "https://portal.test/"
	for _, value := range []string{prefix + "acs", prefix + strings.Repeat("a", 255-len(prefix)), prefix + strings.Repeat("é", 255-len(prefix)), prefix + strings.Repeat("a", 256-len(prefix)), "https://user:password@portal.test/acs", prefix + "%0a", prefix + "%00", prefix + "%09", prefix + "%7f", prefix + "%ff", prefix + "%2a", prefix + "*", string([]byte{0xff}), strings.Repeat("a", 1<<20)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !ValidACS(value) {
			return
		}
		u, err := url.Parse(value)
		if err != nil || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !utf8.ValidString(u.Path) || strings.IndexFunc(u.Path, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || strings.ContainsAny(u.Path, "\\*") {
			t.Fatal("accepted unbounded or non-exact SAML ACS")
		}
	})
}
