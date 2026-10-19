package applications

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOIDCDiscoveryRefusesAmbiguousIdentity(t *testing.T) {
	p := fuzzIssuer + "/protocol/openid-connect"
	raw, _ := json.Marshal(map[string]string{"issuer": fuzzIssuer, "authorization_endpoint": p + "/auth", "token_endpoint": p + "/token", "jwks_uri": p + "/certs", "userinfo_endpoint": p + "/userinfo"})
	for _, value := range []string{strings.Replace(string(raw), `"issuer":`, `"issuer":"foreign", "issuer":`, 1), strings.Replace(string(raw), `"jwks_uri":`, `"jwks_uri":"foreign", "jwks_uri":`, 1), string(raw) + `{}`, strings.Repeat(" ", maxProtocolDocument+1)} {
		if _, err := parseOIDCMetadata([]byte(value), fuzzIssuer); err == nil {
			t.Fatal("ambiguous OIDC evidence accepted")
		}
	}
}
