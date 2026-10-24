package workloadtrust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const publicTestKeys = `{"keys":[{"kty":"RSA","kid":"public-key","n":"AQAB","e":"AQAB"}]}`

func TestPublicDiscoveryIsBoundedUnauthenticatedAndMatchesCurrentCluster(t *testing.T) {
	for _, name := range []string{"qualified", "redirect", "oversized", "malformed", "duplicate", "issuer mismatch", "keys mismatch", "unexpected authority", "26.7 override", "26.8 override", "legacy override", "future override", "future minor override", "unsupported major override"} {
		t.Run(name, func(t *testing.T) {
			var origin string
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("public discovery carried credential")
				}
				if strings.HasSuffix(r.URL.Path, "/jwks") {
					fmt.Fprint(w, publicTestKeys)
					return
				}
				switch name {
				case "redirect":
					http.Redirect(w, r, origin+"/redirect", http.StatusFound)
					return
				case "oversized":
					fmt.Fprint(w, strings.Repeat(" ", PublicDocumentLimit+1))
					return
				case "malformed":
					fmt.Fprint(w, "{")
					return
				case "duplicate":
					fmt.Fprint(w, `{"issuer":"a","issuer":"b"}`)
					return
				}
				issuer, jwks := origin, origin+"/jwks"
				if name == "issuer mismatch" {
					issuer = "https://foreign.example.test"
				}
				if name == "unexpected authority" {
					jwks = "https://foreign.example.test/jwks"
				}
				_ = json.NewEncoder(w).Encode(DiscoveryDocument{issuer, jwks})
			}))
			defer s.Close()
			origin = s.URL
			h, _ := PublicKeysHash([]byte(publicTestKeys))
			current := DiscoveryEvidence{Issuer: origin, JWKSURL: origin + "/jwks", KeysHash: h}
			if name == "keys mismatch" {
				current.KeysHash = Digest("different", 1)
			}
			i := Intent{Issuer: origin}
			if strings.Contains(name, "override") {
				i.DiscoveryURL = origin + "/override"
				i.QualifiedVersion = "26.7.5"
				switch name {
				case "26.8 override":
					i.QualifiedVersion = "26.8.1"
				case "legacy override":
					i.QualifiedVersion = "26.8.0"
				case "future override":
					i.QualifiedVersion = "26.8.2"
				case "future minor override":
					i.QualifiedVersion = "26.10.0"
				case "unsupported major override":
					i.QualifiedVersion = "27.0.0"
				}
			}
			_, err := ValidateDiscovery(context.Background(), s.Client(), i, current)
			want := name == "qualified" || name == "26.8 override" || name == "legacy override" || name == "future override" || name == "future minor override"
			if (err == nil) != want {
				t.Fatalf("qualified=%t, expected %t", err == nil, want)
			}
		})
	}
}

func TestPublicKeysExcludePrivateAndMalformedMaterial(t *testing.T) {
	for _, bad := range []string{`{"keys":[]}`, `{"keys":[{"kty":"oct","kid":"k","k":"secret"}]}`, strings.Replace(publicTestKeys, `"n":"AQAB"`, `"n":"AQAB","d":"private"`, 1), strings.Replace(publicTestKeys, `"kid":"public-key"`, `"kid":"public-key","kid":"duplicate"`, 1), publicTestKeys + " {}"} {
		if _, err := PublicKeysHash([]byte(bad)); err == nil {
			t.Fatal("unqualified keyset accepted")
		}
	}
}
