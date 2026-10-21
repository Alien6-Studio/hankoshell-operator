package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestResourceVerifiesSignatureAndExactAuthority(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier{configuration{"https://fixture/realms/software", "api", map[string]string{"/allowed": "one", "/denied": "two"}}, map[string]*rsa.PublicKey{"current": &key.PublicKey}}
	for _, tc := range []struct {
		name, path string
		status     int
		change     func(jwt.MapClaims)
	}{
		{"read", "/allowed?scope=read", 200, nil},
		{"scope", "/allowed?scope=write", 403, nil},
		{"resource", "/denied?scope=read", 403, nil},
		{"unknown", "/unknown?scope=read", 403, nil},
		{"missing-scope", "/allowed", 403, nil},
		{"issuer", "/allowed?scope=read", 401, func(c jwt.MapClaims) { c["iss"] = "https://foreign" }},
		{"audience", "/allowed?scope=read", 401, func(c jwt.MapClaims) { c["aud"] = "other" }},
		{"multiple-audiences", "/allowed?scope=read", 401, func(c jwt.MapClaims) { c["aud"] = []string{"api", "other"} }},
		{"expired", "/allowed?scope=read", 401, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"missing-expiration", "/allowed?scope=read", 401, func(c jwt.MapClaims) { delete(c, "exp") }},
		{"no-permissions", "/allowed?scope=read", 403, func(c jwt.MapClaims) { delete(c, "authorization") }},
		{"malformed-permissions", "/allowed?scope=read", 403, func(c jwt.MapClaims) { c["authorization"] = "untrusted" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": v.config.Issuer, "aud": "api", "exp": time.Now().Add(time.Minute).Unix(),
				"authorization": map[string]any{"permissions": []any{map[string]any{"rsid": "one", "scopes": []string{"read"}}}}}
			if tc.change != nil {
				tc.change(claims)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "current"
			encoded, signErr := token.SignedString(key)
			if signErr != nil {
				t.Fatal(signErr)
			}
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			request.Header.Set("Authorization", "Bearer "+encoded)
			response := httptest.NewRecorder()
			v.ServeHTTP(response, request)
			if response.Code != tc.status || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), encoded) {
				t.Fatalf("decision: %d", response.Code)
			}
		})
	}
	for _, token := range []*jwt.Token{jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": v.config.Issuer, "aud": "api", "exp": time.Now().Add(time.Minute).Unix()}), jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})} {
		token.Header["kid"] = "current"
		var signing any = other
		if token.Method == jwt.SigningMethodHS256 {
			signing = []byte("synthetic-fixture-HMAC")
		}
		encoded, signErr := token.SignedString(signing)
		if signErr != nil {
			t.Fatal(signErr)
		}
		request := httptest.NewRequest(http.MethodGet, "/allowed?scope=read", nil)
		request.Header.Set("Authorization", "Bearer "+encoded)
		response := httptest.NewRecorder()
		v.ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatal("invalid signature or algorithm was accepted")
		}
	}
	for _, header := range []string{"", "Basic synthetic", "Bearer " + strings.Repeat("a", 16385)} {
		request := httptest.NewRequest(http.MethodGet, "/allowed?scope=read", nil)
		request.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		v.ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatal("invalid bearer accepted")
		}
	}
}

func TestJWKSRequiresBoundedNativeSigningKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{"kid": "native", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())}
	good, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	duplicate, _ := json.Marshal(map[string]any{"keys": []any{jwk, jwk}})
	for _, body := range []string{string(good), string(duplicate), `{}`, `invalid`, strings.Repeat("a", 65537)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		keys, loadErr := loadKeys(server.Client(), server.URL)
		server.Close()
		if body == string(good) {
			if loadErr != nil || keys["native"].N.Cmp(key.N) != 0 {
				t.Fatal("native key was not retained")
			}
		} else if loadErr == nil {
			t.Fatal("malformed or duplicate keys accepted")
		}
	}
	if serve("/missing-disposable-fixture/settings.json") == nil {
		t.Fatal("missing configuration accepted")
	}
}
