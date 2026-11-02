package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOAuthScopeResourceVerifiesNativeClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier{configuration{Issuer: "https://fixture/realms/software", Audience: "api", OAuthScopes: true,
		Resources: map[string]string{"/read": "artifacts:read", "/publish": "artifacts:publish"}}, map[string]*rsa.PublicKey{"current": &key.PublicKey}}
	for _, tc := range []struct {
		name, path, scope, audience, method string
		status                              int
	}{
		{"read", "/read", "basic artifacts:read", "api", http.MethodGet, 200},
		{"publish", "/publish", "basic artifacts:read", "api", http.MethodGet, 403},
		{"prefix", "/read", "artifacts:read-all", "api", http.MethodGet, 403},
		{"missing", "/read", "", "api", http.MethodGet, 403},
		{"unknown", "/unknown", "artifacts:read", "api", http.MethodGet, 403},
		{"method", "/read", "artifacts:read", "api", http.MethodPost, 403},
		{"audience", "/read", "artifacts:read", "foreign", http.MethodGet, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": v.config.Issuer, "aud": tc.audience,
				"exp": time.Now().Add(time.Minute).Unix(), "scope": tc.scope})
			token.Header["kid"] = "current"
			encoded, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", "Bearer "+encoded)
			response := httptest.NewRecorder()
			v.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("scope decision=%d want=%d", response.Code, tc.status)
			}
		})
	}
}
