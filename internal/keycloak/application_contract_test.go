package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicProtocolDocumentsUseBoundedCredentialFreeGateway(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "" {
			t.Error("public metadata carries admin credential")
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20+1)))
	}))
	defer server.Close()
	c := New(server.URL, "operator", "must-not-be-used", WithInsecureHTTP())
	for _, protocol := range []string{"oidc", "saml"} {
		if _, err := c.ProtocolDocument(context.Background(), "managed", protocol); err == nil {
			t.Fatal("unbounded metadata accepted")
		}
	}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/realms/managed/protocol/saml/descriptor", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer must-not-leave")
	if _, err := c.do(req); err == nil {
		t.Fatal("metadata accepted administrative credentials")
	}
	if requests != 2 {
		t.Fatal("credential-bearing metadata reached network")
	}
}

func TestCanonicalMapperDefaultsAreNarrowAndPreserveInputs(t *testing.T) {
	a := ProtocolMapper{ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{"included.client.audience": "", "included.custom.audience": "portal"}}
	b := ProtocolMapper{ProtocolMapper: a.ProtocolMapper, Config: map[string]string{"userinfo.token.claim": "false", "included.custom.audience": "portal"}}
	left, _ := json.Marshal(CanonicalProtocolMapper(a))
	right, _ := json.Marshal(CanonicalProtocolMapper(b))
	if string(left) != string(right) {
		t.Fatal("qualified audience defaults change identity")
	}
	if _, found := a.Config["included.client.audience"]; !found {
		t.Fatal("canonicalization mutated input")
	}
	b.Config["userinfo.token.claim"] = "true"
	right, _ = json.Marshal(CanonicalProtocolMapper(b))
	if string(left) == string(right) {
		t.Fatal("non-default native mapper state hidden")
	}
	if !mapperOwnerConflict(map[string]string{"hanko.sh/application-owner": "foreign"}, map[string]string{"hanko.sh/application-owner": "ours"}) {
		t.Fatal("foreign mapper UID can be overwritten")
	}
}
