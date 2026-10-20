package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func TestClientOwnershipReadbackIgnoresOnlyNativeSetOrdering(t *testing.T) {
	makeSnapshot := func() *ClientOwnershipSnapshot {
		doc := map[string]any{"defaultClientScopes": []any{"profile", "email"}, "optionalClientScopes": []any{"address", "offline_access"}, "protocolMappers": []any{map[string]any{"id": "second", "name": "b"}, map[string]any{"id": "first", "name": "a"}}}
		return &ClientOwnershipSnapshot{document: doc, mappers: []map[string]any{{"id": "first", "name": "a"}, {"id": "second", "name": "b"}}}
	}
	a, b := makeSnapshot(), makeSnapshot()
	for _, key := range []string{"defaultClientScopes", "optionalClientScopes", "protocolMappers"} {
		values := b.document[key].([]any)
		values[0], values[1] = values[1], values[0]
	}
	b.mappers[0], b.mappers[1] = b.mappers[1], b.mappers[0]
	if !a.SameSemantics(b) {
		t.Fatal("provider set reordering broke preservation")
	}
	if a.document["defaultClientScopes"].([]any)[0] != "profile" {
		t.Fatal("comparison mutated original snapshot")
	}
	for _, change := range []func(*ClientOwnershipSnapshot){
		func(s *ClientOwnershipSnapshot) { s.document["defaultClientScopes"] = []any{"profile"} },
		func(s *ClientOwnershipSnapshot) { s.document["optionalClientScopes"] = []any{"address", "address"} },
		func(s *ClientOwnershipSnapshot) { s.document["frontchannelLogout"] = false },
		func(s *ClientOwnershipSnapshot) {
			s.document["protocolMappers"].([]any)[0].(map[string]any)["id"] = "replacement"
		},
		func(s *ClientOwnershipSnapshot) { s.mappers[0]["name"] = "changed" },
	} {
		next := makeSnapshot()
		change(next)
		if a.SameSemantics(next) {
			t.Fatal("native semantic change was hidden by ordering normalization")
		}
	}
}

func TestOIDCClientScopePreservationRemainsClosed(t *testing.T) {
	for _, scopes := range []any{[]any{"profile", "email"}, []any{"../invalid"}, []any{"eyJtoken"}, []any{"profile", "profile"}, []any{true}, "profile"} {
		doc := map[string]any{"protocol": "openid-connect", "defaultClientScopes": scopes, "frontchannelLogout": false}
		s := &ClientOwnershipSnapshot{Application: Application{Protocol: "openid-connect"}, document: doc}
		want := reflect.DeepEqual(scopes, []any{"profile", "email"})
		if s.PreservationQualified() != want {
			t.Fatal("scope qualification admitted unknown values or refused bounded OIDC references")
		}
	}
	oversize := make([]any, 65)
	for i := range oversize {
		oversize[i] = "scope-" + strconv.Itoa(i)
	}
	if !qualifiedClientScopeCollection("defaultClientScopes", oversize[:64]) || qualifiedClientScopeCollection("defaultClientScopes", oversize) || qualifiedClientScopeCollection("unreviewed", []any{}) {
		t.Fatal("scope qualification lost collection or field bound")
	}
}

func TestLegacyClientOwnerAndManageWritesPreserveRemovedServiceAccountScope(t *testing.T) {
	document := map[string]any{"id": "native-uuid", "clientId": "legacy", "name": "legacy", "protocol": "openid-connect", "enabled": true, "serviceAccountsEnabled": true, "defaultClientScopes": []any{"profile"}, "optionalClientScopes": []any{"offline_access"}, "frontchannelLogout": false, "secret": "stored-credential-sentinel", "access": map[string]bool{"configure": true}, "attributes": map[string]any{}}
	puts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = w.Write([]byte(`{"access_token":"fixture-access","expires_in":300}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/clients"):
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "native-uuid", "clientId": "legacy"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/clients/native-uuid"):
			_ = json.NewEncoder(w).Encode(document)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/clients/native-uuid"):
			var next map[string]any
			if json.NewDecoder(r.Body).Decode(&next) != nil {
				t.Error("invalid client PUT")
			}
			for _, field := range []string{"secret", "access", "serviceAccountsEnabled"} {
				if _, resent := next[field]; resent {
					t.Errorf("client PUT resent %s", field)
				}
			}
			next["serviceAccountsEnabled"] = true
			next["secret"] = document["secret"]
			document = next
			puts++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected provider route")
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)
	kc := New(server.URL, "writer", "fixture-credential")
	kc.httpClient = server.Client()
	ctx := context.Background()
	app, err := kc.GetApplication(ctx, "managed", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if err := kc.MarkApplicationOwner(ctx, "managed", *app, adoption.ApplicationOwnerKey, "owner-uid"); err != nil {
		t.Fatal(err)
	}
	app.Attributes[adoption.ApplicationOwnerKey] = "owner-uid"
	if err := kc.UpdateApplication(ctx, "managed", *app, adoption.ApplicationOwnerKey, "owner-uid"); err != nil {
		t.Fatal(err)
	}
	if puts != 2 || document["secret"] != "stored-credential-sentinel" || document["frontchannelLogout"] != false || !reflect.DeepEqual(document["defaultClientScopes"], []any{"profile"}) || !reflect.DeepEqual(document["optionalClientScopes"], []any{"offline_access"}) {
		t.Fatal("legacy migration changed native configuration or credentials")
	}
}
