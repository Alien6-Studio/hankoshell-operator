package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func TestLeafOwnershipPrimitivesPreserveNativeStateAndExcludeCredentialRoutes(t *testing.T) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount", "HankoRole"} {
		t.Run(kind, func(t *testing.T) {
			attrs := map[string]any{"native.key": "opaque-sentinel"}
			document := map[string]any{"id": "provider-id", "clientId": "client", "protocol": "saml", "redirectUris": []any{"https://sp.example.test/acs"}, "attributes": attrs, "nativeTopLevel": map[string]any{"value": "preserved"}, "secret": "client-secret-sentinel"}
			if kind == "HankoRole" {
				document = map[string]any{"id": "provider-id", "name": "role", "description": "original", "composite": true, "containerId": "realm-id", "attributes": map[string]any{"native.key": []any{"opaque-sentinel"}}, "nativeTopLevel": true}
			}
			initial, _ := json.Marshal(document)
			puts, credentialRoutes := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
					return
				}
				if strings.Contains(r.URL.Path, "client-secret") {
					credentialRoutes++
					w.WriteHeader(403)
					return
				}
				if r.Method == http.MethodPut {
					puts++
					var incoming map[string]any
					if json.NewDecoder(r.Body).Decode(&incoming) != nil {
						t.Error("invalid PUT")
					}
					if _, present := incoming["secret"]; present {
						t.Error("secret round-tripped in PUT")
					}
					if secret, present := document["secret"]; present {
						incoming["secret"] = secret
					}
					document = incoming
					w.WriteHeader(204)
					return
				}
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method %s", r.Method)
					w.WriteHeader(403)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/clients"):
					_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "provider-id", "clientId": "client"}})
				case strings.HasSuffix(r.URL.Path, "/protocol-mappers/models"):
					_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "mapper", "name": "native", "config": map[string]string{"private.config": "mapper-secret-sentinel"}}})
				default:
					_ = json.NewEncoder(w).Encode(document)
				}
			}))
			defer server.Close()
			kc := New(server.URL, "writer", "writer-secret")
			kc.httpClient = server.Client()
			receipt, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: kind, TargetUID: "target-uid", CandidateHash: "sha256:" + strings.Repeat("c", 64)}).Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "HankoRole" {
				before, err := kc.ReadRoleOwnership(context.Background(), "realm", "role")
				if err != nil {
					t.Fatal(err)
				}
				if err = kc.MarkRoleAdoption(context.Background(), "realm", before, "target-uid", receipt); err != nil {
					t.Fatal(err)
				}
				after, err := kc.ReadRoleOwnership(context.Background(), "realm", "role")
				if err != nil || !before.SameSemantics(after) {
					t.Fatal("role semantics changed", err)
				}
			} else {
				before, err := kc.ReadClientOwnership(context.Background(), "realm", "client")
				if err != nil {
					t.Fatal(err)
				}
				if kind == "HankoApplication" {
					err = kc.MarkApplicationAdoption(context.Background(), "realm", before, "target-uid", receipt)
				} else {
					err = kc.MarkServiceAccountAdoption(context.Background(), "realm", before, "target-uid", receipt)
				}
				if err != nil {
					t.Fatal(err)
				}
				after, err := kc.ReadClientOwnership(context.Background(), "realm", "client")
				if err != nil || !before.SameSemantics(after) {
					t.Fatal("client semantics changed", err)
				}
			}
			if puts != 1 || credentialRoutes != 0 {
				t.Fatalf("puts=%d credential routes=%d", puts, credentialRoutes)
			}
			if kind != "HankoRole" && document["secret"] != "client-secret-sentinel" {
				t.Fatal("stored credential changed")
			}
			delete(document, "secret")
			var original map[string]any
			_ = json.Unmarshal(initial, &original)
			delete(original, "secret")
			if !reflect.DeepEqual(withoutAcquisition(original), withoutAcquisition(document)) {
				t.Fatal("owner-only PUT changed native provider fields")
			}
		})
	}
}

func TestServiceAccountOwnerIsKindDiscriminated(t *testing.T) {
	base := map[string]string{adoption.ClientOwnerKindKey: "HankoServiceAccount", adoption.ClientOwnerUIDKey: "uid"}
	if !ServiceAccountOwned(&Application{Attributes: base}, "uid") {
		t.Fatal("exact envelope refused")
	}
	for _, attrs := range []map[string]string{nil, {adoption.ApplicationOwnerKey: "uid"}, {adoption.ClientOwnerKindKey: "HankoApplication", adoption.ClientOwnerUIDKey: "uid"}, {adoption.ClientOwnerKindKey: "HankoServiceAccount", adoption.ClientOwnerUIDKey: "foreign"}, {adoption.ClientOwnerKindKey: "HankoServiceAccount", adoption.ClientOwnerUIDKey: "uid", adoption.ApplicationOwnerKey: ""}} {
		if ServiceAccountOwned(&Application{Attributes: attrs}, "uid") {
			t.Fatal("ambiguous or foreign envelope accepted")
		}
	}
}
