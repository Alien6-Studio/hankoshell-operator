package keycloak

import (
	"context"
	"encoding/json"
	"errors"
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

func TestAdoptedClientDeletionCannotCascadeAcrossForeignBoundaries(t *testing.T) {
	for _, scenario := range []string{"empty safe client", "authorization enabled", "foreign journal", "foreign mapper", "foreign role", "owned role with unqualified references", "foreign scope", "unknown native"} {
		t.Run(scenario, func(t *testing.T) {
			receipt, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoApplication", TargetUID: "uid", CandidateHash: "sha256:" + strings.Repeat("a", 64)}).Canonical()
			if err != nil {
				t.Fatal(err)
			}
			attrs := map[string]string{adoption.ApplicationOwnerKey: "uid", adoption.ReceiptKey: receipt}
			document := map[string]any{"id": "client-id", "clientId": "client", "name": "client", "protocol": "openid-connect", "attributes": attrs, "authorizationServicesEnabled": scenario == "authorization enabled"}
			if scenario == "foreign journal" {
				attrs[authorizationOwnerAttribute] = "foreign-journal"
			}
			if scenario == "unknown native" {
				attrs["innocent.native"] = "private-sentinel"
			}
			deletes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
					return
				}
				if r.Method == http.MethodDelete {
					deletes++
					w.WriteHeader(204)
					return
				}
				if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "client-secret") {
					t.Error("cleanup made a sensitive/unexpected request")
					w.WriteHeader(403)
					return
				}
				var value any = document
				switch {
				case strings.HasSuffix(r.URL.Path, "/clients"):
					value = []map[string]any{{"id": "client-id", "clientId": "client"}}
				case strings.HasSuffix(r.URL.Path, "/protocol-mappers/models"):
					value = []map[string]any{}
					if scenario == "foreign mapper" {
						value = []map[string]any{{"id": "mapper-id", "name": "foreign", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{"claim.name": "department", "user.attribute": "department"}}}
					}
				case strings.HasSuffix(r.URL.Path, "/roles"), strings.HasSuffix(r.URL.Path, "/scope-mappings/realm"):
					value = []map[string]any{}
					if scenario == "foreign role" && strings.HasSuffix(r.URL.Path, "/roles") || scenario == "foreign scope" && strings.HasSuffix(r.URL.Path, "/scope-mappings/realm") {
						value = []map[string]any{{"id": "foreign-id", "name": "foreign"}}
					}
					if scenario == "owned role with unqualified references" && strings.HasSuffix(r.URL.Path, "/roles") {
						value = []map[string]any{{"id": "owned-id", "name": "owned", "attributes": map[string][]string{adoption.ApplicationOwnerKey: {"uid"}}}}
					}
				}
				_ = json.NewEncoder(w).Encode(value)
			}))
			defer server.Close()
			kc := New(server.URL, "writer", "fixture-secret")
			kc.httpClient = server.Client()
			err = kc.DeleteApplicationIfOwned(context.Background(), "realm", "client-id", "client", adoption.ApplicationOwnerKey, "uid")
			if scenario == "empty safe client" {
				if err != nil || deletes != 1 {
					t.Fatal("safe owned node cleanup failed", err)
				}
			} else if !errors.Is(err, ErrAdoptionCleanupConflict) || deletes != 0 {
				t.Fatal("foreign boundary authorized cascading parent deletion", err)
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

func TestNativePreservationSchemaRemainsClosed(t *testing.T) {
	for _, attribute := range []struct{ key, value string }{{"locale", "de"}, {"locale", "private-sentinel"}, {"innocent.native", "private-sentinel"}, {"saml.signing.private.key", "private-sentinel"}, {"backchannel.logout.revoke.offline.tokens", "true"}} {
		if QualifiedClientAttribute(attribute.key, attribute.value) {
			t.Fatalf("unqualified native field accepted: %s", attribute.key)
		}
	}
	for _, value := range []string{"en", "fr"} {
		if !QualifiedClientAttribute("locale", value) || !QualifiedRoleAttributes(map[string][]string{"locale": {value}}) {
			t.Fatal("qualified locale refused")
		}
	}
	mapper := ProtocolMapper{ID: "mapper", Name: "department", Protocol: "openid-connect", ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{"claim.name": "department", "user.attribute": "department", "jsonType.label": "String", "access.token.claim": "true", "introspection.token.claim": "true"}}
	if !QualifiedAdoptionMapper(mapper) {
		t.Fatal("qualified public mapper refused")
	}
	mapper.Config["innocent.native"] = "private-sentinel"
	if QualifiedAdoptionMapper(mapper) {
		t.Fatal("opaque mapper configuration accepted")
	}
}

func TestAdoptedManageCannotIntroduceUnqualifiedNativeState(t *testing.T) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount", "HankoRole"} {
		t.Run(kind, func(t *testing.T) {
			proof, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: kind, TargetUID: "uid", CandidateHash: "sha256:" + strings.Repeat("a", 64)}).Canonical()
			if err != nil {
				t.Fatal(err)
			}
			attrs := map[string]any{adoption.ReceiptKey: proof}
			attrs[adoption.ApplicationOwnerKey] = "uid"
			if kind == "HankoServiceAccount" {
				delete(attrs, adoption.ApplicationOwnerKey)
				attrs[adoption.ClientOwnerKindKey], attrs[adoption.ClientOwnerUIDKey] = kind, "uid"
			}
			document := map[string]any{"id": "provider-id", "clientId": "client", "protocol": "openid-connect", "attributes": attrs}
			if kind == "HankoRole" {
				document = map[string]any{"id": "provider-id", "name": "role", "attributes": map[string][]string{adoption.RoleOwnerKey: {"uid"}, adoption.ReceiptKey: {proof}}}
			}
			writes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					_, _ = w.Write([]byte(`{"access_token":"fixture","expires_in":300}`))
					return
				}
				if r.Method != http.MethodGet {
					writes++
					w.WriteHeader(403)
					return
				}
				var value any = document
				if strings.HasSuffix(r.URL.Path, "/clients") {
					value = []map[string]any{{"id": "provider-id", "clientId": "client"}}
				}
				if strings.HasSuffix(r.URL.Path, "/protocol-mappers/models") {
					value = []any{}
				}
				_ = json.NewEncoder(w).Encode(value)
			}))
			defer server.Close()
			kc := New(server.URL, "writer", "credential")
			kc.httpClient = server.Client()
			switch kind {
			case "HankoApplication":
				err = kc.UpdateApplication(context.Background(), "realm", Application{ID: "provider-id", ClientID: "client", Protocol: "openid-connect", Attributes: map[string]string{"unqualified.native": "private-sentinel"}}, adoption.ApplicationOwnerKey, "uid")
			case "HankoServiceAccount":
				err = kc.SyncServiceAccountAttributesIfOwned(context.Background(), "realm", "client", "uid", map[string]string{"unqualified.native": "private-sentinel"})
			case "HankoRole":
				err = kc.SyncRealmRoleIfOwned(context.Background(), "realm", RealmRole{Name: "role", Attributes: map[string][]string{"unqualified.native": {"private-sentinel"}}}, adoption.RoleOwnerKey, "uid")
			}
			if !errors.Is(err, ErrAdoptionPrecondition) || writes != 0 {
				t.Fatal("Manage introduced unsupported state before its preservation qualification", err)
			}
		})
	}
}
