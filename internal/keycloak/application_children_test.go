package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestApplicationChildrenPinOnePhysicalClientAndFailClosed(t *testing.T) {
	for _, denied := range []string{"", "/roles", "/scope-mappings/realm", "/protocol-mappers/models"} {
		t.Run("denied="+denied, func(t *testing.T) {
			lookups, fullReads, children := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet {
					t.Error("observation attempted a mutation")
				}
				switch r.URL.Path {
				case "/admin/realms/realm/clients":
					lookups++
					id := "original"
					if lookups > 1 {
						id = "replacement"
					}
					_ = json.NewEncoder(w).Encode([]Application{{ID: id, ClientID: "portal"}})
				case "/admin/realms/realm/clients/original":
					fullReads++
					_ = json.NewEncoder(w).Encode(Application{ID: "original", ClientID: "portal", Protocol: "openid-connect"})
				default:
					children++
					if denied != "" && r.URL.Path == "/admin/realms/realm/clients/original"+denied {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					switch r.URL.Path {
					case "/admin/realms/realm/clients/original/roles":
						_ = json.NewEncoder(w).Encode([]ClientRole{{Name: "use"}})
					case "/admin/realms/realm/clients/original/scope-mappings/realm":
						_ = json.NewEncoder(w).Encode([]RealmRole{{Name: "reader"}})
					case "/admin/realms/realm/clients/original/protocol-mappers/models":
						_ = json.NewEncoder(w).Encode([]ProtocolMapper{{Name: "claim"}})
					default:
						t.Error("child lookup switched to a replacement client")
						w.WriteHeader(http.StatusNotFound)
					}
				}
			}))
			defer server.Close()
			c := New(server.URL, "operator", "fixture-credential", WithInsecureHTTP())
			app, err := c.GetApplication(context.Background(), "realm", "portal")
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.ReadApplicationChildren(context.Background(), "realm", *app, true)
			if lookups != 1 || fullReads != 1 {
				t.Fatal("child observation repeated identity resolution or omitted the full read")
			}
			if denied != "" {
				if !IsNotFound(err) || !reflect.DeepEqual(result, ApplicationChildren{}) {
					t.Fatal("missing physical client returned partial or successful observation")
				}
			} else if err != nil || children != 3 || len(result.Roles) != 1 || len(result.Scopes) != 1 || len(result.Mappers) != 1 {
				t.Fatal("incomplete client children")
			}
		})
	}
}

func TestApplicationChildrenRespectProtocolAndScopeBoundary(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
			return
		}
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/admin/realms/realm/clients/saml-id/roles" {
			t.Error("SAML observation read OIDC children or credentials")
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	c := New(server.URL, "operator", "fixture-credential", WithInsecureHTTP())
	for _, app := range []Application{{}, {ID: "saml-id"}, {ClientID: "portal"}} {
		if _, err := c.ReadApplicationChildren(context.Background(), "realm", app, false); !errors.Is(err, ErrApplicationPrecondition) {
			t.Fatal("unresolved identity reached child endpoints")
		}
	}
	if _, err := c.ReadApplicationChildren(context.Background(), "realm", Application{ID: "saml-id", ClientID: "portal", Protocol: "saml"}, false); err != nil || requests != 1 {
		t.Fatal("SAML child observation failed or exceeded its read boundary")
	}
}
