package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFleetPermissionEvidenceComesFromProviderTLS(t *testing.T) {
	for _, boundary := range []string{"allowed", "missing-role", "other-realm", "wrong-client", "wrong-issuer", "expired", "future", "old", "opaque", "token-denied", "realm-denied", "wrong-realm-body", "version-denied"} {
		t.Run(boundary, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch r.URL.Path {
				case "/realms/master/protocol/openid-connect/token":
					if r.Method != http.MethodPost {
						t.Error("unexpected authentication method")
					}
					if boundary == "token-denied" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					roles := []string{"manage-realm", "manage-clients", "manage-events", "manage-identity-providers"}
					if boundary == "missing-role" {
						roles = []string{"view-realm"}
					}
					claims := map[string]any{"iss": "https://" + r.Host + "/realms/master", "azp": "writer", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "resource_access": map[string]any{"target-realm": map[string]any{"roles": roles}}}
					switch boundary {
					case "other-realm":
						claims["resource_access"] = map[string]any{"other-realm": map[string]any{"roles": roles}}
					case "wrong-client":
						claims["azp"] = "other"
					case "wrong-issuer":
						claims["iss"] = "https://other.invalid/realms/master"
					case "expired":
						claims["exp"] = time.Now().Add(-time.Minute).Unix()
					case "future":
						claims["iat"] = time.Now().Add(time.Minute).Unix()
					case "old":
						claims["iat"] = time.Now().Add(-time.Hour).Unix()
					}
					raw, _ := json.Marshal(claims)
					token := "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".synthetic"
					if boundary == "opaque" {
						token = "opaque"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 300})
				case "/admin/serverinfo":
					if boundary == "version-denied" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_, _ = w.Write([]byte(`{"systemInfo":{"version":"26.8.1"}}`))
				case "/admin/realms/target":
					if boundary == "realm-denied" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					realm := "target"
					if boundary == "wrong-realm-body" {
						realm = "other"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"id": "realm-id", "realm": realm})
				default:
					t.Error("permission observation tried an unqualified endpoint")
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer server.Close()
			c, err := NewWithTLS(server.URL, "writer", "synthetic", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.FleetPermissions(context.Background(), "target")
			if boundary == "allowed" || boundary == "missing-role" || boundary == "other-realm" {
				if err != nil || p.Version != "26.8.1" || p.ManageClients != (boundary == "allowed") {
					t.Fatal("native effective permissions were not scoped")
				}
			} else if err == nil || strings.Contains(err.Error(), server.URL) {
				t.Fatal("invalid evidence accepted or remote data exposed")
			}
			if calls > 3 {
				t.Fatal("permission check expanded beyond bounded read-only preflight")
			}
		})
	}
	for _, c := range []*Client{nil, New("http://provider.invalid", "writer", "synthetic", WithInsecureHTTP())} {
		if _, err := c.FleetPermissions(context.Background(), "target"); err == nil {
			t.Fatal("untrusted provider authority accepted")
		}
	}
	c := New("https://provider.invalid", "writer", "synthetic")
	c.RestrictToInventory()
	if _, err := c.FleetPermissions(context.Background(), "target"); err == nil {
		t.Fatal("read-only client authorized Fleet writes")
	}
}
