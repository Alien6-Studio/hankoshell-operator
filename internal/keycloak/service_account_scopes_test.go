package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

type oauthScopeFixture struct {
	app                 Application
	available, defaults []oauthClientScope
	optional            []oauthClientScope
	writes, requests    int
	dropWrite           bool
}

func newOAuthScopeFixture(t *testing.T) (*oauthScopeFixture, *Client) {
	t.Helper()
	f := &oauthScopeFixture{app: Application{ID: "client-uuid", ClientID: "reader", Protocol: openIDConnectProtocol, ClientAuthenticatorType: "client-secret", Enabled: true, ServiceAccountsEnabled: true, Attributes: map[string]string{adoption.ClientOwnerKindKey: "HankoServiceAccount", adoption.ClientOwnerUIDKey: "owner"}}, available: []oauthClientScope{{"basic-id", "basic", openIDConnectProtocol}, {"reader-id", "registry:oci:artifacts:read", openIDConnectProtocol}, {"writer-id", "registry:oci:artifacts:publish", openIDConnectProtocol}}}
	f.defaults = slices.Clone(f.available[:1])
	f.optional = slices.Clone(f.available[2:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		base := "/admin/realms/example"
		path := strings.TrimPrefix(r.URL.Path, base)
		switch {
		case r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "expires_in": 300})
		case path == "/clients" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]Application{f.app})
		case path == "/clients/client-uuid" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(f.app)
		case path == "/client-scopes" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(f.available)
		case strings.HasPrefix(path, "/client-scopes/") && r.Method == http.MethodGet:
			for _, scope := range f.available {
				if strings.TrimPrefix(path, "/client-scopes/") == scope.ID {
					_ = json.NewEncoder(w).Encode(scope)
					return
				}
			}
			http.NotFound(w, r)
		case strings.HasPrefix(path, "/clients/client-uuid/default-client-scopes"), strings.HasPrefix(path, "/clients/client-uuid/optional-client-scopes"):
			set := &f.defaults
			if strings.Contains(path, "/optional-client-scopes") {
				set = &f.optional
			}
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(*set)
				return
			}
			f.writes++
			id := path[strings.LastIndex(path, "/")+1:]
			if !f.dropWrite {
				switch r.Method {
				case http.MethodDelete:
					*set = slices.DeleteFunc(*set, func(s oauthClientScope) bool { return s.ID == id })
				case http.MethodPut:
					for _, scope := range f.available {
						if scope.ID == id {
							*set = append(*set, scope)
						}
					}
				default:
					t.Errorf("unexpected method %s", r.Method)
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider call %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return f, New(server.URL, "operator", "fixture-secret", WithInsecureHTTP())
}

func TestServiceAccountOAuthScopeAttachments(t *testing.T) {
	f, kc := newOAuthScopeFixture(t)
	ctx := context.Background()
	verify := func(context.Context) error { return nil }
	wanted := []string{"basic", "registry:oci:artifacts:read"}
	if err := kc.ReconcileServiceAccountScopes(ctx, "example", "reader", "owner", nil, nil); err != nil || f.requests != 0 {
		t.Fatal("omitted scopes must not read or mutate the provider")
	}
	if err := kc.ReconcileServiceAccountScopes(ctx, "example", "reader", "owner", wanted, verify); err != nil {
		t.Fatal(err)
	}
	if !sameOAuthScopes(f.defaults, f.available[:2]) || len(f.optional) != 0 || f.writes != 2 {
		t.Fatal("declared default grants or optional-scope revocation not applied")
	}
	before := f.writes
	if err := kc.ReconcileServiceAccountScopes(ctx, "example", "reader", "owner", wanted, verify); err != nil || f.writes != before {
		t.Fatal("unchanged declarations must not mutate the provider", err)
	}
	if err := kc.ReconcileServiceAccountScopes(ctx, "example", "reader", "owner", []string{}, verify); err != nil || len(f.defaults) != 0 || len(f.optional) != 0 {
		t.Fatal("explicit empty list did not revoke every attachment", err)
	}
	if len(f.available) != 3 {
		t.Fatal("shared scope definitions changed")
	}
}

func TestServiceAccountOAuthScopeFailures(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "wrong protocol", "foreign owner", "unconfirmed", "stale authority", "replacement", "invalid definition ID", "invalid attachment ID"} {
		t.Run(name, func(t *testing.T) {
			f, kc := newOAuthScopeFixture(t)
			verify := func(context.Context) error { return nil }
			switch name {
			case "invalid definition ID":
				f.available[1].ID = ".."
			case "invalid attachment ID":
				f.optional[0].ID = "."
			case "missing":
				f.available = f.available[:1]
			case "duplicate":
				f.available = append(f.available, oauthClientScope{"other-id", f.available[1].Name, openIDConnectProtocol})
			case "wrong protocol":
				f.available[1].Protocol = "saml"
			case "foreign owner":
				f.app.Attributes[adoption.ClientOwnerUIDKey] = "another-owner"
			case "unconfirmed":
				f.dropWrite = true
			case "stale authority":
				checks := 0
				verify = func(context.Context) error {
					checks++
					if checks > 1 {
						return errors.New("changed declaration")
					}
					return nil
				}
			case "replacement":
				checks := 0
				verify = func(context.Context) error {
					checks++
					if checks > 1 {
						f.app.Attributes[adoption.ClientOwnerUIDKey] = "replacement-owner"
					}
					return nil
				}
			}
			err := kc.ReconcileServiceAccountScopes(context.Background(), "example", "reader", "owner", []string{"registry:oci:artifacts:read"}, verify)
			if err == nil || name != "unconfirmed" && f.writes != 0 {
				t.Fatalf("unsafe result: error=%v writes=%d", err, f.writes)
			}
		})
	}
	for _, names := range [][]string{{""}, {"openid profile"}, {"a", "a"}, {"a\""}, {"a\\"}, {"é"}, {"a/b"}, {"eyJexample"}, {strings.Repeat("a", 129)}} {
		if validateOAuthScopeNames(names) == nil {
			t.Fatal("invalid OAuth scope declaration accepted")
		}
	}
}
