package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplicationUpdatePreservesQualifiedDelegation(t *testing.T) {
	for _, scenario := range []string{"audience", "actor", "audience-and-actor", "malformed-audience", "foreign-audience", "foreign-actor"} {
		t.Run(scenario, func(t *testing.T) {
			attrs := map[string]string{adoption.ApplicationOwnerKey: "api-uid", authorizationOwnerAttribute: "ordinary-sibling-journal"}
			document := boundedTestDocument()
			raw, _ := json.Marshal(document)
			marker := boundedDelegationActorMarker{Version: 1, Actor: document.Audience, Owners: map[string]string{"other-api": "other-server"}}
			if scenario == "foreign-audience" {
				raw = []byte(strings.Replace(string(raw), `"api-uid"`, `"foreign"`, 1))
			}
			if scenario == "malformed-audience" {
				raw = []byte(`{"opaque":"private-sentinel"}`)
			}
			if scenario == "foreign-actor" {
				marker.Actor.Value = "foreign"
			}
			if scenario != "actor" && scenario != "foreign-actor" {
				attrs[BoundedDelegationAttribute] = string(raw)
			}
			if scenario == "actor" || scenario == "audience-and-actor" || scenario == "foreign-actor" {
				encoded, _ := json.Marshal(marker)
				attrs[BoundedDelegationActorAttribute] = string(encoded)
				attrs["standard.token.exchange.enabled"] = "true"
			}
			current := Application{ID: "client-uuid", ClientID: "api", Name: "before", Protocol: "openid-connect", Attributes: attrs, Enabled: true, ServiceAccountsEnabled: true}
			writes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "expires_in": 300})
					return
				}
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(current)
					return
				}
				writes++
				var updated Application
				if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				for _, key := range []string{BoundedDelegationAttribute, BoundedDelegationActorAttribute, "standard.token.exchange.enabled", authorizationOwnerAttribute} {
					if attrs[key] != "" && updated.Attributes[key] != attrs[key] {
						t.Error("application update discarded sibling field", key)
					}
				}
				if updated.Name != "after" {
					t.Error("application update did not apply desired change")
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			kc := New(server.URL, "writer", "credential")
			kc.httpClient = server.Client()
			want := current
			want.Name = "after"
			want.Attributes = map[string]string{adoption.ApplicationOwnerKey: "api-uid"}
			original := maps.Clone(attrs)
			err := kc.UpdateApplication(context.Background(), "realm", want, adoption.ApplicationOwnerKey, "api-uid")
			invalid := strings.HasPrefix(scenario, "foreign") || strings.HasPrefix(scenario, "malformed")
			if invalid {
				if !errors.Is(err, ErrApplicationPrecondition) || writes != 0 {
					t.Fatal("unqualified sibling document authorized mutation", err, writes)
				}
			} else if err != nil || writes != 1 {
				t.Fatal("owned application update refused", err, writes)
			}
			if !maps.Equal(attrs, original) {
				t.Fatal("caller attributes mutated")
			}
		})
	}
}

func TestApplicationUpdateWaitsForSiblingDelegationTransaction(t *testing.T) {
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "expires_in": 300})
	}))
	defer server.Close()
	kc := New(server.URL, "writer", "credential")
	kc.httpClient = server.Client()
	release, err := kc.beginBoundedDelegation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := kc.WithMutationGuard(nil).UpdateApplication(ctx, "realm", Application{}, adoption.ApplicationOwnerKey, "uid"); !errors.Is(err, context.DeadlineExceeded) || reads.Load() != 0 {
		t.Fatal("application bypassed shared sibling transaction", err, reads.Load())
	}
}
