package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

type realmIdentityProviderServer struct {
	providers       []keycloak.IdentityProvider
	mappers         map[string][]keycloak.IdentityProviderMapper
	creates         int
	updates         int
	mapperCreates   int
	mapperUpdates   int
	providerDeletes []string
}

func newRealmIdentityProviderServer(t *testing.T) (*realmIdentityProviderServer, *httptest.Server) {
	t.Helper()
	state := &realmIdentityProviderServer{mappers: map[string][]keycloak.IdentityProviderMapper{}}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const collection = "/admin/realms/alien6/identity-provider/instances"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
		case r.Method == http.MethodGet && r.URL.Path == collection:
			_ = json.NewEncoder(w).Encode(state.providers)
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var provider keycloak.IdentityProvider
			if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
				t.Fatalf("decode provider: %v", err)
			}
			state.providers = append(state.providers, provider)
			state.creates++
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/mappers") && r.Method == http.MethodGet:
			alias := pathPart(t, r.URL.Path, 5)
			_ = json.NewEncoder(w).Encode(state.mappers[alias])
		case strings.HasSuffix(r.URL.Path, "/mappers") && r.Method == http.MethodPost:
			alias := pathPart(t, r.URL.Path, 5)
			var mapper keycloak.IdentityProviderMapper
			if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
				t.Fatalf("decode mapper: %v", err)
			}
			state.mapperCreates++
			mapper.ID = fmt.Sprintf("mapper-%d", state.mapperCreates)
			state.mappers[alias] = append(state.mappers[alias], mapper)
			w.Header().Set("Location", server.URL+r.URL.Path+"/"+mapper.ID)
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/mappers/") && r.Method == http.MethodPut:
			alias := pathPart(t, r.URL.Path, 5)
			id := pathPart(t, r.URL.Path, 7)
			var mapper keycloak.IdentityProviderMapper
			if err := json.NewDecoder(r.Body).Decode(&mapper); err != nil {
				t.Fatalf("decode mapper update: %v", err)
			}
			for i := range state.mappers[alias] {
				if state.mappers[alias][i].ID == id {
					mapper.ID = id
					state.mappers[alias][i] = mapper
				}
			}
			state.mapperUpdates++
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/mappers/") && r.Method == http.MethodDelete:
			alias := pathPart(t, r.URL.Path, 5)
			id := pathPart(t, r.URL.Path, 7)
			kept := state.mappers[alias][:0]
			for _, mapper := range state.mappers[alias] {
				if mapper.ID != id {
					kept = append(kept, mapper)
				}
			}
			state.mappers[alias] = kept
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, collection+"/") && r.Method == http.MethodPut:
			alias := pathPart(t, r.URL.Path, 5)
			var provider keycloak.IdentityProvider
			if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
				t.Fatalf("decode provider update: %v", err)
			}
			for i := range state.providers {
				if state.providers[i].Alias == alias {
					state.providers[i] = provider
				}
			}
			state.updates++
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, collection+"/") && r.Method == http.MethodDelete:
			alias := pathPart(t, r.URL.Path, 5)
			kept := state.providers[:0]
			for _, provider := range state.providers {
				if provider.Alias != alias {
					kept = append(kept, provider)
				}
			}
			state.providers = kept
			state.providerDeletes = append(state.providerDeletes, alias)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return state, server
}

func pathPart(t *testing.T, value string, index int) string {
	t.Helper()
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if index >= len(parts) {
		t.Fatalf("path %q has no part %d", value, index)
	}
	return parts[index]
}

func TestRealmIdentityProvidersReconcileFreshRealmIdempotentlyAndCleanOnlyOwned(t *testing.T) {
	state, server := newRealmIdentityProviderServer(t)
	state.providers = append(state.providers, keycloak.IdentityProvider{Alias: "unmanaged", ProviderID: "oidc", Enabled: true})
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "entra-broker", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("resolved-secret")},
	}
	r := &HankoRealmReconciler{Client: newThemeClient(t, secret)}
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
			Alias: "entra", DisplayName: "Microsoft Entra ID", ProviderID: "oidc", Enabled: boolPointer(true), TrustEmail: boolPointer(true),
			FirstBrokerLoginFlowAlias: "first broker login",
			Config: map[string]string{
				"clientId": "hanko", "issuer": "https://login.microsoftonline.com/tenant/v2.0",
				"authorizationUrl": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
				"tokenUrl":         "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
				"userInfoUrl":      "https://graph.microsoft.com/oidc/userinfo", "useJwksUrl": "true",
				"jwksUrl":  "https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
				"syncMode": "IMPORT", "validateSignature": "true", "clientAuthMethod": "client_secret_post",
				"defaultScope": "openid email profile",
			},
			ClientSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "entra-broker"}, Key: "client-secret"},
			Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{
				{Name: "email", IdentityProviderMapper: "oidc-user-attribute-idp-mapper", Config: map[string]string{"syncMode": "IMPORT", "claim": "email", "user.attribute": "email"}},
				{Name: "username", IdentityProviderMapper: "oidc-user-attribute-idp-mapper", Config: map[string]string{"syncMode": "IMPORT", "claim": "preferred_username", "user.attribute": "username"}},
				{Name: "platform-admin-role", IdentityProviderMapper: "oidc-role-idp-mapper", Config: map[string]string{"syncMode": "FORCE", "claim": "groups", "claim.value": "4f24b66f-92c3-424d-aaf2-39b41c9c9630", "role": "A6_TRUNX_PLATFORM"}},
			},
		}}},
	}
	kc := keycloak.New(server.URL, "client", "secret")

	if err := r.reconcileRealmIdentityProviders(context.Background(), realm, kc); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := r.reconcileRealmIdentityProviders(context.Background(), realm, kc); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if state.creates != 1 || state.updates != 0 || state.mapperCreates != 3 || state.mapperUpdates != 0 {
		t.Fatalf("mutations after idempotent reconcile: providers=%d/%d mappers=%d/%d", state.creates, state.updates, state.mapperCreates, state.mapperUpdates)
	}
	if len(realm.Status.ManagedIdentityProviders) != 1 || len(realm.Status.ManagedIdentityProviders[0].Mappers) != 3 {
		t.Fatalf("managed provider status = %+v", realm.Status.ManagedIdentityProviders)
	}
	for _, provider := range state.providers {
		if provider.Alias == "entra" && provider.Config["clientSecret"] != "resolved-secret" {
			t.Fatalf("client secret was not resolved into provider payload")
		}
	}

	realm.Spec.IdentityProviders = nil
	if err := r.reconcileRealmIdentityProviders(context.Background(), realm, kc); err != nil {
		t.Fatalf("cleanup reconcile: %v", err)
	}
	if len(state.providerDeletes) != 1 || state.providerDeletes[0] != "entra" {
		t.Fatalf("provider deletes = %v, want only entra", state.providerDeletes)
	}
	if len(state.providers) != 1 || state.providers[0].Alias != "unmanaged" {
		t.Fatalf("unmanaged provider was changed: %+v", state.providers)
	}
}

func TestRealmIdentityProviderRejectsInlineClientSecret(t *testing.T) {
	r := &HankoRealmReconciler{Client: newThemeClient(t)}
	_, err := r.identityProviderForRealm(context.Background(), &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Namespace: "default"}}, hankoshv1alpha1.RealmIdentityProvider{
		Alias: "entra", ProviderID: "oidc", Config: map[string]string{"clientSecret": "must-not-be-stored"},
	})
	if err == nil || !strings.Contains(err.Error(), "clientSecretRef") {
		t.Fatalf("inline client secret error = %v", err)
	}
}

func TestRealmIdentityProviderAppliesRealmTrustMinimum(t *testing.T) {
	requireSignature := true
	doNotTrustEmail := false
	r := &HankoRealmReconciler{Client: newThemeClient(t)}
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
			IDPBrokerRequireSignature: &requireSignature,
			IDPBrokerTrustEmail:       &doNotTrustEmail,
		}},
	}
	desired, err := r.identityProviderForRealm(context.Background(), realm, hankoshv1alpha1.RealmIdentityProvider{
		Alias: "entra", ProviderID: "oidc", TrustEmail: boolPointer(true),
		Config: map[string]string{"validateSignature": "false"},
	})
	if err != nil {
		t.Fatalf("identityProviderForRealm: %v", err)
	}
	if desired.TrustEmail || desired.Config["validateSignature"] != "true" {
		t.Fatalf("realm trust minimum not applied: %+v", desired)
	}
}
