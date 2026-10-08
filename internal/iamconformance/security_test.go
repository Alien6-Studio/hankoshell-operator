package iamconformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

func TestBothAdaptersBoundAndExcludeCredentialErrors(t *testing.T) {
	credential := "fixture-admin-credential-sentinel"
	token := "fixture-bearer-sentinel"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600}`, token)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat(credential, 100)))
	}))
	defer server.Close()
	kc := keycloak.New(server.URL, "fixture", credential, keycloak.WithInsecureHTTP())
	model := authorization.Model{Name: "api", Realm: "realm", Audience: "urn:api", ApplicationRef: "app"}
	i := authorization.Normalize(model)
	r, _ := authorization.Resolve(i, model)
	caps, _ := authorization.NewKeycloakDriver(kc).Capabilities(context.Background(), "realm")
	ap, err := authorization.Compile(i, r, authorization.KeycloakEvidence(caps), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	rp, err := roles.Compile(roles.Intent{RealmRef: "realm", Name: "reader"}, roles.ResolvedReferences{Realm: "realm", Owner: "uid"}, roles.KeycloakEvidence(), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	_, ae := authorization.NewKeycloakDriver(kc).Observe(context.Background(), ap)
	_, re := roles.NewKeycloakDriver(kc).Observe(context.Background(), rp)
	for _, e := range []error{ae, re} {
		if e == nil || len(e.Error()) > 256 {
			t.Fatal("provider failure absent/unbounded")
		}
		iamconformance.NoSecrets(t, []string{credential, token}, e, e.Error(), ap, rp)
	}
}

func TestRoleConcurrentForeignCreationCannotBeAdopted(t *testing.T) {
	reads, writes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
			return
		}
		if r.Method != http.MethodGet {
			writes++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		reads++
		if reads == 1 {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "foreign-id", "name": "reader", "attributes": map[string][]string{roles.OwnerAttribute: {"foreign-owner"}}})
	}))
	defer server.Close()
	kc := keycloak.New(server.URL, "fixture", "fixture-credential", keycloak.WithInsecureHTTP())
	plan, err := roles.Compile(roles.Intent{RealmRef: "realm", Name: "reader"}, roles.ResolvedReferences{Realm: "realm", Owner: "own-uid"}, roles.KeycloakEvidence(), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = roles.NewKeycloakDriver(kc).Reconcile(context.Background(), plan)
	if !errors.Is(err, roles.ErrOwnershipConflict) || writes != 0 {
		t.Fatal("concurrent foreign role was adopted/mutated")
	}
}
