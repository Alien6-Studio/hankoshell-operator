//go:build keycloak_integration

package controller_test

import (
	"context"
	_ "embed"
	"net/http"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

//go:embed testdata/v0.2-customer-portal.yaml
var legacyApplicationManifest []byte

func TestRealKeycloakLegacyApplicationMigration(t *testing.T) {
	f := newKeycloakFixture(t)
	operator, _ := f.serviceClient("migration-operator")
	f.grantClientRoles("migration-operator", "managed", []string{"manage-clients", "manage-realm"})
	ctx := context.Background()
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "example", "enabled": true}, nil)
	f.admin(http.MethodPost, "/admin/realms/example/roles", map[string]any{"name": "viewer"}, nil)
	f.grantClientRoles("migration-operator", "example", []string{"manage-clients", "manage-realm"})
	kube := newFakeClient(t)
	r := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: newScheme(t), Pool: keycloak.NewPool(operator)}
	for _, kind := range []string{"spa", "web", "m2m"} {
		var app api.HankoApplication
		f.requireNoError(yaml.UnmarshalStrict(legacyApplicationManifest, &app))
		if app.Spec.Protocol != "" {
			t.Fatal("historical manifest contains protocol")
		}
		app.ObjectMeta = fixtureMeta("legacy-" + kind)
		app.Spec.Type = kind
		if kind != "spa" {
			app.Spec.ClientID += "-" + kind
		}
		// These calls are the unchanged v0.2 OIDC constructor and mapper API.
		credential, err := operator.CreateApp(ctx, "example", keycloak.CreateAppSpec{ClientID: app.Spec.ClientID, Name: app.Spec.ClientID, Type: kind, RedirectURIs: app.Spec.RedirectURIs, PostLogoutRedirectURIs: app.Spec.PostLogoutRedirectURIs})
		f.requireNoError(err)
		f.secrets = append(f.secrets, credential)
		if kind == "m2m" {
			cl := f.client("example", app.Spec.ClientID)
			path := "/admin/realms/example/clients/" + cl["id"].(string) + "/default-client-scopes"
			var scopes []map[string]any
			f.admin(http.MethodGet, path, nil, &scopes)
			for _, scope := range scopes {
				if scope["name"] == "service_account" {
					f.admin(http.MethodDelete, path+"/"+scope["id"].(string), nil, nil)
				}
			}
		}
		f.requireNoError(operator.ReconcileClientRealmRoleScopes(ctx, "example", app.Spec.ClientID, app.Spec.RealmRoleScopes))
		f.requireNoError(operator.CreateClientRole(ctx, "example", app.Spec.ClientID, "viewer", "Existing role"))
		app.Spec.Roles = []api.ApplicationRole{{Name: "viewer", Description: "Existing role"}}
		value := "legacy"
		app.Spec.TokenClaims = []api.ApplicationTokenClaim{{Name: "environment", Claim: "deployment_environment", Value: &value}}
		mapper, err := operator.EnsureClientProtocolMapper(ctx, "example", app.Spec.ClientID, keycloak.ProtocolMapper{Name: "hanko:qualification:" + app.Name + ":claim:environment", Protocol: "openid-connect", ProtocolMapper: "oidc-hardcoded-claim-mapper", Config: map[string]string{"claim.name": "deployment_environment", "claim.value": value, "jsonType.label": "String", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}})
		f.requireNoError(err)
		// Existing installations can have explicitly restricted or empty CORS
		// origins. Review them in the declaration before migrating ownership.
		longOrigin := "https://legacy.example.test/" + strings.Repeat("a", 255-len("https://legacy.example.test/"))
		origins := []string{"https://legacy.example.test", "http://localhost:3000", "https://legacy.example.test/auth/callback", "https://legacy.example.test/login/*", longOrigin}
		if kind == "web" {
			origins = []string{}
		}
		app.Spec.WebOrigins = &origins
		current := f.client("example", app.Spec.ClientID)
		current["webOrigins"] = origins
		f.admin(http.MethodPut, "/admin/realms/example/clients/"+current["id"].(string), current, nil)
		before := f.client("example", app.Spec.ClientID)
		if kind != "spa" {
			last := metav1.NewTime(time.Now().Add(-time.Hour))
			app.Status.LastRotated = &last
			app.Spec.SecretRotationPolicy = &api.SecretRotationPolicy{Enabled: true, IntervalDays: 30}
			f.requireNoError(kube.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hanko-app-" + app.Spec.ClientID, Namespace: app.Namespace}, Data: map[string][]byte{"client_secret": []byte(credential)}}))
		}
		f.requireNoError(kube.Create(ctx, &app))
		fixtureReconcile(f, ctx, r, &app)
		fixtureGet(f, ctx, kube, &app)
		if !applicationHasCondition(app.Status.Conditions, "Synced", metav1.ConditionFalse, "OwnershipApprovalRequired") || app.Status.ObservedStateHash == "" {
			t.Fatal("unmarked client automatically adopted")
		}
		observation := string(app.Status.ObservedStateHash)
		// Forged evidence and mapper IDs cannot approve migration or delete objects.
		app.Status.AppliedPlanHash = app.Status.EvaluatedPlanHash
		app.Status.AppliedGeneration = app.Generation
		app.Status.ManagedTokenClaims = []api.ManagedTokenClaimReference{{Name: "forged", KeycloakID: mapper.ID}}
		f.requireNoError(kube.Status().Update(ctx, &app))
		fixtureReconcile(f, ctx, r, &app)
		fixtureGet(f, ctx, kube, &app)
		fixtureEqual(t, "status grants no provider authority", f.client("example", app.Spec.ClientID), before)
		for _, approval := range [][2]string{{"wrong-uuid", observation}, {before["id"].(string), "sha256:" + strings.Repeat("a", 64)}} {
			app.Annotations = map[string]string{applications.MigrationUUIDAnnotation: approval[0], applications.MigrationObservationAnnotation: approval[1]}
			f.requireNoError(kube.Update(ctx, &app))
			fixtureReconcile(f, ctx, r, &app)
			fixtureGet(f, ctx, kube, &app)
			if app.Status.Phase != "Conflict" {
				t.Fatal("incorrect approval accepted")
			}
			fixtureEqual(t, "incorrect approval preserves client", f.client("example", app.Spec.ClientID), before)
		}
		app.Annotations = map[string]string{applications.MigrationUUIDAnnotation: before["id"].(string), applications.MigrationObservationAnnotation: observation}
		f.requireNoError(kube.Update(ctx, &app))
		if kind != "spa" {
			// Provider acquisition does not authorize an ownerless historical
			// Kubernetes credential. An administrator must bind that exact Secret
			// to the application after reviewing its identity and current value.
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&app)}); err == nil {
				t.Fatal("migration implicitly adopted an ownerless credential")
			}
			var secret corev1.Secret
			f.requireNoError(kube.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: "hanko-app-" + app.Spec.ClientID}, &secret))
			fixtureEqual(t, "refused credential remains unchanged", string(secret.Data["client_secret"]), credential)
			if len(secret.OwnerReferences) != 0 {
				t.Fatal("migration changed credential ownership")
			}
			secret.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(&app, api.GroupVersion.WithKind("HankoApplication"))}
			f.requireNoError(kube.Update(ctx, &secret))
		}
		fixtureReconcile(f, ctx, r, &app)
		fixtureGet(f, ctx, kube, &app)
		if app.Status.Phase != "Ready" || app.Status.Protocol != "oidc" {
			t.Fatal("explicit legacy migration did not reconcile")
		}
		after := f.client("example", app.Spec.ClientID)
		fixtureEqual(t, "migration retains UUID", after["id"], before["id"])
		for _, field := range []string{"defaultClientScopes", "optionalClientScopes", "frontchannelLogout"} {
			fixtureEqual(t, "legacy migration retains native setting: "+field, adoptionClone(t, after)[field], adoptionClone(t, before)[field])
		}
		mappers, err := operator.ListClientProtocolMappers(ctx, "example", app.Spec.ClientID)
		f.requireNoError(err)
		fixtureEqual(t, "migration retains mapper UUID", mappers[0].ID, mapper.ID)
		roles, err := operator.ListClientRoles(ctx, "example", app.Spec.ClientID)
		f.requireNoError(err)
		fixtureEqual(t, "migration retains role", len(roles), 1)
		if kind != "spa" {
			actual, err := operator.GetClientSecret(ctx, "example", app.Spec.ClientID)
			f.requireNoError(err)
			fixtureEqual(t, "migration does not rotate secret", actual, credential)
		}
		// OIDC -> SAML is refused even with the migration annotations present.
		app.Spec = api.HankoApplicationSpec{RealmRef: "example", ClientID: app.Spec.ClientID, Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{"https://portal.example.com/acs"}}}
		// Entity IDs are absolute. Use an owned URI client in the separate flow
		// fixture for conversion; this legacy short ID is rejected before writes.
		app.Generation++
		f.requireNoError(kube.Update(ctx, &app))
		fixtureReconcile(f, ctx, r, &app)
		fixtureEqual(t, "invalid SAML conversion preserves legacy client", f.client("example", app.Spec.ClientID), after)
	}
	t.Log("v0.2 README fixture: omitted protocol, explicit UUID+observation adoption, stable UUID/role/mapper/secret; forged evidence rejected")
}
