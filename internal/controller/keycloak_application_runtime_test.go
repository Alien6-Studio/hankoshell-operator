//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Reuses the HTTPS flow fixture and its manage-clients-only service account.
// Bootstrap alone enables/reads audit events; runtime adds no Keycloak role.
func qualifyRuntimeBindings(f *keycloakFixture, operator *keycloak.Client) {
	ctx := context.Background()
	kube := runtimeKube(newFakeClient(f.t))
	ar := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, RuntimeClient: kube, Scheme: newScheme(f.t), Pool: keycloak.NewPool(operator)}
	f.admin(http.MethodPut, "/admin/realms/managed/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed/admin-events?max=1000", nil, &events)
		return len(events)
	}
	for _, kind := range []string{"spa", "web", "m2m", "saml"} {
		f.run("runtime "+kind, func(t *testing.T) {
			name := "runtime-" + kind
			b := api.ApplicationRuntimeBinding{Name: name, Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: name}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: name}}
			audience := name
			app := &api.HankoApplication{ObjectMeta: fixtureMeta(name), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: name, Type: kind, RuntimeBindings: []api.ApplicationRuntimeBinding{b}}}
			if kind == "saml" {
				app.Spec.Type = ""
				app.Spec.Protocol = "saml"
				app.Spec.ClientID = "https://" + name + ".example/entity"
				app.Spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: []string{"https://" + name + ".example/acs"}}
			} else {
				app.Spec.TokenClaims = []api.ApplicationTokenClaim{{Name: "audience", Claim: "aud", Value: &audience}}
			}
			if kind == "web" || kind == "m2m" {
				b.Credentials = &api.ApplicationRuntimeCredentialTarget{SecretRef: name}
				app.Spec.RuntimeBindings[0] = b
			}
			f.requireNoError(kube.Create(ctx, app))
			for _, obj := range runtimeTargets(app, b) {
				f.requireNoError(kube.Create(ctx, obj))
			}
			fixtureReconcile(f, ctx, ar, app)
			fixtureGet(f, ctx, kube, app)
			fixtureEqual(t, "runtime ready", app.Status.Phase, "Ready")
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "payments"}}
			fixtureGet(f, ctx, kube, cm)
			var doc applicationbinding.Document
			f.requireNoError(json.Unmarshal([]byte(cm.Data["identity.json"]), &doc))
			fixtureEqual(t, "runtime schema", doc.SchemaVersion, applicationbinding.Schema)
			fixtureEqual(t, "runtime client ID", doc.ClientID, app.Spec.ClientID)
			if kind == "saml" {
				if doc.SAML == nil || doc.OIDC != nil || doc.Credentials != nil || doc.SAML.NameIDFormat != "persistent" {
					t.Fatal("SAML runtime contract differs")
				}
			} else if doc.OIDC == nil || doc.SAML != nil {
				t.Fatal("OIDC runtime contract differs")
			}
			first := doc.BindingRevision
			before := writes()
			fixtureReconcile(f, ctx, ar, app)
			fixtureEqual(t, "current runtime provider writes", writes(), before)
			if b.Credentials != nil {
				target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "payments"}}
				fixtureGet(f, ctx, kube, target)
				credential := string(target.Data["client_secret"])
				f.secrets = append(f.secrets, credential)
				if credential == "" {
					t.Fatal("missing runtime credential")
				}
				if kind == "m2m" {
					verifyRuntimeToken(f, app.Spec.ClientID, credential)
				}
				// Credential drift repair and a partial output failure must not mutate
				// provider state or create another credential lifecycle.
				target.Data["client_secret"] = []byte("tampered-runtime-value")
				f.requireNoError(kube.Update(ctx, target))
				fail := true
				failing := interceptor.NewClient(kube, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
					if _, ok := obj.(*corev1.Secret); ok && obj.GetNamespace() == "payments" && fail {
						fail = false
						return errors.New("injected target failure")
					}
					return c.Patch(ctx, obj, p, opts...)
				}})
				ar.RuntimeClient = failing
				_, err := ar.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
				if err == nil {
					t.Fatal("target failure not exercised")
				}
				fixtureEqual(t, "failed output provider writes", writes(), before)
				ar.RuntimeClient = kube
				fixtureReconcile(f, ctx, ar, app)
				fixtureEqual(t, "recovered output provider writes", writes(), before)
				fixtureGet(f, ctx, kube, target)
				fixtureEqual(t, "credential drift repair", string(target.Data["client_secret"]), credential)
				fixtureGet(f, ctx, kube, app)
				at := metav1.NewTime(time.Now().Add(time.Second).Truncate(time.Second))
				time.Sleep(time.Until(at.Time) + 20*time.Millisecond)
				app.Spec.SecretRotationPolicy = &api.SecretRotationPolicy{Enabled: true, ForceRotateAt: &at}
				app.Generation++
				f.requireNoError(kube.Update(ctx, app))
				fixtureReconcile(f, ctx, ar, app)
				fixtureGet(f, ctx, kube, app)
				fixtureGet(f, ctx, kube, target)
				fixtureGet(f, ctx, kube, cm)
				rotated := string(target.Data["client_secret"])
				f.secrets = append(f.secrets, rotated)
				if rotated == credential || app.Status.RuntimeBindings[0].BindingRevision == first || cm.Annotations[applicationbinding.RevisionAnnotation] != target.Annotations[applicationbinding.RevisionAnnotation] {
					t.Fatal("rotation outputs/revision did not converge")
				}
				if kind == "m2m" {
					verifyRuntimeToken(f, app.Spec.ClientID, rotated)
				}
				before = writes()
				fixtureReconcile(f, ctx, ar, app)
				fixtureEqual(t, "rotation retry provider writes", writes(), before)
			}
			fixtureGet(f, ctx, kube, app)
			app.Spec.RuntimeBindings = nil
			app.Generation++
			f.requireNoError(kube.Update(ctx, app))
			fixtureReconcile(f, ctx, ar, app)
			fixtureGet(f, ctx, kube, cm)
			if cm.Data["identity.json"] != "" || cm.Data["owner"] != "preserved" {
				t.Fatal("metadata cleanup differs")
			}
			if b.Credentials != nil {
				var target corev1.Secret
				f.requireNoError(kube.Get(ctx, client.ObjectKey{Namespace: "payments", Name: name}, &target))
				if len(target.Data["client_secret"]) > 0 || string(target.Data["owner"]) != "preserved" {
					t.Fatal("credential cleanup differs")
				}
			}
			f.requireNoCredentials("runtime document", []byte(cm.Data["identity.json"]))
		})
	}
}
func verifyRuntimeToken(f *keycloakFixture, name, credential string) {
	issuer := f.baseURL + "/realms/managed"
	status, _, data := protocolHTTP(f, f.http, http.MethodPost, issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {name}, "client_secret": {credential}})
	fixtureEqual(f.t, "projected credential token status", status, http.StatusOK)
	var result struct {
		AccessToken string `json:"access_token"`
	}
	f.requireNoError(json.Unmarshal(data, &result))
	fixtureVerifyJWT(f, result.AccessToken, issuer, name)
}
