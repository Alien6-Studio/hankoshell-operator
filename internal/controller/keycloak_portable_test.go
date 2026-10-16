//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The literal corpus runs through production reconcilers against native HTTPS.
// Only the operational Kubernetes CA binding and discovery are injected here;
// the installed suite supplies real cluster anchors and discovery instead.
func TestRealKeycloakPortableCorpus(t *testing.T) {
	f := newKeycloakFixtureWithTransportAndDiscovery(t, false, false, true)
	ctx := context.Background()
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "portable", "enabled": true}, nil)
	kc, _ := f.serviceClient("portable-operator")
	f.grantClientRoles("portable-operator", "portable", []string{"manage-realm", "manage-clients", "manage-events", "manage-users", "manage-authorization"})
	f.admin(http.MethodPost, "/admin/realms/portable/roles", map[string]any{"name": "portable-writer"}, nil)
	f.admin(http.MethodPut, "/admin/realms/portable/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
	writes := func() int {
		var events []map[string]any
		f.admin(http.MethodGet, "/admin/realms/portable/admin-events?max=1000", nil, &events)
		return len(events)
	}
	scheme := newScheme(t)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&api.HankoApplication{}, controller.RealmClientIndexKey, realmClientIndexer).
		WithStatusSubresource(&api.HankoApplication{}, &api.HankoRealm{}, &api.HankoIAMProfile{}, &api.HankoRole{}, &api.HankoOrganization{}, &api.HankoServiceAccount{}, &api.HankoResourceServer{}, &api.HankoWorkloadTrust{}).Build()
	pool := keycloak.NewPool(kc)
	recorder := events.NewFakeRecorder(1000)
	caHash, err := workloadtrust.APICAHash(f.ca)
	f.requireNoError(err)
	f.requireNoError(kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "portable-synthetic-cluster"}}))
	f.requireNoError(kube.Create(ctx, &corev1.Secret{ObjectMeta: fixtureMeta("portable-ca"), Data: map[string][]byte{"ca.crt": f.ca}}))
	for _, p := range []struct {
		name  string
		roles []string
	}{
		{"source", []string{"view-realm", "view-identity-providers", "manage-identity-providers"}},
		{"dependent-reader", []string{"view-clients"}},
	} {
		_, secret := f.serviceClient("portable-" + p.name)
		f.grantClientRoles("portable-"+p.name, "portable", p.roles)
		f.requireNoError(kube.Create(ctx, &corev1.Secret{ObjectMeta: fixtureMeta(p.name + "-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(f.baseURL), "HANKO_KC_CLIENT_ID": []byte("portable-" + p.name), "HANKO_KC_CLIENT_SECRET": []byte(secret)}}))
		f.requireNoError(kube.Create(ctx, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta(p.name), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "portable-ca", AdminRef: corev1.LocalObjectReference{Name: p.name + "-credential"}}}))
	}
	trust := &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: kube, ClusterConfig: &rest.Config{Host: f.baseURL, TLSClientConfig: rest.TLSClientConfig{CAData: f.ca}}, DiscoveryCheck: func(_ context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		return workloadtrust.DiscoveryEvidence{Issuer: i.Issuer, JWKSURL: i.Issuer + "/jwks", KeysHash: workloadtrust.Digest("portable-source-discovery", 1)}, nil
	}}
	reconcilers := map[string]fixtureReconciler{
		"HankoRealm":          &controller.HankoRealmReconciler{Client: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoIAMProfile":     &controller.HankoIAMProfileReconciler{Client: kube},
		"HankoApplication":    &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoRole":           &controller.HankoRoleReconciler{Client: kube, APIReader: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoOrganization":   &controller.HankoOrganizationReconciler{Client: kube, APIReader: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoServiceAccount": &controller.HankoServiceAccountReconciler{Client: kube, OwnershipReader: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoResourceServer": &controller.HankoResourceServerReconciler{Client: kube, APIReader: kube, Scheme: scheme, Pool: pool, Recorder: recorder},
		"HankoWorkloadTrust":  trust,
	}
	corpus, err := iamconformance.ReadPortableCorpus()
	f.requireNoError(err)
	for _, fixture := range corpus.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			target, err := scheme.New(api.GroupVersion.WithKind(fixture.Manifest.Kind))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(fixture.Manifest)
			if json.Unmarshal(raw, target) != nil {
				t.Fatal("invalid corpus manifest")
			}
			obj := target.(client.Object)
			obj.SetNamespace("qualification")
			obj.SetUID(types.UID("portable-" + fixture.Name))
			obj.SetGeneration(1)
			if tr, ok := obj.(*api.HankoWorkloadTrust); ok {
				tr.Spec.Kubernetes.ClusterAnchor.APIServerCAHash = caHash
			}
			if err := kube.Create(ctx, obj); err != nil {
				t.Fatal(err)
			}
			r := reconcilers[fixture.Manifest.Kind]
			run := func() error {
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				return err
			}
			if fixture.Expected["keycloak"].Classification == "unsupported" {
				iamconformance.NoMutation(t, writes, func() error {
					_ = run() // A refusal may be returned after its status patch.
					return nil
				})
			} else {
				for range 5 {
					if err := run(); err != nil {
						t.Fatal(err)
					}
				}
				// Realm policy maintenance can issue equivalent native PUTs; the
				// sealed IAM domains must converge without further provider writes.
				if fixture.Expected["keycloak"].PlanEvidence {
					iamconformance.NoMutation(t, writes, run)
				}
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			raw, _ = json.Marshal(obj)
			if err := iamconformance.CheckPortableObservation(fixture, "keycloak", raw); err != nil {
				t.Fatal(err)
			}
			if fixture.Expected["keycloak"].Classification == "lossless" {
				checkPortableKeycloakNative(t, f, obj)
			}
			iamconformance.NoSecrets(t, f.secrets, obj)
		})
	}
}

func checkPortableKeycloakNative(t *testing.T, f *keycloakFixture, obj client.Object) {
	t.Helper()
	base := "/admin/realms/portable"
	switch value := obj.(type) {
	case *api.HankoRealm:
		var native map[string]any
		f.admin(http.MethodGet, base, nil, &native)
		fixtureEqual(t, "literal realm display", native["displayName"], value.Spec.DisplayName)
	case *api.HankoIAMProfile:
		if value.Status.PolicyHash == "" {
			t.Fatal("literal IAM profile lacks validation evidence")
		}
	case *api.HankoOrganization:
		var native map[string]any
		f.admin(http.MethodGet, base+"/groups/"+value.Status.GroupID, nil, &native)
		fixtureEqual(t, "literal organization group", native["id"], value.Status.GroupID)
		var roles []map[string]any
		f.admin(http.MethodGet, base+"/groups/"+value.Status.GroupID+"/role-mappings/realm", nil, &roles)
		if len(roles) != 1 || roles[0]["name"] != "portable-reader" {
			t.Fatal("literal organization role mapping differs")
		}
	case *api.HankoServiceAccount:
		native := f.client("portable", value.Spec.ClientID)
		fixtureEqual(t, "literal service account native mode", native["serviceAccountsEnabled"], true)
		fixtureEqual(t, "literal service account enabled", native["enabled"], true)
		var credential map[string]any
		f.admin(http.MethodGet, base+"/clients/"+native["id"].(string)+"/client-secret", nil, &credential)
		if secret, ok := credential["value"].(string); ok && secret != "" {
			f.secrets = append(f.secrets, secret)
		} else {
			t.Fatal("literal service account credential absent")
		}
	case *api.HankoWorkloadTrust:
		var native map[string]any
		f.admin(http.MethodGet, base+"/identity-provider/instances/"+value.Spec.KeycloakAlias, nil, &native)
		fixtureEqual(t, "literal trust native UUID", native["internalId"], value.Status.ProviderID)
		config := native["config"].(map[string]any)
		fixtureEqual(t, "literal trust age", config["fedClientAssertionMaxExp"], "600")
		fixtureEqual(t, "literal trust owner", config["hanko.sh/workload-trust-owner"], string(value.UID))
	case *api.HankoApplication:
		native := f.client("portable", value.Spec.ClientID)
		if value.Spec.Type != "spa" && value.Spec.Protocol != "saml" {
			var credential map[string]any
			f.admin(http.MethodGet, base+"/clients/"+native["id"].(string)+"/client-secret", nil, &credential)
			if secret, ok := credential["value"].(string); ok && secret != "" {
				f.secrets = append(f.secrets, secret)
			}
		}
	}
}
