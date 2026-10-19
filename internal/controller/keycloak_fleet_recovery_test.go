//go:build keycloak_integration

package controller_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// This is real native-provider evidence, distinct from the installed six-cell
// image/chart qualification. Only Kubernetes storage uses a fake here.
func TestRealKeycloakFleetDisconnectedAuthority(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	f.requireNoError(err)
	now := time.Now().UTC()
	tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "fleet", Namespace: "qualification", UID: "fleet-tenant-uid"}, Spec: api.HankoTenantSpec{IsolationMode: "realm", RealmRef: "managed", HubTenantID: "fleet-tenant", HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub"}}}
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: "fleet-tenant", ClusterID: "fleet-cluster", Namespace: tenant.Namespace, TenantName: tenant.Name}, TenantUID: string(tenant.UID)}
	plan := fleetplan.Plan{Issuer: "fixture-publisher", KeyID: "fixture-key", Target: target, Source: fleetplan.Source{Repository: "fixture/config", Revision: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64)}, ContractVersion: string(iamcontract.Version), Sequence: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(3 * time.Minute), Mode: "all-or-refuse"}
	payload, err := json.Marshal(plan)
	f.requireNoError(err)
	envelope, err := json.Marshal(fleetplan.Envelope{Version: fleetplan.EnvelopeVersion, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, fleetplan.SigningInput(payload)))})
	f.requireNoError(err)
	hub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/bundles/latest" {
			_, _ = w.Write(envelope)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(hub.Close)
	tenant.Spec.HubEndpoint = hub.URL
	trust, err := json.Marshal(fleetplan.Trust{Version: fleetplan.TrustVersion, Keys: []fleetplan.Key{{ID: plan.KeyID, Issuer: plan.Issuer, PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Scopes: []fleetplan.Scope{target.Scope}, Sources: []string{plan.Source.Repository}}}})
	f.requireNoError(err)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "fleet-trust", Namespace: tenant.Namespace, UID: "fleet-trust-uid"}, Data: map[string]string{"trust.json": string(trust)}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub", Namespace: tenant.Namespace}, Data: map[string][]byte{"hub_token": []byte("disposable-fleet-token"), "tenant_id": []byte(target.TenantID), "cluster_id": []byte(target.ClusterID), "expires_at": []byte(now.Add(12 * time.Hour).Format(time.RFC3339Nano))}}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&api.HankoTenant{}).WithObjects(tenant, cm, secret).WithInterceptorFuncs(fleetNativeCacheUID()).Build()
	r := &controller.HankoTenantReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(f.kc), HubHTTPClient: hub.Client(), FleetTrustConfigMapName: cm.Name}
	reconcile := func() {
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
		f.requireNoError(err)
		f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(tenant), tenant))
	}
	reconcile()
	if tenant.Status.FleetPlan == nil || tenant.Status.FleetPlan.Cache == nil {
		t.Fatalf("verified plan not retained: %+v", tenant.Status.Conditions)
	}
	// Stop the actual Hub listener; Keycloak remains independently available.
	hub.Close()
	r = &controller.HankoTenantReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(f.kc), HubHTTPClient: hub.Client(), FleetTrustConfigMapName: cm.Name}
	reconcile()
	if tenant.Status.Conditions[0].Reason != "FleetPlanDisconnected" {
		t.Fatalf("offline authority lost: %+v", tenant.Status.Conditions)
	}
	kc := r.Pool.Get(tenant.Namespace + "/" + tenant.Name)
	if kc == nil {
		t.Fatal("client registration depended on Hub availability")
	}
	f.requireNoError(kc.UpdateRealm(ctx, "managed", keycloak.RealmSpec{DisplayName: "Fleet offline valid", Enabled: true}))
	var actual map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed", nil, &actual)
	fixtureEqual(t, "real provider offline write", actual["displayName"], "Fleet offline valid")
	// Persisted expiry also fences a connection acquired before it changed.
	tenant.Status.FleetPlan.Expired = true
	f.requireNoError(kube.Status().Update(ctx, tenant))
	if fleetplan.Reason(kc.UpdateRealm(ctx, "managed", keycloak.RealmSpec{DisplayName: "must not apply", Enabled: true})) != "FleetPlanExpired" {
		t.Fatal("expired cached plan reached real provider")
	}
	f.admin(http.MethodGet, "/admin/realms/managed", nil, &actual)
	fixtureEqual(t, "real provider preserved after expiry", actual["displayName"], "Fleet offline valid")
	// The installation client was not contaminated by tenant-specific expiry.
	f.requireNoError(f.kc.UpdateRealm(ctx, "managed", keycloak.RealmSpec{DisplayName: "Installation authority", Enabled: true}))
}

func fleetNativeCacheUID() interceptor.Funcs {
	return interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("fixture-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}
}
