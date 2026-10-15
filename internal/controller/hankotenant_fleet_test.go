package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fleetFaultClient struct {
	client.Client
	fail         string
	after        bool
	writes       int
	applies      int
	failApplyAt  int
	cacheFailure string
}

func (c *fleetFaultClient) Status() client.SubResourceWriter {
	return fleetFaultStatus{SubResourceWriter: c.Client.Status(), parent: c}
}

type fleetFaultStatus struct {
	client.SubResourceWriter
	parent *fleetFaultClient
}

func (s fleetFaultStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	tenant, ok := obj.(*api.HankoTenant)
	stage := ""
	if ok && tenant.Status.FleetPlan != nil {
		stage = "verified"
		if tenant.Status.FleetPlan.AppliedIdentity == tenant.Status.FleetPlan.Identity {
			stage = "applied"
		}
	}
	fault := stage != "" && s.parent.fail == stage
	if fault && !s.parent.after {
		s.parent.fail = ""
		return errors.New("fixture acknowledgement failure")
	}
	err := s.SubResourceWriter.Patch(ctx, obj, patch, opts...)
	if err == nil && fault {
		s.parent.fail = ""
		return errors.New("fixture acknowledgement failure")
	}
	return err
}

func (c *fleetFaultClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	options := &client.CreateOptions{}
	options.ApplyOptions(opts)
	if len(options.DryRun) == 0 && obj.GetUID() == "" {
		obj.SetUID(types.UID("fixture-" + obj.GetName()))
	}
	cacheFault := c.cacheFailure
	isCache := obj.GetLabels()[fleetCacheLabel] != "" && len(options.DryRun) == 0
	if isCache && cacheFault == "before" {
		c.cacheFailure = ""
		return errors.New("fixture cache storage unavailable")
	}
	err := c.Client.Create(ctx, obj, opts...)
	if err == nil && isCache && cacheFault == "after" {
		c.cacheFailure = ""
		return errors.New("fixture cache acknowledgement lost")
	}
	if err == nil && len(options.DryRun) == 0 && obj.GetLabels()["hanko.sh/fleet-cache"] == "" {
		c.writes++
	}
	return err
}

func (c *fleetFaultClient) Apply(_ context.Context, _ runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	// This fixture exercises checkpoint ordering, not SSA. The real API suite
	// separately verifies actual conditional applies and field ownership.
	var options client.ApplyOptions
	options.ApplyOptions(opts)
	c.applies++
	if c.applies == c.failApplyAt {
		c.failApplyAt = 0
		return errors.New("fixture content apply refusal")
	}
	if options.Force != nil && *options.Force {
		return errors.New("fixture refuses forced ownership")
	}
	return nil
}

type fleetUnitFixture struct {
	r              *HankoTenantReconciler
	client         *fleetFaultClient
	tenant         *api.HankoTenant
	plan           fleetplan.Plan
	private        ed25519.PrivateKey
	envelope       []byte
	beforeResponse func()
	nativeRoles    []string
	nativeVersion  string
	hubStatus      int
	hubCalls       atomic.Int64
	nativeWrites   atomic.Int64
}

func newFleetUnitFixture(t *testing.T) *fleetUnitFixture {
	t.Helper()
	f := &fleetUnitFixture{nativeRoles: []string{"manage-realm", "manage-events", "manage-clients", "manage-identity-providers"}, nativeVersion: "26.8.0"}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.private = private
	now := time.Now().UTC()
	f.tenant = &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "auth", UID: "tenant-uid", Generation: 1}, Spec: api.HankoTenantSpec{IsolationMode: "realm", HubTenantID: "tenant-id", HubTokenSecretRef: corev1.LocalObjectReference{Name: "hub"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/realms/") || strings.HasPrefix(req.URL.Path, "/admin/") {
			switch req.URL.Path {
			case "/realms/master/protocol/openid-connect/token":
				claims, _ := json.Marshal(map[string]any{"iss": "https://" + req.Host + "/realms/master", "azp": "fixture-writer", "iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(), "resource_access": map[string]any{"fleet-realm-realm": map[string]any{"roles": f.nativeRoles}}})
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture", "expires_in": 600})
			case "/admin/serverinfo":
				_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": f.nativeVersion}})
			case "/admin/realms/fleet-realm":
				if req.Method != http.MethodGet {
					f.nativeWrites.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				_, _ = w.Write([]byte(`{"id":"fixture-realm-id","realm":"fleet-realm"}`))
			default:
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		if req.URL.Path == "/api/v1/operators/status" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.URL.Path != "/api/v1/bundles/latest" || req.Header.Get("Accept") != "application/vnd.hanko.fleet-plan+json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.hubCalls.Add(1)
		if f.hubStatus != 0 {
			w.WriteHeader(f.hubStatus)
			return
		}
		if f.beforeResponse != nil {
			callback := f.beforeResponse
			f.beforeResponse = nil
			callback()
		}
		_, _ = w.Write(f.envelope)
	}))
	t.Cleanup(server.Close)
	f.tenant.Spec.HubEndpoint = server.URL
	f.tenant.Spec.RealmRef = "fleet-realm"
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: "tenant-id", ClusterID: "cluster-id", Namespace: "auth", TenantName: "tenant"}, TenantUID: string(f.tenant.UID)}
	f.plan = fleetplan.Plan{Issuer: "publisher", KeyID: "key-1", Target: target, Source: fleetplan.Source{Repository: "example/config", Revision: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64)}, ContractVersion: string(iamcontract.Version), Sequence: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), Mode: "all-or-refuse",
		Content: fleetplan.Content{Realms: []json.RawMessage{json.RawMessage(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","metadata":{"name":"fleet-realm","namespace":"auth","labels":{"hanko.sh/tenant":"tenant"}},"spec":{"otpRequired":true}}`)}}}
	trust := fleetplan.Trust{Version: fleetplan.TrustVersion, Keys: []fleetplan.Key{{ID: "key-1", Issuer: "publisher", PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Scopes: []fleetplan.Scope{target.Scope}, Sources: []string{"example/config"}}}}
	trustRaw, _ := json.Marshal(trust)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "fleet-trust", Namespace: "auth", UID: "trust-uid"}, Data: map[string]string{"trust.json": string(trustRaw)}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub", Namespace: "auth"}, Data: map[string][]byte{"hub_token": []byte("fixture-hub-credential"), "tenant_id": []byte("tenant-id"), "cluster_id": []byte("cluster-id"), "expires_at": []byte(now.Add(12 * time.Hour).Format(time.RFC3339Nano))}}
	kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithStatusSubresource(&api.HankoTenant{}).WithObjects(f.tenant, cm, secret).Build()
	f.client = &fleetFaultClient{Client: kube}
	kc, err := keycloak.NewWithTLS(server.URL, "fixture-writer", "fixture-provider-credential", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	f.r = &HankoTenantReconciler{Client: f.client, APIReader: kube, Pool: keycloak.NewPool(kc), HubHTTPClient: server.Client(), FleetTrustConfigMapName: cm.Name}
	f.sign(t)
	return f
}

func (f *fleetUnitFixture) sign(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	f.envelope, err = json.Marshal(fleetplan.Envelope{Version: fleetplan.EnvelopeVersion, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, fleetplan.SigningInput(raw)))})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fleetUnitFixture) reconcile(t *testing.T) error {
	t.Helper()
	_, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.tenant)})
	return err
}

func TestSignedFleetPlanControllerRecovery(t *testing.T) {
	for _, stage := range []string{"verified", "applied"} {
		for _, after := range []bool{false, true} {
			t.Run(stage+"/"+map[bool]string{true: "after", false: "before"}[after], func(t *testing.T) {
				f := newFleetUnitFixture(t)
				f.client.fail = stage
				f.client.after = after
				if err := f.reconcile(t); !errors.Is(err, errFleetCheckpointWrite) {
					t.Fatalf("checkpoint error swallowed: %v", err)
				}
				if stage == "verified" && f.client.writes != 0 {
					t.Fatal("content write before acknowledged checkpoint")
				}
				for range 2 {
					if err := f.reconcile(t); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
					t.Fatal(err)
				}
				if f.tenant.Status.Phase != "Synced" || f.tenant.Status.FleetPlan == nil || f.tenant.Status.FleetPlan.Identity != f.tenant.Status.FleetPlan.AppliedIdentity || f.client.writes != 1 {
					t.Fatal("recovery duplicated or lost signed content")
				}
				f.r.FleetTrustConfigMapName = ""
				if err := f.reconcile(t); err != nil {
					t.Fatal(err)
				}
				if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
					t.Fatal(err)
				}
				if f.tenant.Status.Phase != "Error" || f.tenant.Status.Conditions[0].Reason != "FleetLegacyDowngrade" {
					t.Fatal("legacy fallback accepted after signed checkpoint")
				}
			})
		}
	}
}

func TestSignedFleetPlanRejectsBeforeApply(t *testing.T) {
	for _, boundary := range []string{"signature", "expired", "authority-change", "trust-change", "foreign-object", "unknown-field", "missing-trust", "invalid-trust", "missing-cluster", "oversize-transport", "checkpoint"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFleetUnitFixture(t)
			reason := map[string]string{"signature": "FleetSignatureInvalid", "expired": "FleetPlanExpired", "authority-change": "FleetAuthorityChanged", "trust-change": "FleetTrustChanged", "foreign-object": "BundleTenantConflict", "unknown-field": "FleetContentInvalid", "missing-trust": "FleetTrustUnavailable", "invalid-trust": "FleetTrustInvalid", "missing-cluster": "FleetTargetMismatch", "oversize-transport": "FleetPlanFetchFailed", "checkpoint": "FleetCheckpointInvalid"}[boundary]
			switch boundary {
			case "signature":
				f.private = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				f.sign(t)
			case "expired":
				f.plan.ExpiresAt = time.Now().Add(-time.Second)
				f.plan.IssuedAt = f.plan.ExpiresAt.Add(-time.Minute)
				f.plan.NotBefore = f.plan.IssuedAt
				f.sign(t)
			case "authority-change":
				f.beforeResponse = func() {
					live := &api.HankoTenant{}
					if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), live); err != nil {
						t.Error(err)
					}
					live.Spec.RealmRef = "changed"
					if err := f.client.Update(context.Background(), live); err != nil {
						t.Error(err)
					}
				}
			case "trust-change":
				f.beforeResponse = func() {
					cm := &corev1.ConfigMap{}
					if err := f.client.Get(context.Background(), client.ObjectKey{Name: "fleet-trust", Namespace: "auth"}, cm); err != nil {
						t.Error(err)
					}
					cm.Data["local-approval"] = "rotated"
					if err := f.client.Update(context.Background(), cm); err != nil {
						t.Error(err)
					}
				}
			case "foreign-object":
				if err := f.client.Client.Create(context.Background(), &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "fleet-realm", Namespace: "auth", Labels: map[string]string{"hanko.sh/tenant": "other"}}}); err != nil {
					t.Fatal(err)
				}
			case "unknown-field":
				f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"otpRequired":true`, `"unknown":true`, 1))
				f.sign(t)
			case "missing-trust", "invalid-trust":
				cm := &corev1.ConfigMap{}
				if err := f.client.Get(context.Background(), client.ObjectKey{Name: "fleet-trust", Namespace: "auth"}, cm); err != nil {
					t.Fatal(err)
				}
				if boundary == "missing-trust" {
					if err := f.client.Delete(context.Background(), cm); err != nil {
						t.Fatal(err)
					}
				} else {
					cm.Data["trust.json"] = `{"unknown":true}`
					if err := f.client.Update(context.Background(), cm); err != nil {
						t.Fatal(err)
					}
				}
			case "missing-cluster":
				secret := &corev1.Secret{}
				if err := f.client.Get(context.Background(), client.ObjectKey{Name: "hub", Namespace: "auth"}, secret); err != nil {
					t.Fatal(err)
				}
				delete(secret.Data, "cluster_id")
				if err := f.client.Update(context.Background(), secret); err != nil {
					t.Fatal(err)
				}
			case "oversize-transport":
				f.envelope = []byte(strings.Repeat("x", fleetplan.MaxEnvelope+1))
			case "checkpoint":
				f.tenant.Status.FleetPlan = &api.FleetPlanStatus{Sequence: 1, Identity: "sha256:" + strings.Repeat("a", 64), TenantUID: "replaced"}
				if err := f.client.Status().Update(context.Background(), f.tenant); err != nil {
					t.Fatal(err)
				}
			}
			checkpoint := f.tenant.Status.FleetPlan.DeepCopy()
			err := f.reconcile(t)
			if boundary == "authority-change" {
				if fleetplan.Reason(err) != "FleetAuthorityChanged" {
					t.Fatalf("changed authority was not requeued: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if f.client.writes != 0 {
				t.Fatal("refused plan wrote content")
			}
			if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
				t.Fatal(err)
			}
			if (boundary != "authority-change" && (f.tenant.Status.Phase != "Error" || len(f.tenant.Status.Conditions) != 1 || f.tenant.Status.Conditions[0].Reason != reason)) || !reflect.DeepEqual(f.tenant.Status.FleetPlan, checkpoint) {
				t.Fatal("refused plan acquired a checkpoint")
			}
		})
	}
}
