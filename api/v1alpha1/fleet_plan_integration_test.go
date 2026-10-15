//go:build integration

package v1alpha1_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

type fleetAPIWriter struct {
	client.Client
	failStage       string
	after           bool
	writes          int
	afterCheckpoint func()
}

func (c *fleetAPIWriter) Status() client.SubResourceWriter {
	return fleetAPIStatus{SubResourceWriter: c.Client.Status(), writer: c}
}

type fleetAPIStatus struct {
	client.SubResourceWriter
	writer *fleetAPIWriter
}

func (s fleetAPIStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	stage := ""
	if tenant, ok := obj.(*api.HankoTenant); ok && tenant.Status.FleetPlan != nil {
		stage = "accepted"
		if tenant.Status.FleetPlan.Identity == tenant.Status.FleetPlan.AppliedIdentity {
			stage = "applied"
		}
	}
	fail := stage != "" && stage == s.writer.failStage
	if fail && !s.writer.after {
		s.writer.failStage = ""
		return errors.New("fixture unacknowledged checkpoint")
	}
	err := s.SubResourceWriter.Patch(ctx, obj, patch, opts...)
	if err == nil && stage == "accepted" && s.writer.afterCheckpoint != nil {
		callback := s.writer.afterCheckpoint
		s.writer.afterCheckpoint = nil
		callback()
	}
	if err == nil && fail {
		s.writer.failStage = ""
		return errors.New("fixture lost checkpoint acknowledgement")
	}
	return err
}

func (c *fleetAPIWriter) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	var options client.CreateOptions
	options.ApplyOptions(opts)
	err := c.Client.Create(ctx, obj, opts...)
	if err == nil && len(options.DryRun) == 0 {
		c.writes++
	}
	return err
}

type fleetAPIFixture struct {
	kube          client.Client
	writer        *fleetAPIWriter
	r             *controller.HankoTenantReconciler
	tenant        *api.HankoTenant
	trust         *corev1.ConfigMap
	plan          fleetplan.Plan
	private       ed25519.PrivateKey
	envelope      atomic.Pointer[[]byte]
	reported      atomic.Pointer[hub.OperatorStatus]
	before        atomic.Pointer[func()]
	nativeRoles   atomic.Pointer[[]string]
	nativeVersion atomic.Pointer[string]
}

func newFleetAPIFixture(t *testing.T, ctx context.Context, kube client.Client, name string) *fleetAPIFixture {
	t.Helper()
	f := &fleetAPIFixture{kube: kube}
	roles := []string{"manage-realm", "manage-events", "manage-clients", "manage-identity-providers"}
	f.nativeRoles.Store(&roles)
	nativeVersion := "26.8.0"
	f.nativeVersion.Store(&nativeVersion)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.private = private
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/realms/") || strings.HasPrefix(req.URL.Path, "/admin/") {
			switch req.URL.Path {
			case "/realms/master/protocol/openid-connect/token":
				claims, _ := json.Marshal(map[string]any{"iss": "https://" + req.Host + "/realms/master", "azp": "fixture-writer", "iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(), "resource_access": map[string]any{name + "-realm": map[string]any{"roles": *f.nativeRoles.Load()}}})
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture", "expires_in": 600})
			case "/admin/serverinfo":
				_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": *f.nativeVersion.Load()}})
			case "/admin/realms/" + name:
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "fixture-realm-id", "realm": name})
			default:
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		if req.Header.Get("Authorization") != "Bearer fixture-fleet-credential" || req.Header.Get("X-Tenant-ID") != "fleet-tenant" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch req.URL.Path {
		case "/api/v1/bundles/latest":
			if req.Header.Get("Accept") != "application/vnd.hanko.fleet-plan+json" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			if callback := f.before.Swap(nil); callback != nil {
				(*callback)()
			}
			_, _ = w.Write(*f.envelope.Load())
		case "/api/v1/operators/status":
			var status hub.OperatorStatus
			if err := json.NewDecoder(req.Body).Decode(&status); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.reported.Store(&status)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(server.Close)
	now := time.Now().UTC().Truncate(time.Second)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "fleet-fixtures"}, Data: map[string][]byte{
		"hub_token": []byte("fixture-fleet-credential"), "tenant_id": []byte("fleet-tenant"), "cluster_id": []byte("fleet-cluster"), "expires_at": []byte(now.Add(12 * time.Hour).Format(time.RFC3339)),
	}}
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	f.tenant = &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: secret.Namespace}, Spec: api.HankoTenantSpec{RealmRef: name, HubTenantID: "fleet-tenant", HubEndpoint: server.URL, HubTokenSecretRef: corev1.LocalObjectReference{Name: secret.Name}}}
	if err := kube.Create(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	target := fleetplan.Target{Scope: fleetplan.Scope{TenantID: "fleet-tenant", ClusterID: "fleet-cluster", Namespace: f.tenant.Namespace, TenantName: name}, TenantUID: string(f.tenant.UID)}
	f.plan = fleetplan.Plan{Issuer: "fixture-publisher", KeyID: "key-1", Target: target, Source: fleetplan.Source{Repository: "example/config", Revision: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64)}, ContractVersion: string(iamcontract.Version), Sequence: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), Mode: "all-or-refuse", Content: fleetplan.Content{Realms: []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","metadata":{"name":%q,"namespace":"fleet-fixtures","labels":{"hanko.sh/tenant":%q}},"spec":{"otpRequired":true}}`, name, name))}}}
	trust := fleetplan.Trust{Version: fleetplan.TrustVersion, Keys: []fleetplan.Key{{ID: "key-1", Issuer: f.plan.Issuer, PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Scopes: []fleetplan.Scope{target.Scope}, Sources: []string{f.plan.Source.Repository}}}}
	raw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	f.trust = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.tenant.Namespace}, Data: map[string]string{"trust.json": string(raw)}}
	if err := kube.Create(ctx, f.trust); err != nil {
		t.Fatal(err)
	}
	f.writer = &fleetAPIWriter{Client: kube}
	kc, err := keycloak.NewWithTLS(server.URL, "fixture-writer", "fixture-provider-credential", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	f.r = &controller.HankoTenantReconciler{Client: f.writer, APIReader: kube, Pool: keycloak.NewPool(kc), HubHTTPClient: server.Client(), FleetTrustConfigMapName: f.trust.Name}
	f.sign(t)
	return f
}

func (f *fleetAPIFixture) sign(t *testing.T) {
	t.Helper()
	payload, err := json.Marshal(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fleetplan.Envelope{Version: fleetplan.EnvelopeVersion, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, fleetplan.SigningInput(payload)))})
	if err != nil {
		t.Fatal(err)
	}
	f.envelope.Store(&raw)
}

func (f *fleetAPIFixture) reconcile(ctx context.Context) error {
	_, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.tenant)})
	return err
}

func (f *fleetAPIFixture) read(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), f.tenant); err != nil {
		t.Fatal(err)
	}
}

func (f *fleetAPIFixture) expect(t *testing.T, ctx context.Context, reason string) {
	t.Helper()
	if err := f.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	f.read(t, ctx)
	found := false
	for _, c := range f.tenant.Status.Conditions {
		if c.Type == "Synced" && c.Reason == reason {
			found = true
		}
	}
	if !found {
		t.Fatalf("wanted %s; conditions: %+v", reason, f.tenant.Status.Conditions)
	}
	evidence := f.reported.Load()
	if evidence == nil || (f.tenant.Status.FleetPlan != nil && (evidence.FleetPlan == nil || evidence.FleetPlan.Identity != f.tenant.Status.FleetPlan.Identity)) {
		t.Fatal("bounded checkpoint evidence missing from heartbeat")
	}
}

func checkSignedFleetPlans(t *testing.T, ctx context.Context, kube client.Client) {
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "fleet-fixtures"}}); err != nil {
		t.Fatal(err)
	}
	t.Run("capability rollout and local overrides", func(t *testing.T) { checkFleetCapabilityRollout(t, ctx, kube) })
	t.Run("accepted-current-next-and-sticky-mode", func(t *testing.T) {
		f := newFleetAPIFixture(t, ctx, kube, "accepted")
		f.expect(t, ctx, "FleetPlanApplied")
		if f.tenant.Status.FleetPlan == nil || f.tenant.Status.FleetPlan.Identity != f.tenant.Status.FleetPlan.AppliedIdentity {
			t.Fatal("applied identity not durable")
		}
		realm := &api.HankoRealm{}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), realm); err != nil {
			t.Fatal(err)
		}
		uid, rv, identity := realm.UID, realm.ResourceVersion, f.tenant.Status.FleetPlan.Identity
		f.expect(t, ctx, "FleetPlanCurrent")
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), realm); err != nil {
			t.Fatal(err)
		}
		if realm.ResourceVersion != rv || f.writer.writes != 1 {
			t.Fatal("current plan replayed content writes")
		}
		f.plan.Sequence++
		f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"otpRequired":true`, `"otpRequired":false`, 1))
		f.sign(t)
		f.expect(t, ctx, "FleetPlanApplied")
		if err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), realm); err != nil {
			t.Fatal(err)
		}
		if realm.UID != uid || realm.Spec.OTPRequired || f.tenant.Status.FleetPlan.PreviousIdentity != identity {
			t.Fatal("higher sequence did not update conditionally")
		}
		f.r.FleetTrustConfigMapName = ""
		f.expect(t, ctx, "FleetLegacyDowngrade")
	})
	for _, stage := range []string{"accepted", "applied"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("checkpoint-%s-after-%t", stage, after), func(t *testing.T) {
				f := newFleetAPIFixture(t, ctx, kube, fmt.Sprintf("ack-%s-%t", stage, after))
				f.writer.failStage, f.writer.after = stage, after
				if err := f.reconcile(ctx); err == nil {
					t.Fatal("checkpoint failure swallowed")
				}
				if stage == "accepted" && f.writer.writes != 0 {
					t.Fatal("write preceded acknowledged acceptance")
				}
				f.expect(t, ctx, map[bool]string{true: "FleetPlanCurrent", false: "FleetPlanApplied"}[stage == "applied" && after])
				f.expect(t, ctx, "FleetPlanCurrent")
				if f.writer.writes != 1 {
					t.Fatal("retry duplicated content")
				}
				f.plan.Sequence++ // Prove the ratchet survives a fresh reconciler.
				f.sign(t)
				f.expect(t, ctx, "FleetPlanApplied")
				checkpoint := *f.tenant.Status.FleetPlan
				f.plan.Sequence--
				f.sign(t)
				f.r = &controller.HankoTenantReconciler{Client: f.writer, APIReader: kube, Pool: f.r.Pool, HubHTTPClient: f.r.HubHTTPClient, FleetTrustConfigMapName: f.trust.Name}
				f.expect(t, ctx, "FleetPlanDowngrade")
				if !reflect.DeepEqual(checkpoint, *f.tenant.Status.FleetPlan) {
					t.Fatal("restart downgraded checkpoint")
				}
			})
		}
	}
	for _, boundary := range []string{"signature", "expired", "tenant", "cluster", "namespace", "tenant-uid", "key", "source", "unknown-field", "approval", "finalizer", "foreign-object", "conflicting-sequence", "trust-change", "intent-change"} {
		t.Run("refuse-"+boundary, func(t *testing.T) {
			f := newFleetAPIFixture(t, ctx, kube, "refuse-"+boundary)
			reason := "FleetIssuerAuthorityMismatch"
			var checkpoint *api.FleetPlanStatus
			switch boundary {
			case "signature":
				f.private = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				reason = "FleetSignatureInvalid"
			case "expired":
				f.plan.ExpiresAt = time.Now().Add(-time.Minute)
				f.plan.IssuedAt = f.plan.ExpiresAt.Add(-time.Minute)
				f.plan.NotBefore = f.plan.IssuedAt
				reason = "FleetPlanExpired"
			case "tenant":
				f.plan.Target.TenantID = "other"
			case "cluster":
				f.plan.Target.ClusterID = "other"
			case "namespace":
				f.plan.Target.Namespace = "other"
			case "tenant-uid":
				f.plan.Target.TenantUID = "other"
				reason = "FleetTargetMismatch"
			case "key":
				f.plan.KeyID = "unapproved"
				reason = "FleetKeyUnapproved"
			case "source":
				f.plan.Source.Repository = "other/config"
			case "unknown-field":
				f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"otpRequired":true`, `"unknown":true`, 1))
				reason = "FleetContentInvalid"
			case "approval":
				f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"labels":`, `"annotations":{"hanko.sh/adoption-approved":"true"},"labels":`, 1))
				reason = "FleetContentAuthorityInvalid"
			case "finalizer":
				f.plan.Content.Realms[0] = json.RawMessage(strings.Replace(string(f.plan.Content.Realms[0]), `"labels":`, `"finalizers":["foreign/retain"],"labels":`, 1))
				reason = "FleetContentInvalid"
			case "foreign-object":
				if err := kube.Create(ctx, &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: f.tenant.Name, Namespace: f.tenant.Namespace, Labels: map[string]string{"hanko.sh/tenant": "other"}}}); err != nil {
					t.Fatal(err)
				}
				reason = "BundleTenantConflict"
			case "conflicting-sequence":
				f.expect(t, ctx, "FleetPlanApplied")
				checkpoint = f.tenant.Status.FleetPlan.DeepCopy()
				f.plan.Source.Revision = strings.Repeat("c", 40)
				reason = "FleetSequenceConflict"
			case "trust-change":
				callback := func() {
					live := f.trust.DeepCopy()
					live.Data["approval-change"] = "rotated"
					if err := kube.Update(ctx, live); err != nil {
						t.Error(err)
					}
				}
				f.before.Store(&callback)
				reason = "FleetTrustChanged"
			case "intent-change":
				callback := func() {
					live := f.tenant.DeepCopy()
					if err := kube.Get(ctx, client.ObjectKeyFromObject(live), live); err != nil {
						t.Error(err)
						return
					}
					live.Spec.RealmRef = "changed"
					if err := kube.Update(ctx, live); err != nil {
						t.Error(err)
					}
				}
				f.before.Store(&callback)
				reason = "FleetAuthorityChanged"
			}
			f.sign(t)
			writes := f.writer.writes
			if boundary == "intent-change" {
				if err := f.reconcile(ctx); fleetplan.Reason(err) != reason {
					t.Fatalf("changed intent not fenced: %v", err)
				}
				f.read(t, ctx)
			} else {
				f.expect(t, ctx, reason)
			}
			if f.writer.writes != writes || !reflect.DeepEqual(f.tenant.Status.FleetPlan, checkpoint) {
				t.Fatal("refusal wrote content or changed durable acceptance")
			}
			if boundary != "foreign-object" && checkpoint == nil {
				err := kube.Get(ctx, client.ObjectKeyFromObject(f.tenant), &api.HankoRealm{})
				if !apierrors.IsNotFound(err) {
					t.Fatalf("refused content exists: %v", err)
				}
			}
		})
	}
}

func checkFleetTrustAdmission(t *testing.T, ctx context.Context, admin client.Client, environment *envtest.Environment, config *rest.Config) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "security", "fleet-plan-trust-admission.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(data), "\n---\n")
	if len(parts) != 2 {
		t.Fatal("trust admission pattern must contain policy and binding")
	}
	policy, binding := &admissionv1.ValidatingAdmissionPolicy{}, &admissionv1.ValidatingAdmissionPolicyBinding{}
	if err := yaml.UnmarshalStrict([]byte(parts[0]), policy); err != nil {
		t.Fatal(err)
	}
	if err := yaml.UnmarshalStrict([]byte(parts[1]), binding); err != nil {
		t.Fatal(err)
	}
	for _, obj := range []client.Object{policy, binding,
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "fleet-trust-writer", Namespace: "auth"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "create", "update", "patch", "delete"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "fleet-trust-writer", Namespace: "auth"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "fleet-trust-writer"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "fleet-cr-author", APIGroup: rbacv1.GroupName}}},
	} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	user, err := environment.AddUser(envtest.User{Name: "fleet-cr-author", Groups: []string{"system:authenticated"}}, config)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := client.New(user.Config(), client.Options{Scheme: admin.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "hanko-fleet-plan-trust", Namespace: "auth"}, Data: map[string]string{"trust.json": "fixture-public-keys"}}
	if err := admin.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	// Prove RBAC grants ordinary ConfigMap writes, then wait only for policy
	// cache propagation. A broad RBAC denial cannot stand in for this policy.
	if err := writer.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "ordinary-fleet-data", Namespace: "auth"}}, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		probe := cm.DeepCopy()
		probe.Data["changed"] = "yes"
		err = writer.Update(ctx, probe, client.DryRunAll)
		if apierrors.IsForbidden(err) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("fleet trust policy did not deny ordinary writer: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			probe := cm.DeepCopy()
			switch operation {
			case "create":
				probe.ResourceVersion = ""
				probe.UID = ""
				err = writer.Create(ctx, probe, client.DryRunAll)
			case "update":
				probe.Data["changed"] = "yes"
				err = writer.Update(ctx, probe, client.DryRunAll)
			case "delete":
				err = writer.Delete(ctx, probe, client.DryRunAll)
			}
			if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "independent local fleet policy administrators") {
				t.Fatalf("trust %s was not denied by local approval policy: %v", operation, err)
			}
		})
	}
	cm.Data["rotated"] = "locally-approved"
	if err := admin.Update(ctx, cm); err != nil {
		t.Fatalf("independent administrator could not rotate trust: %v", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.TypeChecking != nil && len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
		t.Fatalf("trust policy has CEL warnings: %+v", policy.Status.TypeChecking)
	}
}
