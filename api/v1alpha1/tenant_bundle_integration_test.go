//go:build integration

package v1alpha1_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type bundleWriteFixture struct {
	client.Client
	beforeCreate  func()
	beforeApply   func()
	beforePatch   func()
	lostPatchAck  bool
	lostCreateAck bool
}

func (c *bundleWriteFixture) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.beforeCreate != nil {
		f := c.beforeCreate
		c.beforeCreate = nil
		f()
	}
	err := c.Client.Create(ctx, obj, opts...)
	if err == nil && c.lostCreateAck {
		c.lostCreateAck = false
		return errors.New("fixture lost creation acknowledgement")
	}
	return err
}

func (c *bundleWriteFixture) Apply(ctx context.Context, configuration runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	if c.beforeApply != nil {
		f := c.beforeApply
		c.beforeApply = nil
		f()
	}
	return c.Client.Apply(ctx, configuration, opts...)
}

func (c *bundleWriteFixture) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if c.beforePatch != nil {
		f := c.beforePatch
		c.beforePatch = nil
		f()
	}
	err := c.Client.Patch(ctx, obj, patch, opts...)
	if err == nil && c.lostPatchAck {
		c.lostPatchAck = false
		return errors.New("fixture lost ownership transition acknowledgement")
	}
	return err
}

func checkTenantBundleBoundary(t *testing.T, ctx context.Context, kube client.Client) {
	const ns, token = "bundle-boundary", "fixture-bundle-credential"
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[hub.Bundle]
	var reported atomic.Pointer[hub.OperatorStatus]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+token || req.Header.Get("X-Tenant-ID") != "hub-tenant" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch req.URL.Path {
		case "/api/v1/bundles/latest":
			bundle := active.Load()
			payload, _ := json.Marshal(bundle)
			key := sha256.Sum256([]byte(token))
			mac := hmac.New(sha256.New, key[:])
			_, _ = mac.Write(payload)
			_ = json.NewEncoder(w).Encode(hub.SignedBundle{Bundle: *bundle, Signature: hex.EncodeToString(mac.Sum(nil))})
		case "/api/v1/operators/status":
			var status hub.OperatorStatus
			if err := json.NewDecoder(req.Body).Decode(&status); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reported.Store(&status)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "hub-token", Namespace: ns}, Data: map[string][]byte{
		"hub_token": []byte(token), "expires_at": []byte(time.Now().Add(12 * time.Hour).UTC().Format(time.RFC3339Nano)),
	}}
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Namespace: ns}, Spec: api.HankoTenantSpec{
		IsolationMode: "realm", HubEndpoint: server.URL, HubTenantID: "hub-tenant", HubTokenSecretRef: corev1.LocalObjectReference{Name: secret.Name},
	}}
	if err := kube.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	writer := &bundleWriteFixture{Client: kube}
	r := &controller.HankoTenantReconciler{Client: writer, APIReader: kube, Pool: keycloak.NewPool(nil), HubHTTPClient: server.Client()}
	sequence := 0
	apply := func(t *testing.T, raws []json.RawMessage, wantReason string) {
		t.Helper()
		sequence++
		bundle := &hub.Bundle{Version: fmt.Sprintf("v%d", sequence), TenantID: "hub-tenant", Realms: raws}
		active.Store(bundle)
		reported.Store(nil)
		result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tenant)})
		if err != nil || result.RequeueAfter == 0 {
			t.Fatalf("reconcile: %v %v", result, err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, condition := range tenant.Status.Conditions {
			if condition.Type == "Synced" && condition.Reason == wantReason {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("wanted %s, got %+v", wantReason, tenant.Status.Conditions)
		}
		if wantReason != "BundleApplied" {
			status := reported.Load()
			if tenant.Status.Phase != "Error" || tenant.Status.BundleVersion == bundle.Version || status == nil || status.Detail != wantReason || status.Phase != "Error" {
				t.Fatalf("refusal not persisted/reported without promoting bundle: %+v %+v", tenant.Status, status)
			}
		} else if tenant.Status.Phase != "Synced" || tenant.Status.BundleVersion != bundle.Version {
			t.Fatal("successful bundle not recorded")
		}
	}
	raw := func(name string, otp bool) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"metadata":{"name":%q},"spec":{"otpRequired":%t,"securityProfile":{"passwordExpiryDays":0}}}`, name, otp))
	}
	get := func(t *testing.T, name string) *api.HankoRealm {
		t.Helper()
		obj := &api.HankoRealm{}
		if err := kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
			t.Fatal(err)
		}
		return obj
	}
	create := func(t *testing.T, name, owner string) *api.HankoRealm {
		t.Helper()
		obj := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"hanko.sh/tenant": owner}}}
		if err := kube.Create(ctx, obj, client.FieldOwner("local-administrator")); err != nil {
			t.Fatal(err)
		}
		return obj
	}
	t.Run("create-update-explicit-values-and-local-metadata", func(t *testing.T) {
		apply(t, []json.RawMessage{raw("owned", true)}, "BundleApplied")
		obj := get(t, "owned")
		obj.Finalizers = []string{"fixture.test/retain"}
		obj.Annotations = map[string]string{"hanko.sh/adoption-candidate": "local-only"}
		obj.OwnerReferences = []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoTenant", Name: tenant.Name, UID: tenant.UID}}
		if err := kube.Update(ctx, obj, client.FieldOwner("local-administrator")); err != nil {
			t.Fatal(err)
		}
		apply(t, []json.RawMessage{raw("owned", false)}, "BundleApplied")
		obj = get(t, "owned")
		if obj.Spec.OTPRequired || obj.Labels["hanko.sh/tenant"] != tenant.Name || obj.Annotations["hanko.sh/adoption-candidate"] != "local-only" || len(obj.Finalizers) != 1 || len(obj.OwnerReferences) != 1 {
			t.Fatal("update lost explicit false, local approval or lifecycle metadata")
		}
		for _, fields := range obj.ManagedFields {
			if fields.Manager == "hanko-hub-bundle" && fields.FieldsV1 != nil {
				var owned map[string]any
				if err := json.Unmarshal(fields.FieldsV1.GetRawBytes(), &owned); err != nil {
					t.Fatal(err)
				}
				metadata, _ := owned["f:metadata"].(map[string]any)
				if metadata["f:annotations"] != nil || metadata["f:finalizers"] != nil || metadata["f:ownerReferences"] != nil {
					t.Fatal("bundle claimed local metadata ownership")
				}
			}
		}
	})
	t.Run("foreign-and-unassigned-targets-block-entire-bundle", func(t *testing.T) {
		for i, owner := range []string{"tenant-b", ""} {
			name := fmt.Sprintf("foreign-%d", i)
			original := create(t, name, owner)
			first := fmt.Sprintf("must-not-create-%d", i)
			apply(t, []json.RawMessage{raw(first, false), raw(name, true)}, "BundleTenantConflict")
			current := get(t, name)
			if current.ResourceVersion != original.ResourceVersion || current.Spec.OTPRequired {
				t.Fatal("foreign target was changed")
			}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: first}, &api.HankoRealm{}); !apierrors.IsNotFound(err) {
				t.Fatalf("preflight wrote first resource: %v", err)
			}
		}
	})
	t.Run("payload-cannot-grant-local-approval", func(t *testing.T) {
		apply(t, []json.RawMessage{raw("approval-first", false), json.RawMessage(`{"metadata":{"name":"injected","annotations":{"hanko.sh/adoption-candidate":"remote"}}}`)}, "BundleMetadataInvalid")
		if err := kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: "approval-first"}, &api.HankoRealm{}); !apierrors.IsNotFound(err) {
			t.Fatalf("invalid payload caused writes: %v", err)
		}
	})
	t.Run("local-field-conflict-never-forced", func(t *testing.T) {
		original := create(t, "local-fields", tenant.Name)
		original.Spec.OTPRequired = true
		if err := kube.Update(ctx, original, client.FieldOwner("local-administrator")); err != nil {
			t.Fatal(err)
		}
		apply(t, []json.RawMessage{raw(original.Name, false)}, "BundleObjectConflict")
		if get(t, original.Name).ResourceVersion != original.ResourceVersion {
			t.Fatal("local fields overwritten")
		}
	})
	t.Run("legacy-manager-metadata-is-not-pruned", func(t *testing.T) {
		obj := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: ns, Labels: map[string]string{"hanko.sh/tenant": tenant.Name}, Finalizers: []string{"fixture.test/retain"}, Annotations: map[string]string{"hanko.sh/adoption-candidate": "local-only"}}}
		obj.Spec.OTPRequired = true
		if err := kube.Create(ctx, obj, client.FieldOwner("hanko-operator")); err != nil {
			t.Fatal(err)
		}
		apply(t, []json.RawMessage{raw(obj.Name, true)}, "BundleApplied")
		got := get(t, obj.Name)
		if len(got.Finalizers) != 1 || got.Annotations["hanko.sh/adoption-candidate"] != "local-only" {
			t.Fatal("legacy local metadata pruned")
		}
		apply(t, []json.RawMessage{raw(obj.Name, false)}, "BundleObjectConflict")
	})
	t.Run("creation-race-does-not-upsert", func(t *testing.T) {
		writer.beforeCreate = func() { create(t, "creation-race", "tenant-b") }
		apply(t, []json.RawMessage{raw("creation-race", true)}, "BundleObjectConflict")
		got := get(t, "creation-race")
		if got.Labels["hanko.sh/tenant"] != "tenant-b" || got.Spec.OTPRequired {
			t.Fatal("concurrently created target overwritten")
		}
	})
	for _, race := range []string{"transfer", "replace", "delete", "edit"} {
		t.Run("update-race-"+race, func(t *testing.T) {
			name := "race-" + race
			apply(t, []json.RawMessage{raw(name, false)}, "BundleApplied")
			original := get(t, name)
			writer.beforeApply = func() {
				obj := get(t, name)
				switch race {
				case "transfer":
					obj.Labels["hanko.sh/tenant"] = "tenant-b"
				case "edit":
					obj.Annotations = map[string]string{"example.org/local": "changed"}
				case "replace", "delete":
					if err := kube.Delete(ctx, obj); err != nil {
						t.Fatal(err)
					}
					if race == "replace" {
						create(t, name, "tenant-b")
					}
					return
				}
				if err := kube.Update(ctx, obj); err != nil {
					t.Fatal(err)
				}
			}
			apply(t, []json.RawMessage{raw(name, true)}, "BundleObjectConflict")
			if race == "delete" {
				if err := kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &api.HankoRealm{}); !apierrors.IsNotFound(err) {
					t.Fatalf("deleted object recreated: %v", err)
				}
				return
			}
			got := get(t, name)
			if got.Spec.OTPRequired || (race == "replace" && got.UID == original.UID) || (race == "transfer" && got.Labels["hanko.sh/tenant"] != "tenant-b") {
				t.Fatal("concurrent target overwritten")
			}
		})
	}
	t.Run("creation-ownership-transition-is-conditional", func(t *testing.T) {
		writer.beforePatch = func() {
			obj := get(t, "transition-race")
			obj.Labels["hanko.sh/tenant"] = "tenant-b"
			obj.Annotations = map[string]string{"hanko.sh/adoption-candidate": "local-only"}
			if err := kube.Update(ctx, obj, client.FieldOwner("local-administrator")); err != nil {
				t.Fatal(err)
			}
		}
		apply(t, []json.RawMessage{raw("transition-race", true)}, "BundleObjectConflict")
		got := get(t, "transition-race")
		if got.Labels["hanko.sh/tenant"] != "tenant-b" || got.Annotations["hanko.sh/adoption-candidate"] != "local-only" {
			t.Fatal("ownership transition overwrote concurrent local metadata")
		}
		apply(t, []json.RawMessage{raw("transition-race", true)}, "BundleTenantConflict")
	})
	t.Run("lost-transition-ack-retains-field-ownership", func(t *testing.T) {
		writer.lostPatchAck = true
		apply(t, []json.RawMessage{raw("transition-ack", true)}, "BundleApplyFailed")
		original := get(t, "transition-ack")
		apply(t, []json.RawMessage{raw("transition-ack", false)}, "BundleApplied")
		got := get(t, "transition-ack")
		if got.UID != original.UID || got.Spec.OTPRequired {
			t.Fatal("transition retry did not preserve UID and update owned field")
		}
	})
	t.Run("lost-create-ack-retries-existing-object", func(t *testing.T) {
		writer.lostCreateAck = true
		apply(t, []json.RawMessage{raw("lost-ack", true)}, "BundleApplyFailed")
		original := get(t, "lost-ack")
		apply(t, []json.RawMessage{raw("lost-ack", true)}, "BundleApplied")
		if get(t, "lost-ack").UID != original.UID {
			t.Fatal("retry replaced created resource")
		}
	})
}
