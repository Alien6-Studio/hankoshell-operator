//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errImportAck = errors.New("injected import status acknowledgement failure")

type importRecoveryClient struct {
	client.Client
	createError                                 error
	statusAt, statusWrites, creates, candidates int
	after                                       bool
	before                                      func()
}

func (c *importRecoveryClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.creates++
	if c.createError != nil {
		return c.createError
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *importRecoveryClient) Status() client.SubResourceWriter {
	return importRecoveryStatus{SubResourceWriter: c.Client.Status(), parent: c}
}

type importRecoveryStatus struct {
	client.SubResourceWriter
	parent *importRecoveryClient
}

func (s importRecoveryStatus) write(obj client.Object, write func() error) error {
	if _, ok := obj.(*api.HankoImport); !ok {
		s.parent.candidates++
		return write()
	}
	s.parent.statusWrites++
	fail := s.parent.statusAt == s.parent.statusWrites
	if fail && s.parent.before != nil {
		s.parent.before()
		return write()
	}
	if fail && !s.parent.after {
		return errImportAck
	}
	if err := write(); err != nil {
		return err
	}
	if fail {
		return errImportAck
	}
	return nil
}

func (s importRecoveryStatus) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return s.write(obj, func() error { return s.SubResourceWriter.Update(ctx, obj, opts...) })
}

func (s importRecoveryStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return s.write(obj, func() error { return s.SubResourceWriter.Patch(ctx, obj, patch, opts...) })
}

func importRecoveryFixture(t *testing.T, ctx context.Context, kube client.Client, suffix string, dryRun bool) (*api.HankoImport, *api.HankoApplication, *atomic.Int32) {
	t.Helper()
	namespace := "import-recovery-" + suffix
	reads := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPost && req.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
			return
		}
		if req.Method != http.MethodGet {
			t.Errorf("import attempted provider mutation: %s %s", req.Method, req.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads.Add(1)
		providerClient := map[string]any{"id": "client-id", "clientId": "portal", "protocol": "openid-connect", "enabled": true, "publicClient": true, "standardFlowEnabled": true}
		switch req.URL.Path {
		case "/admin/realms":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": "realm-id", "realm": "imported", "enabled": true}})
		case "/admin/realms/imported":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "realm-id", "realm": "imported", "organizationsEnabled": false})
		case "/admin/realms/imported/clients":
			if first := req.URL.Query().Get("first"); first != "" && first != "0" {
				_ = json.NewEncoder(w).Encode([]any{})
				return
			}
			_ = json.NewEncoder(w).Encode([]any{providerClient})
		case "/admin/realms/imported/clients/client-id":
			_ = json.NewEncoder(w).Encode(providerClient)
		case "/admin/realms/imported/roles":
			// Preserve a partial inventory report through the discovery checkpoint.
			w.WriteHeader(http.StatusForbidden)
		default:
			_ = json.NewEncoder(w).Encode([]any{})
		}
	}))
	t.Cleanup(server.Close)
	includeBrokers := false
	operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: namespace}, Spec: api.HankoImportSpec{SourceRef: "source", DryRun: dryRun, IncludeIdentityProviders: &includeBrokers}}
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: namespace, Labels: map[string]string{"hanko.sh/imported-by": operation.Name}}, Spec: api.HankoApplicationSpec{RealmRef: "imported", ClientID: "portal", Type: "spa", Mode: "Observe"}}
	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: namespace}, Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("reader"), "HANKO_KC_CLIENT_SECRET": []byte("fixture-secret")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: namespace}, Data: map[string][]byte{"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}},
		&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: namespace}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
		operation, app,
	} {
		if err := kube.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	return operation, app, reads
}

func importAPIReconcile(ctx context.Context, kube client.Client, reader client.Reader, operation *api.HankoImport) error {
	r := &controller.HankoImportReconciler{Client: kube, APIReader: reader, RequireHTTPS: true}
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)})
	return err
}

func checkImportRecovery(t *testing.T, ctx context.Context, kube client.Client) {
	t.Run("target-creation-failure", func(t *testing.T) {
		op, _, _ := importRecoveryFixture(t, ctx, kube, "failed-create", false)
		wrapped := &importRecoveryClient{Client: kube, createError: errors.New("target create unavailable")}
		if err := importAPIReconcile(ctx, wrapped, kube, op); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
			t.Fatal(err)
		}
		condition := meta.FindStatusCondition(op.Status.Conditions, "ImportReady")
		if op.Status.Phase != "Failed" || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "PartialFailure" || wrapped.creates != 1 {
			t.Fatal("target creation failure was reported as successful completion")
		}
	})
	for _, dryRun := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			for stage := 1; stage <= 3; stage++ {
				t.Run(fmt.Sprintf("status-%d-after-%t-dry-%t", stage, after, dryRun), func(t *testing.T) {
					op, app, reads := importRecoveryFixture(t, ctx, kube, fmt.Sprintf("%d-%t-%t", stage, after, dryRun), dryRun)
					if stage == 1 && !after {
						// Legacy Applying status may contain counts from a prior attempt.
						op.Status = api.HankoImportStatus{Phase: "Applying", Applied: api.ImportCounts{Realms: 9}, Skipped: api.ImportCounts{Applications: 7}}
						if err := kube.Status().Update(ctx, op); err != nil {
							t.Fatal(err)
						}
					}
					wrapped := &importRecoveryClient{Client: kube, statusAt: stage, after: after}
					if err := importAPIReconcile(ctx, wrapped, kube, op); !errors.Is(err, errImportAck) {
						t.Fatalf("status failure was swallowed: %v", err)
					}
					if stage < 3 && (wrapped.creates != 0 || wrapped.candidates != 0) {
						t.Fatal("target creation or evidence publication preceded acknowledged discovery")
					}
					if stage == 1 && reads.Load() != 0 {
						t.Fatal("discovery preceded acknowledged initialization")
					}
					if stage == 2 && after {
						checkpoint := &api.HankoImport{}
						if err := kube.Get(ctx, client.ObjectKeyFromObject(op), checkpoint); err != nil {
							t.Fatal(err)
						}
						if len(checkpoint.Status.Inventory) != 2 || checkpoint.Status.Coverage.Complete || !meta.IsStatusConditionFalse(checkpoint.Status.Conditions, "InventoryComplete") {
							t.Fatal("discovery checkpoint lost the bounded incomplete inventory report")
						}
					}
					readCount := reads.Load()
					wrapped.statusAt = 0
					if err := importAPIReconcile(ctx, wrapped, kube, op); err != nil {
						t.Fatal("fresh reconciler failed to recover", err)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
						t.Fatal(err)
					}
					if op.Status.Phase != "Done" || !meta.IsStatusConditionTrue(op.Status.Conditions, "ImportReady") {
						t.Fatalf("unexpected terminal status: %+v", op.Status)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil || app.Status.AdoptionCandidate == nil {
						t.Fatal("recovery did not publish target evidence", err)
					}
					wantCreates := 1
					if dryRun {
						wantCreates = 0
					}
					if wrapped.creates != wantCreates {
						t.Fatalf("retry duplicated target creation: %d, want %d", wrapped.creates, wantCreates)
					}
					if !dryRun && (op.Status.Applied.Realms+op.Status.Skipped.Realms != 1 || op.Status.Skipped.Applications != 1) {
						t.Fatalf("retry accumulated obsolete attempt counts: %+v", op.Status)
					}
					if stage == 3 && after && reads.Load() != readCount {
						t.Fatal("lost completion acknowledgement repeated terminal discovery")
					}
				})
			}
		}
	}
	for _, dryRun := range []bool{false, true} {
		for _, change := range []string{"spec", "tenant", "deletion", "replacement", "failure", "completion"} {
			t.Run(fmt.Sprintf("concurrent-%s-dry-%t", change, dryRun), func(t *testing.T) {
				op, app, _ := importRecoveryFixture(t, ctx, kube, fmt.Sprintf("%s-%t", change, dryRun), dryRun)
				wrapped := &importRecoveryClient{Client: kube, statusAt: 2, before: func() {
					if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil {
						t.Fatal(err)
					}
					switch change {
					case "spec", "completion":
						op.Spec.SourceRef = "changed-source"
					case "tenant":
						op.Labels = map[string]string{"hanko.sh/tenant": "changed"}
					case "deletion":
						op.Finalizers = []string{"fixture.example/hold"}
					case "replacement":
						if err := kube.Delete(ctx, op); err != nil {
							t.Fatal(err)
						}
						op.ObjectMeta = metav1.ObjectMeta{Name: op.Name, Namespace: op.Namespace}
						if err := kube.Create(ctx, op); err != nil {
							t.Fatal(err)
						}
						return
					case "failure":
						op.Status.Phase = "Failed"
						if err := kube.Status().Update(ctx, op); err != nil {
							t.Fatal(err)
						}
						return
					}
					if err := kube.Update(ctx, op); err != nil {
						t.Fatal(err)
					}
					if change == "deletion" {
						if err := kube.Delete(ctx, op); err != nil {
							t.Fatal(err)
						}
					}
				}}
				if change == "completion" {
					wrapped.statusAt = 3
				}
				if err := importAPIReconcile(ctx, wrapped, kube, op); !apierrors.IsConflict(err) {
					t.Fatalf("stale discovery was not refused: %v", err)
				}
				if change == "completion" {
					if err := kube.Get(ctx, client.ObjectKeyFromObject(op), op); err != nil || op.Status.Phase == "Done" || meta.IsStatusConditionTrue(op.Status.Conditions, "ImportReady") {
						t.Fatal("concurrent edit accepted stale completion", err)
					}
					return
				}
				if wrapped.creates != 0 || wrapped.candidates != 0 {
					t.Fatal("stale import created targets or published evidence")
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil || app.Status.AdoptionCandidate != nil {
					t.Fatal("stale evidence reached a target", err)
				}
				if change == "deletion" {
					if err := importAPIReconcile(ctx, wrapped, kube, op); err != nil || wrapped.statusWrites != 2 {
						t.Fatal("deleting import resumed work", err)
					}
				}
			})
		}
	}
}
