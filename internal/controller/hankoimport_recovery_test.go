package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestImportFailureStatusErrorsAreRetried(t *testing.T) {
	for _, reason := range []string{"SourceNotFound", "KCClientError", "ListRealmsError", "ListAppsError"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-after-%t", reason, after), func(t *testing.T) {
				ctx := context.Background()
				op := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "test"}, Spec: api.HankoImportSpec{SourceRef: "source"}}
				kube := fake.NewClientBuilder().WithScheme(controllerTestScheme(t)).WithStatusSubresource(op).WithObjects(op).Build()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					switch req.URL.Path {
					case "/realms/master/protocol/openid-connect/token":
						_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token", "expires_in": 300})
					case "/admin/realms":
						if reason == "ListAppsError" {
							_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": "realm-id", "realm": "imported"}})
							return
						}
						w.WriteHeader(http.StatusForbidden)
					default:
						w.WriteHeader(http.StatusForbidden)
					}
				}))
				t.Cleanup(server.Close)
				if reason != "SourceNotFound" {
					provisionImportTestSource(t, kube, op, server.URL)
				}
				failure := errors.New("injected failure status acknowledgement error")
				blocked := interceptor.NewClient(kube, interceptor.Funcs{
					SubResourcePatch: func(ctx context.Context, c client.Client, subresource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						if subresource != "status" {
							t.Fatal("unexpected non-status patch")
						}
						if after {
							if err := c.Status().Patch(ctx, obj, patch, opts...); err != nil {
								return err
							}
						}
						return failure
					},
				})
				r := &HankoImportReconciler{Client: blocked, APIReader: kube, RequireHTTPS: reason == "KCClientError"}
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}
				if _, err := r.Reconcile(ctx, req); !errors.Is(err, failure) {
					t.Fatal("failure status error was swallowed", err)
				}
				// A new reconciler either resumes recording the failure or observes
				// that the failed status was persisted despite a lost acknowledgement.
				r = &HankoImportReconciler{Client: kube, APIReader: kube, RequireHTTPS: reason == "KCClientError"}
				_, _ = r.Reconcile(ctx, req)
				if err := kube.Get(ctx, req.NamespacedName, op); err != nil {
					t.Fatal(err)
				}
				condition := meta.FindStatusCondition(op.Status.Conditions, "ImportReady")
				if op.Status.Phase != "Failed" || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != reason {
					t.Fatalf("failure did not recover: %+v", op.Status)
				}
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatal("terminal failure was not stable", err)
				}
			})
		}
	}
}

func TestImportPartialApplyCannotReportReady(t *testing.T) {
	op := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "partial", Namespace: "test"}, Status: api.HankoImportStatus{Phase: "Applying"}}
	kube := controllerTestClient(controllerTestScheme(t), op)
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(op), op); err != nil {
		t.Fatal(err)
	}
	r := &HankoImportReconciler{Client: kube}
	patch := client.MergeFromWithOptions(op.DeepCopy(), client.MergeFromWithOptimisticLock{})
	if _, err := r.completeImport(context.Background(), op, []string{"target creation failed"}, patch); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(op), op); err != nil {
		t.Fatal(err)
	}
	if op.Status.Phase != "Failed" || !meta.IsStatusConditionFalse(op.Status.Conditions, "ImportReady") || op.Status.CompletedAt == nil {
		t.Fatal("partial apply reported successful completion")
	}
}
