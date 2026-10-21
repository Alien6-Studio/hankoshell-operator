//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Exercise the reconciler against served CRDs: a fake Kubernetes client does
// not reject merge patches missing the required false-valued coverage fields.
func checkInitialImportStatus(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	for _, tc := range []struct {
		name          string
		missingSource bool
		denyDiscovery bool
	}{
		{name: "partial"},
		{name: "missing-source", missingSource: true},
		{name: "discovery-denied", denyDiscovery: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			namespace := "import-status-" + tc.name
			if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
				t.Fatal(err)
			}
			var reads, deniedRoles, writes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token" {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "import-private-token", "expires_in": 300})
					return
				}
				if r.Method != http.MethodGet {
					writes.Add(1)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				reads.Add(1)
				switch r.URL.Path {
				case "/admin/realms":
					if tc.denyDiscovery {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": "realm-uuid", "realm": "imported", "enabled": true}})
				case "/admin/realms/imported":
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "realm-uuid", "realm": "imported", "organizationsEnabled": false})
				case "/admin/realms/imported/clients", "/admin/realms/imported/groups":
					_ = json.NewEncoder(w).Encode([]any{})
				case "/admin/realms/imported/roles":
					deniedRoles.Add(1)
					w.WriteHeader(http.StatusForbidden)
				default:
					t.Errorf("unexpected inventory request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			if !tc.missingSource {
				objects := []client.Object{
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: namespace}, Data: map[string][]byte{
						"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("inventory-reader"), "HANKO_KC_CLIENT_SECRET": []byte("import-private-secret"),
					}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader-ca", Namespace: namespace}, Data: map[string][]byte{
						"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
					}},
					&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: namespace}, Spec: api.HankoKeycloakInstanceSpec{
						Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "reader-ca",
					}},
				}
				for _, object := range objects {
					if err := kube.Create(ctx, object); err != nil {
						t.Fatal(err)
					}
				}
			}
			includeBrokers := false
			operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: namespace}, Spec: api.HankoImportSpec{
				SourceRef: "source", Realms: []string{"imported"}, DryRun: true, IncludeIdentityProviders: &includeBrokers,
			}}
			if err := kube.Create(ctx, operation); err != nil {
				t.Fatal(err)
			}
			raw := &unstructured.Unstructured{}
			raw.SetGroupVersionKind(api.GroupVersion.WithKind("HankoImport"))
			key := client.ObjectKeyFromObject(operation)
			if err := kube.Get(ctx, key, raw); err != nil {
				t.Fatal(err)
			}
			if _, present := raw.Object["status"]; present {
				t.Fatal("fixture must begin with no persisted status")
			}
			reconciler := &controller.HankoImportReconciler{Client: kube, APIReader: kube, RequireHTTPS: true}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, key, raw); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"complete", "truncated"} {
				value, present, err := unstructured.NestedBool(raw.Object, "status", "coverage", field)
				if err != nil || !present || value {
					t.Fatalf("required coverage.%s must be persisted as false", field)
				}
			}
			if err := kube.Get(ctx, key, operation); err != nil {
				t.Fatal(err)
			}
			wantPhase := "Failed"
			if !tc.missingSource && !tc.denyDiscovery {
				wantPhase = "Done"
				if deniedRoles.Load() == 0 || operation.Status.Coverage.InventoryCount == 0 || operation.Status.CompletedAt == nil {
					t.Fatal("partial dry-run did not retain its incomplete inventory report")
				}
			}
			if operation.Status.Phase != wantPhase || len(operation.Finalizers) != 0 || len(operation.Annotations) != 0 || writes.Load() != 0 {
				t.Fatal("import status or read-only authority changed", operation.Status.Phase)
			}
			for _, item := range operation.Status.Inventory {
				if item.Complete || item.Approvable {
					t.Fatal("incomplete discovery granted adoption authority")
				}
			}
			for _, kind := range []string{"HankoRealmList", "HankoApplicationList", "HankoServiceAccountList"} {
				list := &unstructured.UnstructuredList{}
				list.SetGroupVersionKind(api.GroupVersion.WithKind(kind))
				if err := kube.List(ctx, list, client.InNamespace(namespace)); err != nil || len(list.Items) != 0 {
					t.Fatalf("dry-run created target objects: %s", kind)
				}
			}
			encoded, err := json.Marshal(operation.Status)
			if err != nil || strings.Contains(string(encoded), "import-private-") {
				t.Fatal("status serialization failed or exposed private inventory credentials")
			}
			readCount, revision := reads.Load(), operation.ResourceVersion
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(ctx, key, operation); err != nil || operation.ResourceVersion != revision || reads.Load() != readCount {
				t.Fatal("terminal import repeated discovery or status writes")
			}
		})
	}
}
