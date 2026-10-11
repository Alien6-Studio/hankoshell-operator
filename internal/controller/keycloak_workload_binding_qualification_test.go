//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Kubernetes admission/RBAC and installed-manager suites separately qualify
// actual storage. This boundary uses real native Keycloak with production code.
func qualifyWorkloadBinding(f *keycloakFixture, kube client.Client, shared *controller.HankoWorkloadTrustReconciler, trust *api.HankoWorkloadTrust, proxyURL string, routes func() map[string]int) string {
	ctx := context.Background()
	_, credential := f.serviceClient("workload-client-writer")
	f.grantClientRoles("workload-client-writer", "managed", []string{"manage-clients", "view-realm"})
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "workload-unrelated", "enabled": true}, nil)
	for _, operation := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/admin/realms/managed/users", map[string]any{"username": "denied"}},
		{"DELETE", "/admin/realms/managed", nil},
		{"PUT", "/admin/realms/managed", map[string]any{"sslRequired": "none"}},
		{"POST", "/admin/realms/managed/identity-provider/instances", map[string]any{"alias": "denied", "providerId": "kubernetes", "enabled": false}},
		{"POST", "/admin/realms", map[string]any{"realm": "denied"}},
		{"GET", "/admin/realms/master/clients", nil},
		{"PUT", "/admin/realms/master", map[string]any{"enabled": false}},
		{"GET", "/admin/realms/workload-unrelated/clients", nil},
		{"PUT", "/admin/realms/workload-unrelated", map[string]any{"enabled": false}},
	} {
		fixtureEqual(f.t, "client-writer excluded authority", f.identityStatus("workload-client-writer", credential, operation.method, operation.path, operation.body), http.StatusForbidden)
	}
	var serviceUser map[string]any
	writerNative := f.client("master", "workload-client-writer")
	f.admin(http.MethodGet, "/admin/realms/master/clients/"+writerNative["id"].(string)+"/service-account-user", nil, &serviceUser)
	fixtureEqual(f.t, "client-writer impersonation excluded", f.identityStatus("workload-client-writer", credential, http.MethodPost, "/admin/realms/master/users/"+serviceUser["id"].(string)+"/impersonation", nil), http.StatusForbidden)
	f.admin(http.MethodDelete, "/admin/realms/workload-unrelated", nil, nil)

	account := &api.HankoServiceAccount{ObjectMeta: fixtureMeta("bound-worker"), Spec: api.HankoServiceAccountSpec{RealmRef: "managed", ClientID: "bound-worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: trust.Name, SourceRef: "client-writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workloads", ServiceAccountRef: "worker"}, ExpectedUID: "approved-workload-uid"}, ExpirationSeconds: 600}}, RuntimeMetadata: &api.WorkloadRuntimeMetadataTarget{ApplicationRuntimeMetadataTarget: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}, ExpectedUID: "approved-target-uid"}}}
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "identity", UID: "approved-target-uid", Labels: map[string]string{workloadbinding.TargetLabel: "workload-metadata"}, Annotations: workloadbinding.Authorization(account, account.Spec.Authentication.Kubernetes.Workload)}, Data: map[string]string{"unrelated": "preserved"}}
	live := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "worker", UID: "approved-workload-uid"}}
	for _, obj := range []client.Object{account, config, live, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta("client-writer"), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "trust-ca", AdminRef: corev1.LocalObjectReference{Name: "client-writer-credential"}}}, &corev1.Secret{ObjectMeta: fixtureMeta("client-writer-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(proxyURL), "HANKO_KC_CLIENT_ID": []byte("workload-client-writer"), "HANKO_KC_CLIENT_SECRET": []byte(credential)}}} {
		f.requireNoError(kube.Create(ctx, obj))
	}
	reconciler := &controller.HankoServiceAccountReconciler{Client: kube, APIReader: kube, OwnershipReader: kube, RuntimeClient: kube, WorkloadTrust: shared}
	for range 4 {
		fixtureReconcile(f, ctx, reconciler, account)
	}
	fixtureGet(f, ctx, kube, account)
	fixtureGet(f, ctx, kube, config)
	if account.Status.WorkloadBinding == nil || account.Status.RuntimeMetadata == nil || account.Status.Phase != "Ready" || account.Status.SecretRef != nil {
		f.t.Fatalf("native federated activation did not converge: phase=%s conditions=%v", account.Status.Phase, account.Status.Conditions)
	}
	f.requireNoCredentials("binding/status", fixtureJSON(f.t, account))
	f.requireNoCredentials("runtime metadata", fixtureJSON(f.t, config))
	// The production reconciler creates/configures the native identity. The
	// fixture administrator observes retained material only for preservation
	// qualification; production activation never reads a credential endpoint.
	created := f.client("managed", account.Spec.ClientID)
	if created["clientAuthenticatorType"] != "federated-jwt" || created["enabled"] != true {
		f.t.Fatal("native activation mapping differs")
	}
	path := "/admin/realms/managed/clients/" + created["id"].(string)
	var originalCredential map[string]any
	f.admin(http.MethodGet, path+"/client-secret", nil, &originalCredential)
	secret, _ := originalCredential["value"].(string)
	if secret != "" {
		f.secrets = append(f.secrets, secret)
	}
	// Qualify containment of independent native display settings after actual
	// controller activation. Unsupported edits may stop readiness, never cause
	// their replacement by an opaque full client PUT.
	f.admin(http.MethodPut, path, map[string]any{"name": "Preserved display", "description": "Preserved description"}, nil)
	before := f.client("managed", account.Spec.ClientID)
	fixtureReconcile(f, ctx, reconciler, account)
	fixtureGet(f, ctx, kube, account)
	fixtureGet(f, ctx, kube, config)
	if account.Status.WorkloadBinding == nil {
		f.t.Fatal("owned native configuration did not retain passive binding")
	}
	publicBefore := config.Data[workloadbinding.MetadataKey]
	f.requireNoError(kube.Delete(ctx, live))
	live.ResourceVersion = ""
	live.UID = "replacement-workload-uid"
	f.requireNoError(kube.Create(ctx, live))
	for range 2 {
		fixtureReconcile(f, ctx, reconciler, account)
	}
	fixtureGet(f, ctx, kube, account)
	fixtureGet(f, ctx, kube, config)
	after := f.client("managed", account.Spec.ClientID)
	if after["enabled"] != false || account.Status.WorkloadBinding != nil || account.Status.RuntimeMetadata != nil || account.Status.Phase == "Ready" || config.Data[workloadbinding.MetadataKey] != publicBefore {
		f.t.Fatal("native replacement containment failed")
	}
	before["enabled"] = false
	if !reflect.DeepEqual(before, after) {
		f.t.Fatal("enabled-only native containment changed independent fields")
	}
	fixtureEqual(f.t, "owned containment PUT exactly once", routes()["PUT "+path], 1)
	// The fixture's retained secret is checked privately and never serialized
	// into proof. Its presence is a native credential capability, not route use.
	var retained map[string]any
	f.admin(http.MethodGet, path+"/client-secret", nil, &retained)
	if retained["value"] != secret {
		f.t.Fatal("containment changed retained native credential (values withheld)")
	}
	for route := range routes() {
		if strings.Contains(route, "client-secret") || strings.HasPrefix(route, "DELETE /admin/realms/managed/clients") {
			f.t.Fatal("federated creation or containment crossed credential/delete boundary")
		}
	}
	var document workloadbinding.Document
	f.requireNoError(json.Unmarshal([]byte(publicBefore), &document))
	var published map[string]any
	f.admin(http.MethodGet, "/realms/managed/.well-known/openid-configuration", nil, &published)
	if document.AssertionAudience != published["issuer"] || document.TokenEndpoint != published["token_endpoint"] || document.Workload.ExpectedUID != "approved-workload-uid" {
		f.t.Fatal("native binding public audience/UID differs")
	}
	f.requireNoCredentials("contained public status", fixtureJSON(f.t, account))
	// Recreated UID and removed consent require administrator resolution before
	// metadata cleanup. Remove fixture dependents explicitly for trust cleanup.
	f.admin(http.MethodDelete, path, nil, nil)
	f.t.Logf("Keycloak %s: production federated creation and public metadata, native UID containment and preservation, zero activation credential routes", f.version)
	return path
}
