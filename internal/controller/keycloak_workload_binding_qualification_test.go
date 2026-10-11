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
	account := &api.HankoServiceAccount{ObjectMeta: fixtureMeta("bound-worker"), Spec: api.HankoServiceAccountSpec{RealmRef: "managed", ClientID: "bound-worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: trust.Name, SourceRef: "client-writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workloads", ServiceAccountRef: "worker"}, ExpectedUID: "approved-workload-uid"}, ExpirationSeconds: 600}}, RuntimeMetadata: &api.WorkloadRuntimeMetadataTarget{ApplicationRuntimeMetadataTarget: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}, ExpectedUID: "approved-target-uid"}}}
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "identity", UID: "approved-target-uid", Labels: map[string]string{workloadbinding.TargetLabel: "workload-metadata"}, Annotations: workloadbinding.Authorization(account, account.Spec.Authentication.Kubernetes.Workload)}, Data: map[string]string{"unrelated": "preserved"}}
	live := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "worker", UID: "approved-workload-uid"}}
	for _, obj := range []client.Object{account, config, live, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta("client-writer"), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "trust-ca", AdminRef: corev1.LocalObjectReference{Name: "client-writer-credential"}}}, &corev1.Secret{ObjectMeta: fixtureMeta("client-writer-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(proxyURL), "HANKO_KC_CLIENT_ID": []byte("workload-client-writer"), "HANKO_KC_CLIENT_SECRET": []byte(credential)}}} {
		f.requireNoError(kube.Create(ctx, obj))
	}
	reconciler := &controller.HankoServiceAccountReconciler{Client: kube, APIReader: kube, OwnershipReader: kube, RuntimeClient: kube, WorkloadTrust: shared}
	fixtureReconcile(f, ctx, reconciler, account)
	fixtureGet(f, ctx, kube, account)
	fixtureGet(f, ctx, kube, config)
	if account.Status.WorkloadBinding == nil || account.Status.RuntimeMetadata == nil || account.Status.Phase != "Pending" || account.Status.SecretRef != nil {
		f.t.Fatal("passive native binding claimed activation or failed public delivery")
	}
	f.requireNoCredentials("binding/status", fixtureJSON(f.t, account))
	f.requireNoCredentials("runtime metadata", fixtureJSON(f.t, config))
	// Native activation is fixture administrator setup, never an action of this
	// binding controller. Seed independent fields to prove partial containment.
	secret := fixtureSecret(f.t)
	f.secrets = append(f.secrets, secret)
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": account.Spec.ClientID, "secret": secret, "protocol": "openid-connect", "enabled": true, "clientAuthenticatorType": "federated-jwt", "serviceAccountsEnabled": true, "publicClient": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "fullScopeAllowed": false, "name": "Preserved display", "description": "Preserved description", "attributes": map[string]string{"hanko.sh/client-owner-kind": "HankoServiceAccount", "hanko.sh/client-owner-uid": string(account.UID), "jwt.credential.issuer": trust.Spec.KeycloakAlias, "jwt.credential.sub": "system:serviceaccount:workloads:worker", "custom-public-setting": "preserved"}}, nil)
	before := f.client("managed", account.Spec.ClientID)
	path := "/admin/realms/managed/clients/" + before["id"].(string)
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
		if strings.Contains(route, "client-secret") || strings.HasPrefix(route, "POST /admin/realms/managed/clients") || strings.HasPrefix(route, "DELETE /admin/realms/managed/clients") {
			f.t.Fatal("binding controller crossed credential/create/delete boundary")
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
	f.t.Logf("Keycloak %s: workload binding public-only delivery, actual native enabled-only containment with complete field/secret preservation, zero controller credential/create/delete routes", f.version)
	return path
}
