//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Native storage and production acquisition are real. Public cluster discovery
// and Hanko API storage are explicit fixtures, independently covered elsewhere.
func TestRealKeycloakFederatedServiceAccountAdoption(t *testing.T) {
	f := newKeycloakFixtureWithTransportAndDiscovery(t, false, false, true)
	ctx := context.Background()
	endpoint, ca, routes := newWorkloadTrustACKProxy(t, f)
	caHash, err := workloadtrust.APICAHash(f.ca)
	f.requireNoError(err)
	trust := &api.HankoWorkloadTrust{ObjectMeta: fixtureMeta("adoption-trust"), Spec: api.HankoWorkloadTrustSpec{Mode: "Manage", RealmRef: "managed", SourceRef: "trust-observer", WriterRef: "trust-writer", DependentReaderRef: "dependent-reader", KeycloakAlias: "adoption-kube", Provider: "Kubernetes", Kubernetes: api.KubernetesWorkloadTrustSpec{Issuer: "https://current-cluster.example.test", AssertionMaxAgeSeconds: 600, ClusterAnchor: api.WorkloadClusterAnchor{KubeSystemNamespaceUID: "cluster-uid", APIServerCAHash: caHash}}}}
	account := &api.HankoServiceAccount{ObjectMeta: fixtureMeta("imported-federated"), Spec: api.HankoServiceAccountSpec{Mode: "Observe", RealmRef: "managed", ClientID: "imported-federated", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: trust.Name, SourceRef: "client-writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workloads", ServiceAccountRef: "imported"}, ExpectedUID: "reviewed-workload-uid"}, ExpirationSeconds: 600}}}}
	account.Annotations = map[string]string{adoption.SourceAnnotation: "client-observer"}
	objects := []client.Object{trust, account, &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "imported", UID: "reviewed-workload-uid"}}, &corev1.Secret{ObjectMeta: fixtureMeta("ca"), Data: map[string][]byte{"ca.crt": ca}}}
	for _, p := range []struct {
		name  string
		roles []string
	}{
		{"trust-observer", []string{"view-identity-providers", "view-realm"}},
		{"trust-writer", []string{"manage-identity-providers", "view-realm"}},
		{"dependent-reader", []string{"view-clients"}},
		{"client-observer", []string{"view-clients", "view-realm"}},
		{"client-writer", []string{"manage-clients", "view-realm"}},
	} {
		_, credential := f.serviceClient("fed-adopt-" + p.name)
		f.grantClientRoles("fed-adopt-"+p.name, "managed", p.roles)
		objects = append(objects, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta(p.name), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "ca", AdminRef: corev1.LocalObjectReference{Name: p.name + "-credential"}}}, &corev1.Secret{ObjectMeta: fixtureMeta(p.name + "-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(endpoint), "HANKO_KC_CLIENT_ID": []byte("fed-adopt-" + p.name), "HANKO_KC_CLIENT_SECRET": []byte(credential)}})
	}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&api.HankoWorkloadTrust{}, &api.HankoServiceAccount{}).WithObjects(objects...).Build()
	shared := &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: kube, ClusterConfig: &rest.Config{Host: f.baseURL, TLSClientConfig: rest.TLSClientConfig{CAData: f.ca}}, DiscoveryCheck: func(_ context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		return workloadtrust.DiscoveryEvidence{Issuer: i.Issuer, JWKSURL: i.Issuer + "/jwks", KeysHash: workloadtrust.Digest("public-fixture", 1)}, nil
	}}
	for range 4 {
		fixtureReconcile(f, ctx, shared, trust)
	}
	fixtureGet(f, ctx, kube, trust)
	fixtureEqual(t, "fresh trust qualified", trust.Status.Phase, "Ready")
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": account.Spec.ClientID, "name": account.Spec.ClientID, "protocol": "openid-connect", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "fullScopeAllowed": false, "clientAuthenticatorType": "federated-jwt", "webOrigins": []string{}, "redirectUris": []string{}, "defaultClientScopes": []string{"profile", "service_account"}, "optionalClientScopes": []string{"offline_access"}, "attributes": map[string]string{"locale": "fr", "jwt.credential.issuer": trust.Spec.KeycloakAlias, "jwt.credential.sub": "system:serviceaccount:workloads:imported"}}, nil)
	before := f.client("managed", account.Spec.ClientID)
	path := "/admin/realms/managed/clients/" + before["id"].(string)
	r := &controller.HankoServiceAccountReconciler{Client: kube, APIReader: kube, OwnershipReader: kube, RuntimeClient: kube, Scheme: kube.Scheme(), WorkloadTrust: shared}
	fixtureReconcile(f, ctx, r, account)
	fixtureGet(f, ctx, kube, account)
	if account.Status.AdoptionCandidate == nil || !account.Status.AdoptionCandidate.Approvable {
		t.Fatalf("closed federated candidate unavailable: %v", account.Status.Conditions)
	}
	account.Annotations[adoption.ContractAnnotation] = string(adoption.Version)
	account.Annotations[adoption.CandidateAnnotation] = account.Status.AdoptionCandidate.CandidateHash
	f.requireNoError(kube.Update(ctx, account))
	for range 2 {
		fixtureReconcile(f, ctx, r, account)
	}
	fixtureGet(f, ctx, kube, account)
	if account.Spec.Mode != "Observe" || len(account.Finalizers) != 0 || account.Status.AdoptionReceipt == nil || account.Status.AdoptionReceipt.State != "Verified" {
		t.Fatalf("native owner-only acquisition unavailable: %v", account.Status.Conditions)
	}
	after := f.client("managed", account.Spec.ClientID)
	attrs := after["attributes"].(map[string]any)
	for _, key := range []string{adoption.ClientOwnerKindKey, adoption.ClientOwnerUIDKey, adoption.ReceiptKey} {
		delete(attrs, key)
	}
	fixtureEqual(t, "owner-only native semantics preserved", after, before)
	fixtureEqual(t, "one ownership PUT", routes()["PUT "+path], 1)
	for route := range routes() {
		if strings.Contains(route, "client-secret") {
			t.Fatal("observation or acquisition read a native credential")
		}
	}
	f.requireNoCredentials("federated adoption public references", fixtureJSON(t, account))
	account.Spec.Mode = "Manage"
	account.Generation++
	f.requireNoError(kube.Update(ctx, account))
	for range 4 {
		fixtureReconcile(f, ctx, r, account)
	}
	fixtureGet(f, ctx, kube, account)
	if account.Status.Phase != "Ready" || account.Status.SecretRef != nil {
		t.Fatalf("explicit Manage did not verify active adopted client: %v", account.Status.Conditions)
	}
	fixtureEqual(t, "Manage retains native UUID", f.client("managed", account.Spec.ClientID)["id"], before["id"])
	fixtureEqual(t, "Manage did not replace native configuration", routes()["PUT "+path], 1)
	for route := range routes() {
		if strings.Contains(route, "client-secret") {
			t.Fatal("federated Manage recovered a native credential")
		}
	}
	t.Logf("Keycloak %s: closed federated acquisition preserves native configuration, stays Observe, and requires explicit Manage", f.version)
}
