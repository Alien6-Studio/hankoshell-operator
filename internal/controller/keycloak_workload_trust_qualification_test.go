//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This qualifies the actual production trust controller and native Admin
// semantics. Kubernetes storage/discovery have separate real-server tests; this
// test explicitly injects public discovery evidence and never claims JWT auth.
func TestRealKeycloakWorkloadTrustController(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	hash, err := workloadtrust.APICAHash(f.ca)
	f.requireNoError(err)
	trust := &api.HankoWorkloadTrust{ObjectMeta: fixtureMeta("shared-trust"), Spec: api.HankoWorkloadTrustSpec{Mode: "Manage", RealmRef: "managed", SourceRef: "trust-observer", WriterRef: "trust-writer", DependentReaderRef: "dependent-reader", KeycloakAlias: "p62-shared", Provider: "Kubernetes", Kubernetes: api.KubernetesWorkloadTrustSpec{Issuer: "https://current-cluster.example.test", AssertionMaxAgeSeconds: 600, ClusterAnchor: api.WorkloadClusterAnchor{KubeSystemNamespaceUID: "cluster-uid", APIServerCAHash: hash}}}}
	objects := []client.Object{trust, &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.Secret{ObjectMeta: fixtureMeta("trust-ca"), Data: map[string][]byte{"ca.crt": f.ca}}}
	profiles := []struct {
		name  string
		roles []string
	}{{"trust-observer", []string{"view-identity-providers", "view-realm"}}, {"trust-writer", []string{"manage-identity-providers", "view-realm"}}, {"dependent-reader", []string{"view-clients"}}}
	for _, p := range profiles {
		_, secret := f.serviceClient("p62-" + p.name)
		f.grantClientRoles("p62-"+p.name, "managed", p.roles)
		objects = append(objects, &api.HankoKeycloakInstance{ObjectMeta: fixtureMeta(p.name), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", TLSCARef: "trust-ca", AdminRef: corev1.LocalObjectReference{Name: p.name}}}, &corev1.Secret{ObjectMeta: fixtureMeta(p.name + "-credential"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(f.baseURL), "HANKO_KC_CLIENT_ID": []byte("p62-" + p.name), "HANKO_KC_CLIENT_SECRET": []byte(secret)}})
		objects[len(objects)-2].(*api.HankoKeycloakInstance).Spec.AdminRef.Name = p.name + "-credential"
	}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&api.HankoWorkloadTrust{}).WithObjects(objects...).Build()
	r := &controller.HankoWorkloadTrustReconciler{Client: kube, APIReader: kube, ClusterConfig: &rest.Config{Host: f.baseURL, TLSClientConfig: rest.TLSClientConfig{CAData: f.ca}}, DiscoveryCheck: func(_ context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
		return workloadtrust.DiscoveryEvidence{Issuer: i.Issuer, JWKSURL: i.Issuer + "/jwks", KeysHash: workloadtrust.Digest("public-fixture", 1)}, nil
	}}
	run := func(n int) {
		for range n {
			fixtureReconcile(f, ctx, r, trust)
		}
		fixtureGet(f, ctx, kube, trust)
	}
	run(4)
	fixtureEqual(t, "native trust controller Ready", trust.Status.Phase, "Ready")
	base := "/admin/realms/managed/identity-provider/instances/p62-shared"
	var native map[string]any
	f.admin(http.MethodGet, base, nil, &native)
	id := native["internalId"].(string)
	fixtureEqual(t, "planned exact native UUID", id, trust.Status.ProviderID)
	config := native["config"].(map[string]any)
	fixtureEqual(t, "native UID marker", config["hanko.sh/workload-trust-owner"], string(trust.UID))
	fixtureEqual(t, "native typed age", config["fedClientAssertionMaxExp"], "600")
	journal, err := workloadtrust.ParseJournal(config["hanko.sh/workload-trust-journal"].(string))
	f.requireNoError(err)
	fixtureEqual(t, "journal exact native UUID", journal.ProviderID, id)
	run(2)
	var again map[string]any
	f.admin(http.MethodGet, base, nil, &again)
	fixtureEqual(t, "idempotent native document", again, native)
	trust.Spec.Kubernetes.AssertionMaxAgeSeconds = 900
	trust.Generation++
	f.requireNoError(kube.Update(ctx, trust))
	run(1)
	fixtureEqual(t, "shared-age review required", trust.Status.Conditions[0].Reason, "SharedAgeReviewRequired")
	a := workloadtrust.SharedAgeApproval{Contract: "hanko.sh/iam-contract/v1alpha1", PlanHash: trust.Status.EvaluatedPlanHash, DependenciesHash: trust.Status.DependentInventoryHash, ReviewHash: trust.Status.SharedAgeReviewHash}
	b, err := json.Marshal(a)
	f.requireNoError(err)
	trust.Annotations[workloadtrust.AgeApprovalKey] = string(b)
	f.requireNoError(kube.Update(ctx, trust))
	run(2)
	fixtureEqual(t, "reviewed age Ready", trust.Status.Phase, "Ready")
	f.admin(http.MethodGet, base, nil, &again)
	fixtureEqual(t, "update preserves UUID", again["internalId"], id)
	// A native foreign dependent blocks provider deletion, even when disabled.
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "p62-foreign-dependent", "enabled": false, "clientAuthenticatorType": "federated-jwt", "attributes": map[string]string{"jwt.credential.issuer": "p62-shared", "jwt.credential.sub": "system:serviceaccount:workloads:worker"}}, nil)
	f.requireNoError(kube.Delete(ctx, trust))
	run(1)
	fixtureEqual(t, "foreign dependent blocks deletion", trust.Status.Conditions[0].Reason, "DependentClientsPresent")
	dependent := f.client("managed", "p62-foreign-dependent")
	f.admin(http.MethodDelete, "/admin/realms/managed/clients/"+dependent["id"].(string), nil, nil)
	fixtureReconcile(f, ctx, r, trust)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(trust), trust); err == nil || client.IgnoreNotFound(err) != nil {
		t.Fatal("zero-dependent owned cleanup did not release finalizer")
	}
	var providers []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances", nil, &providers)
	for _, p := range providers {
		if p["alias"] == "p62-shared" {
			t.Fatal("owned zero-dependent provider retained")
		}
	}
	// Writer retains native realm-wide IdP powers, but no client/user/realm/master
	// authority. The separate reader concession never modifies its mappings.
	_, writerSecret := f.serviceClient("p62-negative-writer")
	f.grantClientRoles("p62-negative-writer", "managed", []string{"manage-identity-providers", "view-realm"})
	for _, request := range []struct {
		method, path string
		body         any
	}{{"POST", "/admin/realms/managed/users", map[string]any{"username": "forbidden"}}, {"POST", "/admin/realms/managed/groups", map[string]any{"name": "forbidden"}}, {"PUT", "/admin/realms/managed", map[string]any{"sslRequired": "none"}}, {"DELETE", "/admin/realms/managed", nil}, {"POST", "/admin/realms", map[string]any{"realm": "forbidden"}}, {"GET", "/admin/realms/master/clients", nil}, {"PUT", "/admin/realms/master", map[string]any{"enabled": false}}, {"POST", "/admin/realms/managed/clients", map[string]any{"clientId": "forbidden"}}} {
		fixtureEqual(t, "trust-writer native negative permission", f.identityStatus("p62-negative-writer", writerSecret, request.method, request.path, request.body), http.StatusForbidden)
	}
	if strings.Contains(string(fixtureJSON(t, trust)), "client-secret") {
		t.Fatal("credential route in controller evidence")
	}
	t.Logf("Keycloak %s: production controller creates/seals exact UUID and UID journal, read-back/idempotence, reviewed age update and real foreign-dependent deletion guard; exact trust-writer profiles retained", f.version)
}
