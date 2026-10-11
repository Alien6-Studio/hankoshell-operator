package workloadbinding

import (
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testIntent() (*api.HankoServiceAccount, References) {
	sa := &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "worker", UID: "source-uid", Generation: 1}, Spec: api.HankoServiceAccountSpec{RealmRef: "managed", ClientID: "worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: "trust", SourceRef: "writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "workloads", ServiceAccountRef: "worker"}, ExpectedUID: "workload-uid"}, ExpirationSeconds: 600}}}}
	hash := Digest("fixture", 1)
	return sa, References{TrustUID: "trust-uid", ProviderID: "provider-uid", RealmID: "realm-uid", ClusterUID: "cluster-uid", CAHash: hash, TrustGeneration: 1, SourceHash: hash, TrustHash: hash, FlowHash: hash, WorkloadUID: "workload-uid", AssertionAudience: "https://keycloak.example/realms/managed", TokenEndpoint: "https://keycloak.example/realms/managed/protocol/openid-connect/token", TrustMaxAge: 600}
}

func TestPlanRejectsEveryChangedAuthorityAndExcludesOpaqueAttributes(t *testing.T) {
	sa, refs := testIntent()
	plan, err := Compile(sa, refs)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*api.HankoServiceAccount, *References){
		func(sa *api.HankoServiceAccount, _ *References) { sa.Generation++ },
		func(sa *api.HankoServiceAccount, _ *References) { sa.UID = "replacement-source" },
		func(_ *api.HankoServiceAccount, r *References) { r.SourceHash = Digest("credential-rv", 2) },
		func(_ *api.HankoServiceAccount, r *References) { r.TrustHash = Digest("trust", 2) },
		func(_ *api.HankoServiceAccount, r *References) { r.FlowHash = Digest("flow", 2) },
		func(_ *api.HankoServiceAccount, r *References) { r.CAHash = Digest("ca", 2) },
		func(_ *api.HankoServiceAccount, r *References) { r.NativeClientID = "replacement-native-client" },
	} {
		current := sa.DeepCopy()
		r := refs
		change(current, &r)
		next, err := Compile(current, r)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Validate(next) == nil {
			t.Fatal("stale authority retained execution permission")
		}
	}
	sa.Spec.Attributes = map[string]string{"opaque": "secret-sentinel"}
	next, err := Compile(sa, refs)
	if err != nil || plan.Validate(next) != nil {
		t.Fatal("opaque/credential-like attributes entered public semantic hash")
	}
	b, _, err := plan.Metadata(sa)
	if err != nil || strings.Contains(string(b), "secret-sentinel") {
		t.Fatal("opaque attributes entered metadata")
	}
}

func TestCompileRefusesWrongUIDOverAgeAndUnsafeEndpoint(t *testing.T) {
	for _, change := range []func(*api.HankoServiceAccount, *References){
		func(_ *api.HankoServiceAccount, r *References) { r.WorkloadUID = "recreated" },
		func(sa *api.HankoServiceAccount, _ *References) {
			sa.Spec.Authentication.Kubernetes.ExpirationSeconds = 900
		},
		func(_ *api.HankoServiceAccount, r *References) { r.TokenEndpoint = "http://keycloak.example/token" },
		func(_ *api.HankoServiceAccount, r *References) {
			r.AssertionAudience = "https://user@keycloak.example/realm"
		},
		func(sa *api.HankoServiceAccount, _ *References) {
			sa.Spec.Authentication.Kubernetes.Workload.ServiceAccountRef = "default"
		},
	} {
		sa, r := testIntent()
		change(sa, &r)
		if _, err := Compile(sa, r); err == nil {
			t.Fatal("unsafe workload authority compiled")
		}
	}
}

func TestJournalIsBoundedCanonicalLookupData(t *testing.T) {
	sa, r := testIntent()
	plan, err := Compile(sa, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`{"schema":"unknown"}`, strings.Repeat("x", 4097), `{"schema":"` + Schema + `","unknown":true}`, `{"schema":"` + Schema + `"} {}`} {
		if _, err := ParseRecord(value); err == nil {
			t.Fatal("unqualified cleanup lookup accepted")
		}
	}
	if !strings.HasPrefix(plan.Revision(), "sha256:") {
		t.Fatal("binding revision is not a public deterministic digest")
	}
}
