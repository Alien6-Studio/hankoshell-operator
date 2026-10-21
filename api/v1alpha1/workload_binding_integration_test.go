//go:build integration

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkWorkloadBindingAdmission(t *testing.T, ctx context.Context, admin client.Client) {
	t.Helper()
	base := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": map[string]any{"name": "binding-admission", "namespace": "auth"}, "spec": map[string]any{"realmRef": "example", "clientID": "worker", "authentication": map[string]any{"mode": "Kubernetes", "kubernetes": map[string]any{"trustRef": "cluster", "sourceRef": "client-writer", "workload": map[string]any{"namespace": "other", "serviceAccountRef": "worker", "expectedUID": "approved-uid"}}}, "runtimeMetadata": map[string]any{"configMapRef": "identity", "expectedUID": "target-uid"}}}}
	for _, bad := range []struct {
		name  string
		path  []string
		value any
	}{
		{"default", []string{"authentication", "kubernetes", "workload", "serviceAccountRef"}, "default"},
		{"uid", []string{"authentication", "kubernetes", "workload", "expectedUID"}, ""},
		{"namespace", []string{"authentication", "kubernetes", "workload", "namespace"}, ""},
		{"source", []string{"authentication", "kubernetes", "sourceRef"}, ""},
		{"age-low", []string{"authentication", "kubernetes", "expirationSeconds"}, int64(599)},
		{"age-high", []string{"authentication", "kubernetes", "expirationSeconds"}, int64(3601)},
		{"rotation", []string{"secretRotationPolicy"}, map[string]any{"enabled": true, "intervalDays": int64(30)}},
		{"reserved", []string{"attributes"}, map[string]any{"jwt.credential.issuer": "forged"}},
		{"reserved-workload", []string{"attributes"}, map[string]any{"hanko.sh/workload-owner": "forged"}},
		{"target-uid", []string{"runtimeMetadata", "expectedUID"}, ""},
		{"secret-parameters", []string{"authentication", "mode"}, "Secret"},
	} {
		obj := base.DeepCopy()
		obj.SetName("binding-bad-" + bad.name)
		if err := unstructured.SetNestedField(obj.Object, bad.value, append([]string{"spec"}, bad.path...)...); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, obj); !apierrors.IsInvalid(err) {
			t.Fatalf("invalid workload binding %s admitted: %v", bad.name, err)
		}
	}
	if err := admin.Create(ctx, base); err != nil {
		t.Fatal(err)
	}
	if age, _, _ := unstructured.NestedInt64(base.Object, "spec", "authentication", "kubernetes", "expirationSeconds"); age != 600 {
		t.Fatal("projection default differs")
	}
	legacy := base.DeepCopy()
	legacy.SetName("binding-legacy")
	legacy.SetResourceVersion("")
	legacy.SetUID("")
	unstructured.RemoveNestedField(legacy.Object, "spec", "authentication")
	unstructured.RemoveNestedField(legacy.Object, "spec", "runtimeMetadata")
	if err := admin.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := unstructured.NestedFieldNoCopy(legacy.Object, "spec", "authentication"); found {
		t.Fatal("omitted authentication acquired a new intent")
	}
	var account api.HankoServiceAccount
	if err := admin.Get(ctx, client.ObjectKeyFromObject(base), &account); err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	account.Status.WorkloadBinding = &api.WorkloadBindingStatus{Workload: account.Spec.Authentication.Kubernetes.Workload, ClusterNamespaceUID: "cluster-uid", APIServerCAHash: hash, TrustUID: "trust-uid", TrustGeneration: 1, ProviderID: "provider-uid", RealmID: "realm-uid", SourceGeneration: account.Generation, IntentHash: hash, PlanHash: hash, BindingRevision: hash}
	if err := admin.Status().Update(ctx, &account); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(base), &account); err != nil || account.Status.WorkloadBinding == nil || account.Status.WorkloadBinding.Workload.ExpectedUID != "approved-uid" {
		t.Fatal("public binding status did not round-trip")
	}
	checkAuthenticationTransitionAdmission(t, ctx, admin, &account, hash)
}

func checkAuthenticationTransitionAdmission(t *testing.T, ctx context.Context, admin client.Client, account *api.HankoServiceAccount, hash string) {
	t.Helper()
	for _, authentication := range []*api.ServiceAccountAuthentication{nil, {Mode: "Secret"}, {Mode: "Secret", FallbackBinding: account.Spec.Authentication.Kubernetes}} {
		changed := account.DeepCopy()
		changed.Spec.RuntimeMetadata = nil
		changed.Spec.Authentication = authentication
		if err := admin.Update(ctx, changed); !apierrors.IsInvalid(err) {
			t.Fatal("dropping Kubernetes authority without a typed fallback was admitted")
		}
	}
	changed := account.DeepCopy()
	changed.Spec.RuntimeMetadata = nil
	changed.Spec.Authentication = &api.ServiceAccountAuthentication{Mode: "Secret", FallbackBinding: account.Spec.Authentication.Kubernetes, Transition: &api.ServiceAccountAuthenticationTransition{Strategy: "CoordinatedCutover", RequestID: "fallback-request", PreparedWorkloadRevision: "deployment-revision"}}
	if err := admin.Update(ctx, changed); err != nil {
		t.Fatalf("explicit fallback contract rejected: %v", err)
	}
	for _, invalid := range []api.ServiceAccountAuthenticationTransition{{Strategy: "Automatic", RequestID: "valid", PreparedWorkloadRevision: "valid"}, {Strategy: "CoordinatedCutover", RequestID: "", PreparedWorkloadRevision: "valid"}, {Strategy: "CoordinatedCutover", RequestID: "valid", PreparedWorkloadRevision: "../foreign"}} {
		candidate := changed.DeepCopy()
		candidate.Spec.Authentication.Transition = &invalid
		if err := admin.Update(ctx, candidate); !apierrors.IsInvalid(err) {
			t.Fatal("unqualified transition request admitted")
		}
	}
	changed.Status.AuthenticationTransition = &api.AuthenticationTransitionStatus{RequestID: "fallback-request", ClientUUID: "native-client", PreviousMode: "Kubernetes", DesiredMode: "Secret", BindingRevision: hash, NativeStateHash: hash, PlanHash: hash, Step: "ModeApplied"}
	if err := admin.Status().Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(changed), changed); err != nil || changed.Status.AuthenticationTransition == nil || changed.Status.AuthenticationTransition.Step != "ModeApplied" {
		t.Fatal("bounded authentication status did not round-trip")
	}
}

func checkWorkloadBindingDeliveryRBAC(t *testing.T, ctx context.Context, admin client.Client, operator client.WithWatch) {
	t.Helper()
	live := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "bound-worker"}}
	if err := admin.Create(ctx, live); err != nil {
		t.Fatal(err)
	}
	account := &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "bound-worker"}, Spec: api.HankoServiceAccountSpec{RealmRef: "example", ClientID: "bound-worker", Authentication: &api.ServiceAccountAuthentication{Mode: "Kubernetes", Kubernetes: &api.KubernetesServiceAccountAuthentication{TrustRef: "cluster", SourceRef: "client-writer", Workload: api.KubernetesWorkloadBinding{ApplicationRuntimeWorkload: api.ApplicationRuntimeWorkload{Namespace: "other", ServiceAccountRef: live.Name}, ExpectedUID: string(live.UID)}}}}}
	if err := admin.Create(ctx, account); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "bound-identity", Labels: map[string]string{workloadbinding.TargetLabel: "workload-metadata"}, Annotations: workloadbinding.Authorization(account, account.Spec.Authentication.Kubernetes.Workload)}, Data: map[string]string{"unrelated": "preserved"}}
	if err := admin.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	account.Spec.RuntimeMetadata = &api.WorkloadRuntimeMetadataTarget{ApplicationRuntimeMetadataTarget: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: cm.Name}, ExpectedUID: string(cm.UID)}
	if err := admin.Update(ctx, account); err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("b", 64)
	plan, err := workloadbinding.Compile(account, workloadbinding.References{TrustUID: "trust-uid", ProviderID: "provider-uid", RealmID: "realm-uid", ClusterUID: "cluster-uid", CAHash: hash, TrustGeneration: 1, SourceHash: hash, TrustHash: hash, FlowHash: hash, WorkloadUID: string(live.UID), TargetUID: string(cm.UID), ConsentHash: hash, AssertionAudience: "https://keycloak.example/realms/example", TokenEndpoint: "https://keycloak.example/realms/example/protocol/openid-connect/token", TrustMaxAge: 600})
	if err != nil {
		t.Fatal(err)
	}
	delivery := &workloadbinding.Delivery{Client: operator, Reader: operator, Verify: func(context.Context) error { return nil }}
	if _, err := delivery.Deliver(ctx, account, plan); err == nil {
		t.Fatal("cross-namespace delivery succeeded without named grant")
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "workload-binding"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{live.Name}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{cm.Name}, Verbs: []string{"get", "patch"}}}}
	if err := admin.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: role.Name}, RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "auth", Name: "compatibility-hanko-operator"}}}
	if err := admin.Create(ctx, rb); err != nil {
		t.Fatal(err)
	}
	if status, err := delivery.Deliver(ctx, account, plan); err != nil || status == nil {
		t.Fatalf("named runtime grant failed: %v", err)
	}
	for _, attributes := range []authorizationv1.ResourceAttributes{
		{Namespace: "other", Verb: "list", Resource: "serviceaccounts"},
		{Namespace: "other", Verb: "watch", Resource: "serviceaccounts"},
		{Namespace: "other", Verb: "get", Resource: "serviceaccounts", Name: "default"},
		{Namespace: "other", Verb: "patch", Resource: "serviceaccounts", Name: live.Name},
		{Namespace: "other", Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: live.Name},
		{Verb: "create", Group: "authentication.k8s.io", Resource: "tokenreviews"},
		{Namespace: "other", Verb: "create", Resource: "configmaps"},
		{Namespace: "other", Verb: "delete", Resource: "configmaps", Name: cm.Name},
		{Namespace: "other", Verb: "patch", Resource: "configmaps", Name: "foreign"},
		{Namespace: "other", Verb: "get", Resource: "secrets", Name: cm.Name},
		{Namespace: "other", Verb: "patch", Group: "apps", Resource: "deployments", Name: "worker"},
	} {
		review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attributes}}
		if err := operator.Create(ctx, review); err != nil || review.Status.Allowed {
			t.Fatalf("named binding RBAC broadened for %s/%s/%s: %v", attributes.Verb, attributes.Resource, attributes.Subresource, err)
		}
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data["unrelated"] != "preserved" {
		t.Fatal("delivery changed independent field")
	}
	delete(cm.Annotations, workloadbinding.ConsentPrefix+"owner-uid")
	if err := admin.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Cleanup(ctx, account); err == nil {
		t.Fatal("removed consent authorized cleanup")
	}
}
