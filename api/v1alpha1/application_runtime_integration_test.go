//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkRuntimeBindings(t *testing.T, ctx context.Context, admin client.Client, operator client.WithWatch) {
	t.Helper()
	b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "other", ServiceAccountRef: "runtime-worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "runtime-identity"}, Credentials: &api.ApplicationRuntimeCredentialTarget{SecretRef: "runtime-identity"}}
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "runtime-worker"}, Spec: api.HankoApplicationSpec{RealmRef: "example", ClientID: "runtime-worker", Type: "m2m", RuntimeBindings: []api.ApplicationRuntimeBinding{b}}}
	if err := admin.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-worker"}}
	if err := admin.Create(ctx, sa); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-identity", Labels: map[string]string{applicationbinding.TargetLabel: "metadata"}, Annotations: applicationbinding.Authorization(app, b, string(sa.UID))}, Data: map[string]string{"unrelated": "preserved"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-identity", Labels: map[string]string{applicationbinding.TargetLabel: "credentials"}, Annotations: applicationbinding.Authorization(app, b, string(sa.UID))}, Data: map[string][]byte{"unrelated": []byte("preserved")}}
	controller := true
	source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "hanko-app-runtime-worker", OwnerReferences: []metav1.OwnerReference{{APIVersion: "hanko.sh/v1alpha1", Kind: "HankoApplication", Name: app.Name, UID: app.UID, Controller: &controller}}}, Data: map[string][]byte{"client_secret": []byte("fixture-owned-credential")}}
	for _, obj := range []client.Object{cm, secret, source} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	proof := runtimeAPIProof(app)
	if err := admin.Status().Update(ctx, app); err != nil {
		t.Fatal(err)
	}
	delivery := &applicationbinding.Delivery{Client: operator, Reader: operator, Verify: func(context.Context) error { return nil }}
	// The API-boundary fixture supplies proof; independent real-Keycloak and
	// installed-manager suites qualify provider verification and token use.
	if _, err := delivery.Deliver(ctx, app, proof); err == nil {
		t.Fatal("target namespace without RoleBinding accepted")
	}
	for _, obj := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}} {
		if err := operator.Get(ctx, client.ObjectKey{Namespace: "other", Name: "runtime-identity"}, obj); !apierrors.IsForbidden(err) {
			t.Fatalf("ungranted namespace readable: %v", err)
		}
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-delivery"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{"runtime-worker"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"runtime-identity"}, Verbs: []string{"get", "patch"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"runtime-identity"}, Verbs: []string{"get", "patch"}},
	}}
	if err := admin.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-delivery"}, RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "auth", Name: "compatibility-hanko-operator"}}}
	if err := admin.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	status, err := delivery.Deliver(ctx, app, proof)
	if err != nil || len(status) != 1 {
		t.Fatalf("authorized output failed: %v", err)
	}
	first := status[0].BindingRevision
	if err := admin.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil {
		t.Fatal(err)
	}
	app.Status.RuntimeBindings = status
	if err := admin.Status().Update(ctx, app); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil {
		t.Fatal(err)
	}
	if app.Status.RuntimeBindings[0].ServiceAccountUID != string(sa.UID) {
		t.Fatal("runtime status UID roundtrip lost")
	}
	checkRuntimeRBACDenials(t, ctx, admin, operator)
	checkRuntimeBindingAdmission(t, ctx, admin, app)
	// Cross-list writer checks run before provider interaction in the controller;
	// admission keeps the legacy unbounded projection API compatible.
	duplicate := app.DeepCopy()
	duplicate.Spec.ClientSecretProjections = []api.ApplicationSecretProjection{{Namespace: "other", Name: "runtime-identity"}}
	if applicationbinding.Reason(applicationbinding.Validate(duplicate)) != "DuplicateWriter" {
		t.Fatal("legacy/runtime duplicate writer accepted")
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(source), source); err != nil {
		t.Fatal(err)
	}
	source.Data["client_secret"] = []byte("fixture-rotated-credential")
	if err := admin.Update(ctx, source); err != nil {
		t.Fatal(err)
	}
	status, err = delivery.Deliver(ctx, app, proof)
	if err != nil || status[0].BindingRevision == first {
		t.Fatalf("rotation revision failed: %v", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["client_secret"]) != "fixture-rotated-credential" {
		t.Fatal("rotation not projected")
	}
	if err := admin.Delete(ctx, sa); err != nil {
		t.Fatal(err)
	}
	sa.ResourceVersion = ""
	sa.UID = ""
	if err := admin.Create(ctx, sa); err != nil {
		t.Fatal(err)
	}
	if _, err = delivery.Deliver(ctx, app, proof); applicationbinding.Reason(err) != "WorkloadChanged" {
		t.Fatalf("SA replacement not rejected: %v", err)
	}
	for _, target := range []client.Object{cm, secret} {
		if err := admin.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
			t.Fatal(err)
		}
		target.GetAnnotations()[applicationbinding.ServiceAccountUID] = string(sa.UID)
		if err := admin.Update(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = delivery.Deliver(ctx, app, proof); err != nil {
		t.Fatal(err)
	}
	// Recreated same-name targets must carry fresh, exact owner authorization.
	if err := admin.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatal(err)
	}
	if err := admin.Delete(ctx, cm); err != nil {
		t.Fatal(err)
	}
	cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "runtime-identity"}, Data: map[string]string{"unrelated": "preserved"}}
	if err := admin.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err = delivery.Deliver(ctx, app, proof); err == nil {
		t.Fatal("unmarked recreated target adopted")
	}
	cm.Labels = map[string]string{applicationbinding.TargetLabel: "metadata"}
	cm.Annotations = applicationbinding.Authorization(app, b, string(sa.UID))
	if err := admin.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err = delivery.Deliver(ctx, app, proof); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil {
		t.Fatal(err)
	}
	app.Spec.RuntimeBindings = nil
	if err := admin.Update(ctx, app); err != nil {
		t.Fatal(err)
	}
	if _, err = delivery.Deliver(ctx, app, proof); err != nil {
		t.Fatal(err)
	}
	for _, target := range []client.Object{cm, secret} {
		if err := admin.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
			t.Fatal("cleanup deleted target")
		}
	}
	if cm.Data["identity.json"] != "" || len(secret.Data["client_secret"]) != 0 || cm.Data["unrelated"] != "preserved" || string(secret.Data["unrelated"]) != "preserved" {
		t.Fatal("cleanup did not preserve owner data")
	}
}

func runtimeAPIProof(app *api.HankoApplication) applicationbinding.Proof {
	hash := string(iamcontract.Hash(iamcontract.Version, "fixture", "runtime-proof", []byte("public contract")))
	app.Status = api.HankoApplicationStatus{EvaluatedGeneration: app.Generation, AppliedGeneration: app.Generation, ObservationGeneration: app.Generation, ContractVersion: string(iamcontract.Version), IntentHash: hash, EvaluatedPlanHash: hash, AppliedPlanHash: hash, ObservationPlanHash: hash, ObservationComplete: true, DriftState: "InSync"}
	return applicationbinding.Proof{ApplicationUID: string(app.UID), Generation: app.Generation, ContractVersion: string(iamcontract.Version), IntentHash: hash, AppliedPlanHash: hash, Protocol: "oidc", Pattern: "m2m", ClientID: app.Spec.ClientID, OIDC: &api.OIDCEndpoints{Issuer: "https://idp.test/realms/example", Token: "https://idp.test/realms/example/token", JWKS: "https://idp.test/realms/example/certs"}}
}

func checkRuntimeRBACDenials(t *testing.T, ctx context.Context, admin client.Client, operator client.WithWatch) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "unrelated-runtime"}}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "unrelated-runtime"}}
	for _, obj := range []client.Object{cm, s} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
		p := client.MergeFrom(obj.DeepCopyObject().(client.Object))
		obj.SetAnnotations(map[string]string{"attempt": "denied"})
		if err := operator.Patch(ctx, obj, p); !apierrors.IsForbidden(err) {
			t.Fatalf("unrelated target patch allowed: %v", err)
		}
	}
	denied := []error{operator.List(ctx, &corev1.SecretList{}, client.InNamespace("other")), operator.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "forbidden", Namespace: "other"}}), operator.Delete(ctx, s), operator.Patch(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "other"}}, client.RawPatch("application/merge-patch+json", []byte(`{"metadata":{"annotations":{"attempt":"denied"}}}`)))}
	for _, err := range denied {
		if !apierrors.IsForbidden(err) {
			t.Fatalf("runtime RBAC excess: %v", err)
		}
	}
	w, err := operator.Watch(ctx, &corev1.SecretList{}, client.InNamespace("other"))
	if w != nil {
		w.Stop()
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("Secret watch allowed: %v", err)
	}
}

func checkRuntimeBindingAdmission(t *testing.T, ctx context.Context, kube client.Client, app *api.HankoApplication) {
	t.Helper()
	data, _ := json.Marshal(app.Spec)
	var base map[string]any
	_ = json.Unmarshal(data, &base)
	for n, change := range []func(map[string]any){
		func(s map[string]any) { s["mode"] = "Observe" }, func(s map[string]any) { s["type"] = "spa" },
		func(s map[string]any) { b := s["runtimeBindings"].([]any)[0]; s["runtimeBindings"] = []any{b, b} },
		func(s map[string]any) { s["runtimeBindings"].([]any)[0].(map[string]any)["name"] = "invalid_name" },
		func(s map[string]any) {
			s["runtimeBindings"].([]any)[0].(map[string]any)["publicMetadata"].(map[string]any)["configMapRef"] = "invalid..name"
		},
		func(s map[string]any) {
			bindings := []any{}
			for i := 0; i < 33; i++ {
				var one map[string]any
				_ = json.Unmarshal(data, &one)
				b := one["runtimeBindings"].([]any)[0].(map[string]any)
				b["name"] = fmt.Sprintf("bound-%d", i)
				bindings = append(bindings, b)
			}
			s["runtimeBindings"] = bindings
		},
		func(s map[string]any) {
			delete(s, "type")
			s["protocol"] = "saml"
			s["clientID"] = "https://sp.test"
			s["saml"] = map[string]any{"assertionConsumerServices": []any{"https://sp.test/acs"}}
		},
	} {
		_ = json.Unmarshal(data, &base)
		change(base)
		bad := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": map[string]any{"namespace": "auth", "name": fmt.Sprintf("runtime-invalid-%d", n)}, "spec": base}}
		if err := kube.Create(ctx, bad); !apierrors.IsInvalid(err) {
			t.Fatalf("invalid runtime case %d admitted: %v", n, err)
		}
	}
}
