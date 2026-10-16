//go:build integration

package v1alpha1_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func checkExperimentalConnectionAdmission(t *testing.T, ctx context.Context, admin client.Client, environment *envtest.Environment, config *rest.Config) {
	t.Helper()
	args := []string{"template", "provider-test", filepath.Join("..", "..", "charts", "hankoshell-operator"), "--namespace", "auth", "--kube-version", os.Getenv("KUBERNETES_VERSION"), "--set-string", "image.tag=fixture", "--set", "experimental.authentik.enabled=true", "--set-string", "experimental.authentik.connectionNames[0]=experimental-connection", "--set-string", "experimental.authentik.egress.namespace=identity", "--set-string", "experimental.authentik.egress.selector.app=authentik-edge", "--show-only", "templates/experimental-provider-admission.yaml"}
	// #nosec G702 -- Fixed executable/arguments render the reviewed local chart; no shell or remote input.
	data, err := exec.CommandContext(ctx, "helm", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	policy := &admissionv1.ValidatingAdmissionPolicy{}
	binding := &admissionv1.ValidatingAdmissionPolicyBinding{}
	for _, target := range []any{policy, binding} {
		if err := decoder.Decode(target); err != nil {
			t.Fatal(err)
		}
	}
	if decoder.Decode(new(any)) != io.EOF {
		t.Fatal("unexpected provider admission document")
	}
	for _, object := range []client.Object{policy, binding,
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "provider-config-writer", Namespace: "auth"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create", "get", "update", "delete"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "provider-config-writer", Namespace: "auth"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "provider-config-writer"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "provider-config-author", APIGroup: rbacv1.GroupName}}},
	} {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := environment.AddUser(envtest.User{Name: "provider-config-author", Groups: []string{"system:authenticated"}}, config)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := client.New(identity.Config(), client.Options{Scheme: admin.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "ordinary-provider-data", Namespace: "auth"}}, client.DryRunAll); err != nil {
		t.Fatal("ordinary writer lacks required fixture RBAC")
	}
	protected := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "experimental-connection", Namespace: "auth"}, Data: map[string]string{"connection.json": "administrator-reviewed"}}
	if err := admin.Create(ctx, protected); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		probe := protected.DeepCopy()
		probe.Data["connection.json"] = "refused"
		err = writer.Update(ctx, probe, client.DryRunAll)
		if apierrors.IsForbidden(err) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("provider connection admission failed to propagate: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			probe := protected.DeepCopy()
			switch operation {
			case "create":
				probe.ResourceVersion = ""
				probe.UID = ""
				err = writer.Create(ctx, probe, client.DryRunAll)
			case "update":
				probe.Data["connection.json"] = "refused"
				err = writer.Update(ctx, probe, client.DryRunAll)
			case "delete":
				err = writer.Delete(ctx, probe, client.DryRunAll)
			}
			if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "require administrator authority") {
				t.Fatalf("provider connection %s bypassed independent admission: %v", operation, err)
			}
		})
	}
	protected.Data["connection.json"] = "administrator-approved-update"
	if err := admin.Update(ctx, protected); err != nil {
		t.Fatal("administrator connection update refused")
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.TypeChecking != nil && len(policy.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatal("provider policy has CEL type warnings")
	}
}
