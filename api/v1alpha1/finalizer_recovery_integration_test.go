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

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func installRecoveryFixture(t *testing.T, ctx context.Context, admin client.Client) {
	t.Helper()
	for _, name := range []string{"approval-policy.yaml", "audit-access.yaml", "target-access.yaml"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "config", "recovery", name))
		if err != nil {
			t.Fatal(err)
		}
		decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			obj := &unstructured.Unstructured{}
			err := decoder.Decode(obj)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if (obj.GetKind() == "Role" || obj.GetKind() == "RoleBinding") && obj.GetNamespace() == "" {
				obj.SetNamespace("auth")
			}
			if err := admin.Create(ctx, obj); err != nil {
				t.Fatal("install administrator recovery fixture", err)
			}
		}
	}
}

func recoveryIdentity(t *testing.T, environment *envtest.Environment, config *rest.Config, admin client.Client, name string, groups []string) (client.Client, string) {
	t.Helper()
	identity, err := environment.AddUser(envtest.User{Name: name, Groups: append([]string{"system:authenticated"}, groups...)}, config)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := client.New(identity.Config(), client.Options{Scheme: admin.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	data, err := identity.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return actor, path
}

func checkFinalizerRecovery(t *testing.T, ctx context.Context, admin client.Client, environment *envtest.Environment, config *rest.Config) {
	t.Helper()
	installRecoveryFixture(t, ctx, admin)
	executor, executorConfig := recoveryIdentity(t, environment, config, admin, "recovery-executor", []string{"hanko:recovery-executors", "hanko:recovery-approvers"})
	approver, approverConfig := recoveryIdentity(t, environment, config, admin, "recovery-approver", []string{"hanko:recovery-approvers"})
	operatorName := "system:serviceaccount:auth:recovery-operator"
	operator, _ := recoveryIdentity(t, environment, config, admin, operatorName, []string{"hanko:recovery-executors", "hanko:recovery-approvers"})
	zero := int32(0)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "recovery-paused", Namespace: "auth", Labels: map[string]string{"app.kubernetes.io/name": "hankoshell-operator"}}, Spec: appsv1.DeploymentSpec{
		Replicas: &zero, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"fixture": "recovery-paused"}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"fixture": "recovery-paused"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "operator", Image: "fixture"}}}},
	}}
	role := &api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: "release-blocked", Namespace: "auth", Finalizers: []string{"fixture.hanko.sh/hold", "hanko.sh/role-cleanup"}, Annotations: map[string]string{"private-fixture": "private-fixture-canary"}}, Spec: api.HankoRoleSpec{RealmRef: "realm", Name: "blocked"}}
	for _, obj := range []client.Object{deployment, role} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	if err := admin.Delete(ctx, role); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 G702 -- Fixed local fixture, private generated configs and reviewed envtest executable; no shell.
	command := exec.CommandContext(ctx, "python3", filepath.Join("..", "..", "scripts", "finalizer-recovery-fixture.py"), "--executor", executorConfig, "--approver", approverConfig, "--kubectl", filepath.Join(environment.BinaryAssetsDirectory, "kubectl"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual recovery CLI fixture: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
	if err := approver.Patch(ctx, role, client.RawPatch("application/json-patch+json", []byte(`[{"op":"remove","path":"/metadata/finalizers/0"}]`)), client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("approver acquired target mutation authority: %v", err)
	}
	checkRecoveryAuditDenials(t, ctx, admin, executor, operator)
	policy := &admissionv1.ValidatingAdmissionPolicy{}
	if err := admin.Get(ctx, client.ObjectKey{Name: "hanko-finalizer-release-audit"}, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.TypeChecking != nil && len(policy.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatalf("recovery policy CEL warnings: %#v", policy.Status.TypeChecking)
	}
}

func checkRecoveryAuditDenials(t *testing.T, ctx context.Context, admin, executor, operator client.Client) {
	t.Helper()
	base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "hanko-recovery-audit"}, Immutable: new(true), Data: map[string]string{
		"format": "hanko.sh/finalizer-release/v1alpha1", "phase": "approval", "digest": strings.Repeat("a", 64),
		"actor": "recovery-executor", "requestor": "independent-requestor", "payload": "{}",
	}}
	base.Name = "hanko-release-" + base.Data["digest"] + "-approval"
	for _, scenario := range []string{"self-approval", "forged-actor", "operator", "mutable", "owner-reference", "binary-data", "extra-data"} {
		t.Run(scenario, func(t *testing.T) {
			obj, actor := base.DeepCopy(), executor
			switch scenario {
			case "self-approval":
				obj.Data["requestor"] = obj.Data["actor"]
			case "forged-actor":
				obj.Data["actor"] = "recovery-approver"
			case "operator":
				actor = operator
				obj.Data["actor"] = "system:serviceaccount:auth:recovery-operator"
			case "mutable":
				obj.Immutable = new(false)
			case "owner-reference":
				obj.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "foreign", UID: "foreign"}}
			case "binary-data":
				obj.BinaryData = map[string][]byte{"extra": []byte("private")}
			case "extra-data":
				obj.Data["extra"] = "private"
			}
			if err := actor.Create(ctx, obj, client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "authenticated independent administrator provenance") {
				t.Fatalf("forged audit provenance accepted or wrong denial: %v", err)
			}
		})
	}
	// Even administrators must explicitly retire the guard to erase evidence.
	base.Data["phase"], base.Data["requestor"] = "request", "recovery-executor"
	base.Name = "hanko-release-" + base.Data["digest"] + "-request"
	if err := executor.Create(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := admin.Delete(ctx, base, client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("audit deletion accepted: %v", err)
	}
	base.Labels = map[string]string{"tampered": "true"}
	if err := admin.Update(ctx, base, client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("audit metadata rewrite accepted: %v", err)
	}
}
