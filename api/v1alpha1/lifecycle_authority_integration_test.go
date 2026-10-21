//go:build integration

package v1alpha1_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func checkLifecycleAdmission(t *testing.T, ctx context.Context, admin client.Client, environment *envtest.Environment, config *rest.Config) {
	t.Helper()
	args := []string{"template", "lifecycle-test", filepath.Join("..", "..", "charts", "hankoshell-operator"), "--namespace", "auth", "--kube-version", os.Getenv("KUBERNETES_VERSION"), "--set-string", "image.tag=fixture", "--set-string", "fullnameOverride=lifecycle-test", "--show-only", "templates/lifecycle-admission.yaml"}
	// #nosec G702 -- Fixed local Helm renderer; no shell, remote executable or user arguments.
	data, err := exec.CommandContext(ctx, "helm", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	policy, binding := &admissionv1.ValidatingAdmissionPolicy{}, &admissionv1.ValidatingAdmissionPolicyBinding{}
	for _, target := range []any{policy, binding} {
		if err := decoder.Decode(target); err != nil {
			t.Fatal(err)
		}
	}
	operatorName := "system:serviceaccount:auth:lifecycle-test"
	for _, object := range []client.Object{policy, binding,
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "lifecycle-writer", Namespace: "auth"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"hanko.sh"}, Resources: []string{"hankooperations", "hankosnapshots", "hankokeycloakinstances", "hankoimports"}, Verbs: []string{"get", "create", "update", "patch"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "lifecycle-writer", Namespace: "auth"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "lifecycle-writer"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "lifecycle-author", APIGroup: rbacv1.GroupName}, {Kind: "User", Name: operatorName, APIGroup: rbacv1.GroupName}}},
	} {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	identities := map[string]client.Client{}
	for _, name := range []string{"lifecycle-author", operatorName} {
		identity, err := environment.AddUser(envtest.User{Name: name, Groups: []string{"system:authenticated"}}, config)
		if err != nil {
			t.Fatal(err)
		}
		identities[name], err = client.New(identity.Config(), client.Options{Scheme: admin.Scheme()})
		if err != nil {
			t.Fatal(err)
		}
	}
	writer, operator := identities["lifecycle-author"], identities[operatorName]
	op := &api.HankoOperation{ObjectMeta: metav1.ObjectMeta{Name: "approval-boundary", Namespace: "auth"}, Spec: api.HankoOperationSpec{Type: api.OperationClone, InstanceRef: "source", Clone: &api.CloneSpec{TargetName: "target"}}}
	if err := writer.Create(ctx, op); err != nil {
		t.Fatal("ordinary author cannot submit an unapproved request", err)
	}
	approved := op.DeepCopy()
	approved.Annotations = map[string]string{"hanko.sh/lifecycle-approval": "administrator-reviewed-intent"}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = writer.Update(ctx, approved.DeepCopy(), client.DryRunAll)
		if apierrors.IsForbidden(err) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("lifecycle approval policy did not propagate: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for name, actor := range map[string]client.Client{"author": writer, "operator": operator} {
		t.Run(name+" cannot approve", func(t *testing.T) {
			if err := actor.Update(ctx, approved.DeepCopy(), client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "independent administrator") {
				t.Fatalf("self-approval was not refused: %v", err)
			}
		})
	}
	if err := admin.Update(ctx, approved); err != nil {
		t.Fatal("independent administrator cannot approve", err)
	}
	controller := true
	child := &api.HankoSnapshot{ObjectMeta: metav1.ObjectMeta{Name: "op-approval-boundary-snap", Namespace: "auth", Annotations: map[string]string{"hanko.sh/operation-intent": "bound-intent"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoOperation", Name: op.Name, UID: types.UID(op.UID), Controller: &controller}}}, Spec: api.HankoSnapshotSpec{InstanceRef: "source"}}
	if err := writer.Create(ctx, child.DeepCopy(), client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("ordinary author forged operation child provenance: %v", err)
	}
	if err := operator.Create(ctx, child); err != nil {
		t.Fatal("operator cannot create its operation child", err)
	}
	child.OwnerReferences, child.Annotations = nil, nil
	if err := writer.Update(ctx, child, client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("ordinary author stripped operation child provenance: %v", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	if policy.Status.TypeChecking != nil && len(policy.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatalf("lifecycle policy CEL type warnings: %#v", policy.Status.TypeChecking.ExpressionWarnings)
	}
}
