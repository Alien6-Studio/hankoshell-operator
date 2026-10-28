package installation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixture(t *testing.T) (*Contract, []client.Object) {
	t.Helper()
	contract := &Contract{Namespace: "test-operator", Deployment: "test-operator", MinimumKubernetes: "1.35.0", MaximumKubernetes: "1.38.0"}
	objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: contract.Namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}}}}
	appendProtection := func(kind string, object client.Object, spec any) {
		encoded, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		apiVersion := "admissionregistration.k8s.io/v1"
		if kind == "NetworkPolicy" {
			apiVersion = "networking.k8s.io/v1"
		}
		contract.Objects = append(contract.Objects, Object{APIVersion: apiVersion, Kind: kind, Name: object.GetName(), Namespace: object.GetNamespace(), Spec: encoded})
		objects = append(objects, object)
	}
	for i := range 8 {
		name := fmt.Sprintf("guard-%d", i)
		fail := admissionv1.Fail
		policy := &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1}, Spec: admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Validations: []admissionv1.Validation{{Expression: "false"}}}, Status: admissionv1.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admissionv1.TypeChecking{}}}
		binding := &admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: name, ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny, admissionv1.Audit}}}
		appendProtection("ValidatingAdmissionPolicy", policy, policy.Spec)
		appendProtection("ValidatingAdmissionPolicyBinding", binding, binding.Spec)
	}
	for i := range 2 {
		policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("network-%d", i), Namespace: contract.Namespace}, Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}
		appendProtection("NetworkPolicy", policy, policy.Spec)
	}
	for i := range 17 {
		name := fmt.Sprintf("examples%d.hanko.sh", i)
		kind := fmt.Sprintf("Example%d", i)
		contract.CRDs = append(contract.CRDs, CRD{Name: name, Kind: kind, Version: "v1alpha1"})
		objects = append(objects, &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: apiextensionsv1.CustomResourceDefinitionSpec{Group: "hanko.sh", Names: apiextensionsv1.CustomResourceDefinitionNames{Kind: kind}, Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true}}}, Status: apiextensionsv1.CustomResourceDefinitionStatus{StoredVersions: []string{"v1alpha1"}, Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue}}}})
	}
	return contract, objects
}

func reader(t *testing.T, objects []client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, admissionv1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme, apiextensionsv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestVerifyInstallationFailsClosed(t *testing.T) {
	tests := []struct {
		name, version, namespace, want string
		change                         func([]client.Object) []client.Object
	}{
		{name: "complete", version: "v1.37.0", namespace: "test-operator"},
		{name: "old kubernetes", version: "v1.34.0", namespace: "test-operator", want: "qualification window"},
		{name: "new kubernetes", version: "v1.38.0", namespace: "test-operator", want: "qualification window"},
		{name: "prerelease kubernetes", version: "v1.37.0-beta.1", namespace: "test-operator", want: "qualification window"},
		{name: "another namespace", version: "v1.37.0", namespace: "other", want: "another namespace"},
		{name: "pod security weakened", want: "Restricted", change: func(objects []client.Object) []client.Object {
			objects[0].(*corev1.Namespace).Labels["pod-security.kubernetes.io/enforce"] = "baseline"
			return objects
		}},
		{name: "policy missing", want: "cannot verify required protection", change: func(objects []client.Object) []client.Object { return append(objects[:1], objects[2:]...) }},
		{name: "policy ignores denial", want: "differs", change: func(objects []client.Object) []client.Object {
			ignore := admissionv1.Ignore
			objects[1].(*admissionv1.ValidatingAdmissionPolicy).Spec.FailurePolicy = &ignore
			return objects
		}},
		{name: "policy not type checked", want: "type checking", change: func(objects []client.Object) []client.Object {
			objects[1].(*admissionv1.ValidatingAdmissionPolicy).Status.ObservedGeneration = 0
			return objects
		}},
		{name: "binding audit only", want: "differs", change: func(objects []client.Object) []client.Object {
			objects[2].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Audit}
			return objects
		}},
		{name: "network opened", want: "differs", change: func(objects []client.Object) []client.Object {
			objects[17].(*networkingv1.NetworkPolicy).Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
			return objects
		}},
		{name: "storage migration required", want: "storage migration", change: func(objects []client.Object) []client.Object {
			objects[19].(*apiextensionsv1.CustomResourceDefinition).Status.StoredVersions = []string{"v1alpha1", "v1beta1"}
			return objects
		}},
		{name: "crd not established", want: "expected storage", change: func(objects []client.Object) []client.Object {
			objects[19].(*apiextensionsv1.CustomResourceDefinition).Status.Conditions = nil
			return objects
		}},
		{name: "helm collision", want: "another operator installation", change: func(objects []client.Object) []client.Object {
			return append(objects, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "helm-operator", Namespace: "test-operator"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "hanko-operator"}}}}})
		}},
		{name: "helm role retained", want: "helm still owns", change: func(objects []client.Object) []client.Object {
			return append(objects, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "test-operator", Namespace: "test-operator", Labels: map[string]string{"app.kubernetes.io/managed-by": "Helm"}}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contract, objects := fixture(t)
			if test.change != nil {
				objects = test.change(objects)
			}
			if test.version == "" {
				test.version = "v1.37.0"
			}
			if test.namespace == "" {
				test.namespace = contract.Namespace
			}
			err := contract.Verify(context.Background(), reader(t, objects), test.namespace, test.version)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want %q, got %v", test.want, err)
			}
		})
	}
}

func TestContractApprovalCannotComeFromMutableContent(t *testing.T) {
	contract, _ := fixture(t)
	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "contract.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	if _, err := Load(path, hash); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "not-a-digest", strings.Repeat("0", 64)} {
		if _, err := Load(path, invalid); err == nil {
			t.Fatal("accepted unapproved contract")
		}
	}
	contract.Namespace = "another-namespace"
	changed, _ := json.Marshal(contract)
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, hash); err == nil {
		t.Fatal("accepted changed contract with old approval")
	}
	for _, malformed := range []string{`{"unknown":true}`, string(data) + "{}", strings.Repeat(" ", MaxContractBytes+1)} {
		if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(malformed))
		if _, err := Load(path, hex.EncodeToString(digest[:])); err == nil {
			t.Fatal("accepted malformed or oversized approved content")
		}
	}
}

func TestContractRejectsOmittedAndUnknownProtection(t *testing.T) {
	contract, _ := fixture(t)
	contract.Objects = contract.Objects[1:]
	if err := contract.Validate(); err == nil {
		t.Fatal("accepted missing baseline policy")
	}
	contract, _ = fixture(t)
	contract.Objects[0].Spec = json.RawMessage(`{"futureUnknownGuard":true}`)
	if err := contract.Validate(); err == nil {
		t.Fatal("accepted unrecognized security fields")
	}
}

func TestAdmissionAPIDefaultsDoNotChangeApprovedMeaning(t *testing.T) {
	for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		field := "matchConstraints"
		if kind == "ValidatingAdmissionPolicyBinding" {
			field = "matchResources"
		}
		minimal := []byte(`{"` + field + `":{"resourceRules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["secrets"],"operations":["CREATE"]}],"excludeResourceRules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["configmaps"],"operations":["CREATE"]}]}}`)
		var typed map[string]any
		if err := json.Unmarshal(minimal, &typed); err != nil {
			t.Fatal(err)
		}
		match := typed[field].(map[string]any)
		match["matchPolicy"] = "Equivalent"
		match["namespaceSelector"] = map[string]any{}
		match["objectSelector"] = map[string]any{}
		for _, key := range []string{"resourceRules", "excludeResourceRules"} {
			match[key].([]any)[0].(map[string]any)["scope"] = "*"
		}
		defaulted, _ := json.Marshal(typed)
		want, err := canonicalSpec(kind, minimal)
		if err != nil {
			t.Fatal(err)
		}
		got, err := canonicalSpec(kind, defaulted)
		if err != nil || !bytes.Equal(want, got) {
			t.Fatalf("legitimate API defaults caused installation drift for %s: %v", kind, err)
		}
	}
}
