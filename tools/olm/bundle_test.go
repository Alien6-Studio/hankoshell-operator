package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/Alien6-Studio/hankoshell-operator/internal/installation"
)

func chartFixture(t *testing.T) (*chartSource, options) {
	t.Helper()
	opts := options{chart: "../../charts/hankoshell-operator", helm: "helm", namespace: defaultNamespace, kubernetes: "1.37.0", image: imageRepository + "@sha256:" + strings.Repeat("a", 64), catalog: "operatorhubio-catalog", catalogNamespace: "olm"}
	chart, err := render(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return chart, opts
}

func TestBundleRetainsChartSecurityAndOLMOwnership(t *testing.T) {
	chart, opts := chartFixture(t)
	output := filepath.Join(t.TempDir(), "bundle")
	if err := run([]string{"bundle", "--chart", opts.chart, "--output", output, "--image", opts.image}); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(output, "manifests", "*.yaml"))
	if err != nil || len(files) != 18 {
		t.Fatalf("unexpected generated API inventory: %v", err)
	}
	csv, err := clusterServiceVersion(chart, opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(csv)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	owned, _, _ := unstructured.NestedSlice(document, "spec", "customresourcedefinitions", "owned")
	if len(owned) != len(chart.CRDs) {
		t.Fatal("bundle dropped owned APIs")
	}
	strategy, _, _ := unstructured.NestedSlice(document, "spec", "install", "spec", "deployments")
	deployment := strategy[0].(map[string]any)["spec"].(map[string]any)
	manager := deployment["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if manager["image"] != opts.image {
		t.Fatal("operator image is not pinned to approved digest")
	}
	joined, _ := json.Marshal(manager)
	if !strings.Contains(string(joined), "--installation-contract-sha256=$(HANKO_INSTALLATION_CONTRACT_SHA256)") || !strings.Contains(string(joined), "--watch-namespace=$(POD_NAMESPACE)") || !strings.Contains(string(joined), "--require-installation-contract=true") {
		t.Fatal("bundle can bypass installation or namespace verification")
	}
	if !strings.Contains(string(joined), `"readOnlyRootFilesystem":true`) || !strings.Contains(string(joined), `"allowPrivilegeEscalation":false`) {
		t.Fatal("bundle weakened container security")
	}
	for _, rule := range operatorRules(chart.Role.Rules) {
		assertBoundedRule(t, rule)
	}
	contract, err := installationContract(chart, opts)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, object := range contract.Objects {
		counts[object.Kind]++
	}
	if counts["ValidatingAdmissionPolicy"] < 8 || counts["NetworkPolicy"] != 2 {
		t.Fatal("chart protections omitted")
	}
}

func assertBoundedRule(t *testing.T, rule rbacv1.PolicyRule) {
	t.Helper()
	if contains(rule.Resources, "secrets") && (contains(rule.Verbs, "list") || contains(rule.Verbs, "watch")) {
		t.Fatal("bundle grants bulk credential reads")
	}
	for _, resource := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts"} {
		if contains(rule.Resources, resource) && (contains(rule.Verbs, "create") || contains(rule.Verbs, "update") || contains(rule.Verbs, "patch") || contains(rule.Verbs, "delete")) {
			t.Fatal("bundle can mutate installation authority")
		}
	}
	if contains(rule.Resources, "deployments") && contains(rule.ResourceNames, deploymentName) && (contains(rule.Verbs, "update") || contains(rule.Verbs, "patch") || contains(rule.Verbs, "delete")) {
		t.Fatal("operator can mutate its OLM-owned deployment")
	}
}

func TestPreparationIndependentlyBindsImmutableProtectionContract(t *testing.T) {
	_, opts := chartFixture(t)
	opts.namespace = "another-namespace"
	var err error
	chart, err := render(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := writeInstallation(directory, chart, opts); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "installation.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// Decode as unstructured because this document deliberately also contains
	// OLM CRs, without adding the OLM controller as an operator dependency.
	objects, err := decodeInstallation(data)
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	var approvedHash, mountedName string
	for _, object := range objects {
		encoded, _ := json.Marshal(object.Object)
		if object.GetKind() == "ConfigMap" {
			if err := json.Unmarshal(encoded, &cm); err != nil {
				t.Fatal(err)
			}
		}
		if object.GetKind() == "Subscription" {
			envs, _, _ := unstructured.NestedSlice(object.Object, "spec", "config", "env")
			for _, entry := range envs {
				env := entry.(map[string]any)
				if env["name"] == "HANKO_INSTALLATION_CONTRACT_SHA256" {
					approvedHash = env["value"].(string)
				}
				if env["name"] == "HANKO_INSTALLATION_CONTRACT_CONFIGMAP" {
					mountedName = env["value"].(string)
				}
			}
		}
		if object.GetKind() == "Deployment" || object.GetKind() == "CustomResourceDefinition" || object.GetKind() == "ServiceAccount" {
			t.Fatal("administrator preparation takes over an OLM-owned object")
		}
	}
	if cm.Immutable == nil || !*cm.Immutable || cm.Name != mountedName || approvedHash == "" {
		t.Fatal("contract is mutable or approval/mount missing")
	}
	path := filepath.Join(directory, "contract.json")
	if err := os.WriteFile(path, []byte(cm.Data["contract.json"]), 0o600); err != nil {
		t.Fatal(err)
	}
	contract, err := installation.Load(path, approvedHash)
	if err != nil || contract.Namespace != opts.namespace {
		t.Fatalf("contract does not bind administrator protections: %v", err)
	}
}

func TestPublicBundleRejectsSiteInput(t *testing.T) {
	for _, flags := range [][]string{{"--values", "private-values.yaml"}, {"--namespace", "site-namespace"}, {"--image", "registry.example.com/private:latest"}} {
		args := append([]string{"bundle", "--output", filepath.Join(t.TempDir(), "bundle")}, flags...)
		if err := run(args); err == nil {
			t.Fatal("public bundle accepted site-specific input")
		}
	}
}

func decodeInstallation(data []byte) ([]*unstructured.Unstructured, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var objects []*unstructured.Unstructured
	for {
		var object unstructured.Unstructured
		if err := decoder.Decode(&object); err != nil {
			if err == io.EOF {
				return objects, nil
			}
			return nil, err
		}
		objects = append(objects, &object)
	}
}
