package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

type chartSource struct {
	Version      string
	Objects      []*unstructured.Unstructured
	Deployment   appsv1.Deployment
	Role         rbacv1.Role
	ClusterRoles []rbacv1.ClusterRole
	CRDs         []apiextensionsv1.CustomResourceDefinition
}

func render(ctx context.Context, opts options) (*chartSource, error) {
	data, err := os.ReadFile(filepath.Join(opts.chart, "Chart.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read chart metadata: %w", err)
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if err := sigsyaml.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("decode chart metadata: %w", err)
	}
	args := []string{"template", packageName, opts.chart, "--namespace", opts.namespace, "--kube-version", opts.kubernetes, "--include-crds", "--set-string", "fullnameOverride=" + deploymentName}
	if opts.image != "" {
		parts := strings.SplitN(opts.image, "@", 2)
		if len(parts) != 2 || parts[0] != imageRepository {
			return nil, errors.New("operator image must use the public repository and an immutable digest")
		}
		args = append(args, "--set-string", "image.repository="+parts[0], "--set-string", "image.digest="+parts[1])
	} else {
		// Installation output contains no Deployment: the catalog owns its image.
		args = append(args, "--set-string", "image.tag=installation-render")
	}
	if opts.values != "" {
		args = append(args, "--values", opts.values)
	}
	command := exec.CommandContext(ctx, opts.helm, args...) // #nosec G204 -- Explicit administrator-selected Helm executable; arguments are never interpreted by a shell.
	data, err = command.Output()
	if err != nil {
		return nil, errors.New("helm rendering failed; verify the chart and administrator values")
	}
	return decodeChart(data, metadata.Version)
}

func decodeChart(data []byte, version string) (*chartSource, error) {
	result := &chartSource{Version: version}
	deployments, roles := 0, 0
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		object := &unstructured.Unstructured{Object: raw}
		result.Objects = append(result.Objects, object)
		if object.GetKind() == "Deployment" {
			deployments++
		}
		if object.GetKind() == "Role" {
			roles++
		}
		if err := result.decodeObject(object); err != nil {
			return nil, err
		}
	}
	if deployments != 1 || roles != 1 || len(result.Deployment.Spec.Template.Spec.Containers) != 1 || result.Role.Name == "" || len(result.CRDs) != 17 {
		return nil, errors.New("unexpected chart installation inventory")
	}
	return result, nil
}

func (c *chartSource) decodeObject(object *unstructured.Unstructured) error {
	encoded, err := json.Marshal(object.Object)
	if err != nil {
		return err
	}
	switch object.GetKind() {
	case "Deployment":
		return json.Unmarshal(encoded, &c.Deployment)
	case "Role":
		return json.Unmarshal(encoded, &c.Role)
	case "ClusterRole":
		var role rbacv1.ClusterRole
		if err := json.Unmarshal(encoded, &role); err != nil {
			return err
		}
		c.ClusterRoles = append(c.ClusterRoles, role)
	case "CustomResourceDefinition":
		var crd apiextensionsv1.CustomResourceDefinition
		if err := json.Unmarshal(encoded, &crd); err != nil {
			return err
		}
		c.CRDs = append(c.CRDs, crd)
	case "ServiceAccount", "RoleBinding", "ClusterRoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "NetworkPolicy":
	default:
		return fmt.Errorf("the initial OLM profile does not support chart resource %s", object.GetKind())
	}
	return nil
}

func validateProfile(chart *chartSource) error {
	manager := chart.Deployment.Spec.Template.Spec.Containers[0]
	for _, arg := range manager.Args {
		if strings.HasPrefix(arg, "--lifecycle-enabled=") && arg != "--lifecycle-enabled=false" {
			return errors.New("experimental lifecycle operations require the Helm distribution")
		}
		if strings.HasPrefix(arg, "--metrics-bind-address=") && arg != "--metrics-bind-address=0" {
			return errors.New("custom metrics and integration profiles require the Helm distribution")
		}
	}
	for _, env := range manager.Env {
		if err := validateEnvironment(env); err != nil {
			return err
		}
	}
	if len(chart.Deployment.Spec.Template.Spec.InitContainers) != 0 {
		return errors.New("additional transport components require the Helm distribution")
	}
	return nil
}

func validateEnvironment(env corev1.EnvVar) error {
	if (env.Name == "HANKO_SECURITY_PROFILE" && env.Value != "standard") || (env.Name == "HANKO_EXPERIMENTAL_AUTHENTIK_ENABLED" && env.Value != "false") {
		return errors.New("the initial OLM profile supports standard Keycloak IAM only")
	}
	if strings.HasPrefix(env.Name, "HANKO_INSTALLATION_") || env.Name == "POD_NAMESPACE" {
		return errors.New("installation verification settings are reserved for OLM preparation")
	}
	connected := []string{"HANKO_HUB_URL", "HANKO_API_URL", "HANKO_SUPERVISION_API_URL", "HANKO_IMAGE_POLICY_FILE", "HANKO_DECOMMISSION_RELEASE", "HANKO_FLEET_TRUST_CONFIGMAP"}
	if contains(connected, env.Name) || strings.HasPrefix(env.Name, "HANKO_ENTERPRISE_") || strings.HasPrefix(env.Name, "HANKO_CONTINUUM_") {
		return errors.New("connected integration profiles require the Helm distribution")
	}
	if env.ValueFrom == nil && sensitiveEnvironment(env.Name) && env.Value != "" {
		return errors.New("credential values must be supplied through Secret references")
	}
	return nil
}

func sensitiveEnvironment(name string) bool {
	for _, part := range []string{"SECRET", "TOKEN", "PASSWORD"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func operatorEnvironment(container corev1.Container) []corev1.EnvVar {
	result := make([]corev1.EnvVar, 0, len(container.Env)+1)
	for _, env := range container.Env {
		if strings.HasPrefix(env.Name, "HANKO_DECOMMISSION_") || strings.HasPrefix(env.Name, "HANKO_AGENT_UPDATE_") {
			continue
		}
		result = append(result, env)
	}
	return result
}

// OLM alone owns installation Deployments and RBAC. Provider write targets
// continue to come from the chart's exact-name administrator allowlists.
func operatorRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	var result []rbacv1.PolicyRule
	for _, original := range rules {
		rule := *original.DeepCopy()
		stripInstallationMutations(&rule)
		if contains(rule.Resources, "deployments") && (contains(rule.Verbs, "update") || contains(rule.Verbs, "patch") || contains(rule.Verbs, "delete")) {
			names := make([]string, 0, len(rule.ResourceNames))
			for _, name := range rule.ResourceNames {
				if name != deploymentName {
					names = append(names, name)
				}
			}
			if len(names) == 0 {
				continue
			}
			rule.ResourceNames = names
		}
		if len(rule.Verbs) != 0 {
			result = append(result, rule)
		}
	}
	return result
}

func stripInstallationMutations(rule *rbacv1.PolicyRule) {
	installationAuthority := false
	for _, resource := range rule.Resources {
		if contains([]string{"roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts"}, resource) {
			installationAuthority = true
		}
	}
	if !installationAuthority {
		return
	}
	var verbs []string
	for _, verb := range rule.Verbs {
		if contains([]string{"get", "list", "watch"}, verb) {
			verbs = append(verbs, verb)
		}
	}
	rule.Verbs = verbs
}

func contains(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
