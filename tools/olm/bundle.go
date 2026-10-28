package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	sigsyaml "sigs.k8s.io/yaml"
)

func writeBundle(directory string, chart *chartSource, opts options) error {
	csv, err := clusterServiceVersion(chart, opts)
	if err != nil {
		return err
	}
	if err := writeYAML(filepath.Join(directory, "manifests", packageName+".clusterserviceversion.yaml"), csv); err != nil {
		return err
	}
	for _, object := range chart.Objects {
		if object.GetKind() == "CustomResourceDefinition" {
			if err := writeYAML(filepath.Join(directory, "manifests", object.GetName()+".yaml"), object); err != nil {
				return err
			}
		}
	}
	annotations := map[string]string{
		"operators.operatorframework.io.bundle.mediatype.v1":       "registry+v1",
		"operators.operatorframework.io.bundle.manifests.v1":       "manifests/",
		"operators.operatorframework.io.bundle.metadata.v1":        "metadata/",
		"operators.operatorframework.io.bundle.package.v1":         packageName,
		"operators.operatorframework.io.bundle.channels.v1":        "alpha",
		"operators.operatorframework.io.bundle.channel.default.v1": "alpha",
	}
	if err := writeYAML(filepath.Join(directory, "metadata", "annotations.yaml"), map[string]any{"annotations": annotations}); err != nil {
		return err
	}
	if err := writeYAML(filepath.Join(directory, "tests", "scorecard", "config.yaml"), map[string]any{
		"apiVersion": "scorecard.operatorframework.io/v1alpha3", "kind": "Configuration",
		"metadata": map[string]string{"name": "config"},
		"stages": []any{map[string]any{"parallel": true, "tests": []any{
			map[string]any{"image": "quay.io/operator-framework/scorecard-test:v1.42.3", "entrypoint": []string{"scorecard-test", "basic-check-spec"}, "labels": map[string]string{"suite": "basic", "test": "basic-check-spec-test"}},
			map[string]any{"image": "quay.io/operator-framework/scorecard-test:v1.42.3", "entrypoint": []string{"scorecard-test", "olm-bundle-validation"}, "labels": map[string]string{"suite": "olm", "test": "olm-bundle-validation-test"}},
		}}},
	}); err != nil {
		return err
	}
	dockerfile := "FROM scratch\nCOPY manifests /manifests/\nCOPY metadata /metadata/\nCOPY tests /tests/\n"
	if err := os.WriteFile(filepath.Join(directory, "bundle.Dockerfile"), []byte(dockerfile), 0o644); err != nil { // #nosec G306 -- Public bundle metadata, readable by OLM's non-root unpacker; no administrator values are accepted.
		return fmt.Errorf("write bundle Dockerfile: %w", err)
	}
	return nil
}

func clusterServiceVersion(chart *chartSource, opts options) (map[string]any, error) {
	icon, err := os.ReadFile(filepath.Join(opts.chart, "icon.svg"))
	if err != nil {
		return nil, fmt.Errorf("read bundle icon: %w", err)
	}
	deployment := chart.Deployment.DeepCopy()
	deployment.Spec.Template.Spec.ServiceAccountName = deploymentName
	manager := &deployment.Spec.Template.Spec.Containers[0]
	manager.Env = append(operatorEnvironment(*manager),
		corev1.EnvVar{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
		corev1.EnvVar{Name: "HANKO_INSTALLATION_CONTRACT_SHA256", Value: ""},
		corev1.EnvVar{Name: "HANKO_INSTALLATION_CONTRACT_CONFIGMAP", Value: configurationName},
	)
	for i, arg := range manager.Args {
		if strings.HasPrefix(arg, "--watch-namespace=") {
			manager.Args[i] = "--watch-namespace=$(POD_NAMESPACE)"
		}
	}
	manager.Args = append(manager.Args, "--require-installation-contract=true", "--installation-configmap=$(HANKO_INSTALLATION_CONTRACT_CONFIGMAP)", "--installation-contract-sha256=$(HANKO_INSTALLATION_CONTRACT_SHA256)")
	var owned []any
	for _, crd := range chart.CRDs {
		owned = append(owned, map[string]any{"name": crd.Name, "kind": crd.Spec.Names.Kind, "version": "v1alpha1", "displayName": crd.Spec.Names.Kind, "description": "Experimental v1alpha1 API. " + crd.Spec.Names.Kind + " reconciles only in the operator's own namespace."})
	}
	var clusterRules []rbacv1.PolicyRule
	for _, role := range chart.ClusterRoles {
		clusterRules = append(clusterRules, operatorRules(role.Rules)...)
	}
	examples, err := json.Marshal([]any{
		map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": map[string]string{"name": "example"}, "spec": map[string]any{"displayName": "Example"}},
		map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": map[string]string{"name": "customer-portal"}, "spec": map[string]any{"realmRef": "example", "clientID": "customer-portal", "type": "spa", "redirectURIs": []string{"https://portal.example.com/callback"}}},
	})
	if err != nil {
		return nil, err
	}
	annotations := map[string]string{
		"capabilities": "Basic Install", "categories": "Security", "containerImage": opts.image,
		"repository": "https://github.com/Alien6-Studio/hankoshell-operator", "support": "Alien6 Studio",
		"alm-examples": string(examples), "operatorframework.io/suggested-namespace": defaultNamespace,
		"operators.operatorframework.io/arch.amd64": "supported", "operators.operatorframework.io/arch.arm64": "supported",
		"operators.operatorframework.io/os.linux": "supported",
	}
	spec := map[string]any{
		"displayName": "HankoShell Operator", "description": bundleDescription,
		"version": chart.Version, "minKubeVersion": "1.35.0", "maturity": "alpha",
		"provider":    map[string]string{"name": "Alien6 Studio", "url": "https://hanko.sh"},
		"maintainers": []any{map[string]string{"name": "Alien6 Studio", "email": "contact@alien6.com"}},
		"keywords":    []string{"keycloak", "iam", "oidc", "gitops"}, "license": "Apache-2.0",
		"links":                     []any{map[string]string{"name": "Documentation", "url": "https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/operatorhub.md"}, map[string]string{"name": "Source", "url": "https://github.com/Alien6-Studio/hankoshell-operator"}},
		"icon":                      []any{map[string]string{"base64data": base64.StdEncoding.EncodeToString(icon), "mediatype": "image/svg+xml"}},
		"installModes":              []any{map[string]any{"type": "OwnNamespace", "supported": true}, map[string]any{"type": "SingleNamespace", "supported": false}, map[string]any{"type": "MultiNamespace", "supported": false}, map[string]any{"type": "AllNamespaces", "supported": false}},
		"customresourcedefinitions": map[string]any{"owned": owned},
		"nativeAPIs":                []any{map[string]string{"group": "admissionregistration.k8s.io", "version": "v1", "kind": "ValidatingAdmissionPolicy"}, map[string]string{"group": "admissionregistration.k8s.io", "version": "v1", "kind": "ValidatingAdmissionPolicyBinding"}},
		"relatedImages":             []any{map[string]string{"name": "hankoshell-operator", "image": opts.image}},
		"install": map[string]any{"strategy": "deployment", "spec": map[string]any{
			"deployments":        []any{map[string]any{"name": deploymentName, "spec": deployment.Spec}},
			"permissions":        []any{map[string]any{"serviceAccountName": deploymentName, "rules": operatorRules(chart.Role.Rules)}},
			"clusterPermissions": []any{map[string]any{"serviceAccountName": deploymentName, "rules": clusterRules}},
		}},
	}
	if opts.replaces != "" {
		spec["replaces"] = opts.replaces
	}
	return map[string]any{"apiVersion": "operators.coreos.com/v1alpha1", "kind": "ClusterServiceVersion", "metadata": map[string]any{"name": packageName + ".v" + chart.Version, "annotations": annotations}, "spec": spec}, nil
}

const bundleDescription = `Manage Keycloak realms, OIDC clients, machine identities, roles and organizations declaratively from Kubernetes.

Administrator preparation is REQUIRED before installation: follow https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/operatorhub.md. OLM does not install the chart's admission policies. The preparation command renders admission and network protections from the chart, an immutable installation contract and a Subscription with its independently approved hash. Missing, incompatible or changed protections prevent the operator from starting. A NetworkPolicy-enforcing CNI is required.

This alpha channel supports one namespace, the standard Keycloak profile, Linux amd64/arm64 and qualified Kubernetes 1.35–1.37. All 17 hanko.sh/v1alpha1 APIs remain experimental. Lifecycle operations stay disabled. Use Helm for connected Hub, lifecycle, experimental provider and advanced integration profiles. Do not install over a Helm-owned operator or share its watched namespace. Provider objects and custom resources are retained when the operator is removed; review finalizers before deleting CRDs.`

func writeYAML(path string, object any) error {
	data, err := sigsyaml.Marshal(object)
	if err != nil {
		return fmt.Errorf("encode generated YAML: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { // #nosec G306 -- Public bundle manifests must be readable by OLM's non-root unpacker.
		return fmt.Errorf("write generated YAML: %w", err)
	}
	return nil
}

func installationMetadata(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/part-of": packageName, "app.kubernetes.io/managed-by": "hankoshell-installation"}}
}

func administratorObject(source *unstructured.Unstructured) *unstructured.Unstructured {
	object := source.DeepCopy()
	object.SetLabels(installationMetadata("", "").Labels)
	object.SetAnnotations(nil)
	return object
}
