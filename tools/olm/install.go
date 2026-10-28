package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/version"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/Alien6-Studio/hankoshell-operator/internal/installation"
)

func installationContract(chart *chartSource, opts options) (*installation.Contract, error) {
	contract := &installation.Contract{Namespace: opts.namespace, Deployment: deploymentName, MinimumKubernetes: "1.35.0", MaximumKubernetes: "1.38.0"}
	for _, object := range chart.Objects {
		switch object.GetKind() {
		case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "NetworkPolicy":
			spec, err := json.Marshal(object.Object["spec"])
			if err != nil {
				return nil, err
			}
			contract.Objects = append(contract.Objects, installation.Object{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName(), Namespace: object.GetNamespace(), Spec: spec})
		}
	}
	for _, crd := range chart.CRDs {
		contract.CRDs = append(contract.CRDs, installation.CRD{Name: crd.Name, Kind: crd.Spec.Names.Kind, Version: "v1alpha1"})
	}
	return contract, contract.Validate()
}

func writeInstallation(directory string, chart *chartSource, opts options) error {
	contract, err := installationContract(chart, opts)
	if err != nil {
		return err
	}
	data, err := json.Marshal(contract)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	approvedHash := hex.EncodeToString(digest[:])
	objects, err := installationObjects(chart, opts, contract, data, approvedHash)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	for _, object := range objects {
		encoded, err := sigsyaml.Marshal(object)
		if err != nil {
			return fmt.Errorf("encode administrator manifest: %w", err)
		}
		output.WriteString("---\n")
		output.Write(encoded)
	}
	if err := os.WriteFile(filepath.Join(directory, "installation.yaml"), output.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write administrator installation: %w", err)
	}
	return nil
}

func installationObjects(chart *chartSource, opts options, contract *installation.Contract, data []byte, hash string) ([]any, error) {
	kubernetes, err := version.ParseSemantic(opts.kubernetes)
	if err != nil || kubernetes.PreRelease() != "" || kubernetes.Major() != 1 || kubernetes.Minor() < 35 || kubernetes.Minor() > 37 {
		return nil, fmt.Errorf("installation requires qualified stable Kubernetes 1.35–1.37")
	}
	namespace := corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: installationMetadata(opts.namespace, "")}
	namespace.Labels["pod-security.kubernetes.io/enforce"] = "restricted"
	namespace.Labels["pod-security.kubernetes.io/enforce-version"] = fmt.Sprintf("v1.%d", kubernetes.Minor())
	objects := []any{namespace}
	for _, object := range chart.Objects {
		switch object.GetKind() {
		case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "NetworkPolicy":
			objects = append(objects, administratorObject(object))
		}
	}
	immutable := true
	contractName := configurationName + "-" + hash[:12]
	objects = append(objects, corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: installationMetadata(contractName, opts.namespace), Immutable: &immutable, Data: map[string]string{"contract.json": string(data)}})
	objects = append(objects, administratorPermissions(chart, opts, contract)...)
	objects = append(objects, map[string]any{
		"apiVersion": "operators.coreos.com/v1", "kind": "OperatorGroup", "metadata": installationMetadata(packageName, opts.namespace),
		"spec": map[string]any{"targetNamespaces": []string{opts.namespace}},
	})
	manager := chart.Deployment.Spec.Template.Spec.Containers[0]
	environment := append(operatorEnvironment(manager), corev1.EnvVar{Name: "HANKO_INSTALLATION_CONTRACT_SHA256", Value: hash}, corev1.EnvVar{Name: "HANKO_INSTALLATION_CONTRACT_CONFIGMAP", Value: contractName})
	config := map[string]any{"env": environment}
	// OLM merges these administrator-approved CA mounts into the bundle's pod.
	// The baseline temporary volume remains bundle-owned.
	if len(chart.Deployment.Spec.Template.Spec.Volumes) > 1 {
		config["volumes"] = chart.Deployment.Spec.Template.Spec.Volumes[1:]
	}
	if len(manager.VolumeMounts) > 1 {
		config["volumeMounts"] = manager.VolumeMounts[1:]
	}
	objects = append(objects, map[string]any{
		"apiVersion": "operators.coreos.com/v1alpha1", "kind": "Subscription", "metadata": installationMetadata(packageName, opts.namespace),
		"spec": map[string]any{"name": packageName, "channel": "alpha", "source": opts.catalog, "sourceNamespace": opts.catalogNamespace, "installPlanApproval": "Manual", "startingCSV": packageName + ".v" + chart.Version, "config": config},
	})
	return objects, nil
}

func administratorPermissions(chart *chartSource, opts options, contract *installation.Contract) []any {
	name := deploymentName + "-" + opts.namespace + "-preparation"
	subject := rbacv1.Subject{Kind: "ServiceAccount", Name: deploymentName, Namespace: opts.namespace}
	role := rbacv1.Role{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: installationMetadata(name, opts.namespace), Rules: operatorRules(chart.Role.Rules)}
	binding := rbacv1.RoleBinding{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: installationMetadata(name, opts.namespace), Subjects: []rbacv1.Subject{subject}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}}
	clusterRules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{opts.namespace}, Verbs: []string{"get"}}}
	for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		var names []string
		for _, object := range contract.Objects {
			if object.Kind == kind {
				names = append(names, object.Name)
			}
		}
		resource := "validatingadmissionpolicies"
		if kind == "ValidatingAdmissionPolicyBinding" {
			resource = "validatingadmissionpolicybindings"
		}
		clusterRules = append(clusterRules, rbacv1.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{resource}, ResourceNames: names, Verbs: []string{"get"}})
	}
	var names []string
	for _, crd := range contract.CRDs {
		names = append(names, crd.Name)
	}
	clusterRules = append(clusterRules, rbacv1.PolicyRule{APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"}, ResourceNames: names, Verbs: []string{"get"}})
	clusterRole := rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: installationMetadata(name, ""), Rules: clusterRules}
	clusterBinding := rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: installationMetadata(name, ""), Subjects: []rbacv1.Subject{subject}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}}
	return []any{role, binding, clusterRole, clusterBinding}
}
