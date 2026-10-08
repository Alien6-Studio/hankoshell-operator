//go:build integration

package v1alpha1_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// TestKubernetesCompatibility qualifies the API boundary, not nodes, CNI or providers.
func TestKubernetesCompatibility(t *testing.T) {
	assets, version := os.Getenv("KUBEBUILDER_ASSETS"), os.Getenv("KUBERNETES_VERSION")
	if assets == "" || version == "" {
		t.Fatal("use make integration-test to select reviewed Kubernetes assets")
	}
	chart := filepath.Join("..", "..", "charts", "hankoshell-operator")
	environment := &envtest.Environment{
		BinaryAssetsDirectory: assets,
		CRDDirectoryPaths:     []string{filepath.Join(chart, "crds")},
		ErrorIfCRDPathMissing: true,
	}
	environment.ControlPlane.GetAPIServer().Configure().Set("enable-admission-plugins", "PodSecurity")
	config, err := environment.Start()
	if err != nil {
		t.Fatalf("start Kubernetes %s: %v", version, err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop Kubernetes: %v", err)
		}
	})
	if len(environment.CRDs) != 16 {
		t.Fatalf("installed %d CRDs, want 16", len(environment.CRDs))
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := discoveryClient.ServerVersion()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimPrefix(server.GitVersion, "v") != version {
		t.Fatalf("server version = %v, want %s: %v", server, version, err)
	}
	t.Logf("qualifying Kubernetes %s with all 16 CRDs", server.GitVersion)
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	policyVersion := "v" + strings.Join(strings.Split(version, ".")[:2], ".")
	for _, name := range []string{"auth", "other"} {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			"pod-security.kubernetes.io/enforce":         "restricted",
			"pod-security.kubernetes.io/enforce-version": policyVersion,
		}}}
		if err := admin.Create(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("instance-administrative-capability-contract", func(t *testing.T) {
		instance := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance",
			"metadata": map[string]any{"name": "capability-defaults", "namespace": "auth"},
			"spec": map[string]any{"mode": "adopted", "adminRef": map[string]any{"name": "existing-admin"},
				"adopted": map[string]any{"deploymentRef": "existing-keycloak", "serviceRef": "existing-keycloak"}},
		}}
		if err := admin.Create(ctx, instance); err != nil {
			t.Fatal(err)
		}
		paths := [][]string{{"spec", "hardenMasterRealm"}, {"spec", "rotateAdminCredentials"}, {"spec", "adopted", "publishDiscovery"}}
		for index, path := range paths {
			value, found, err := unstructured.NestedBool(instance.Object, path...)
			if err != nil || !found || value {
				t.Fatalf("optional authority is not disabled by default at %v", path)
			}
			bad := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance",
				"metadata": map[string]any{"name": []string{"bad-hardening", "bad-rotation", "bad-discovery"}[index], "namespace": "auth"},
			}}
			bad.Object["spec"] = instance.DeepCopy().Object["spec"]
			if err := unstructured.SetNestedField(bad.Object, "true", path...); err != nil {
				t.Fatal(err)
			}
			if err := admin.Create(ctx, bad); !apierrors.IsInvalid(err) {
				t.Fatalf("nonboolean authority admitted at %v: %v", path, err)
			}
		}
		for _, path := range paths {
			if err := unstructured.SetNestedField(instance.Object, true, path...); err != nil {
				t.Fatal(err)
			}
		}
		if err := admin.Update(ctx, instance); err != nil {
			t.Fatal(err)
		}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			value, found, err := unstructured.NestedBool(instance.Object, path...)
			if err != nil || !found || !value {
				t.Fatalf("explicit authority not preserved at %v", path)
			}
		}
	})

	t.Run("managed-instance-transport-schema", func(t *testing.T) {
		instance := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance",
			"metadata": map[string]any{"name": "managed-transport", "namespace": "auth"},
			"spec":     map[string]any{"mode": "managed", "adminRef": map[string]any{"name": "admin"}},
		}}
		if err := admin.Create(ctx, instance); !apierrors.IsInvalid(err) {
			t.Fatalf("managed without managed spec admitted: %v", err)
		}
		managed := map[string]any{"image": "registry.example/keycloak@sha256:" + strings.Repeat("a", 64), "database": map[string]any{"name": "db"}}
		if err := unstructured.SetNestedMap(instance.Object, managed, "spec", "managed"); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, instance); !apierrors.IsInvalid(err) {
			t.Fatalf("managed without serving TLS or opt-in admitted: %v", err)
		}
		if err := unstructured.SetNestedField(instance.Object, "serving-tls", "spec", "managed", "tlsSecretRef"); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, instance); err != nil {
			t.Fatal(err)
		}
		allow, found, err := unstructured.NestedBool(instance.Object, "spec", "managed", "allowInsecureHTTP")
		if err != nil || !found || allow {
			t.Fatal("managed transport does not default to HTTPS")
		}
		if err := unstructured.SetNestedField(instance.Object, true, "spec", "managed", "allowInsecureHTTP"); err != nil {
			t.Fatal(err)
		}
		if err := admin.Update(ctx, instance); !apierrors.IsInvalid(err) {
			t.Fatalf("ambiguous HTTP/TLS listener admitted: %v", err)
		}
		unstructured.RemoveNestedField(instance.Object, "spec", "managed", "tlsSecretRef")
		if err := admin.Update(ctx, instance); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("database-snapshot-execution-contract", func(t *testing.T) {
		checkSnapshotBackupContract(t, ctx, admin, scheme)
	})

	t.Run("chart-and-restricted-admission", func(t *testing.T) {
		deployment := installCompatibilityChart(t, ctx, admin, chart, version, nil)
		checkRestrictedAdmission(t, ctx, admin, deployment)
		armor := installCompatibilityChart(t, ctx, admin, chart, version, []string{"--set", "hardening.appArmor=true"})
		if armor.Spec.Template.Spec.SecurityContext.AppArmorProfile == nil || armor.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type != corev1.AppArmorProfileTypeRuntimeDefault {
			t.Fatal("API server did not preserve RuntimeDefault AppArmor")
		}
		if server.Minor != "35" {
			isolated := installCompatibilityChart(t, ctx, admin, chart, version, []string{
				"--set", "hardening.appArmor=true,hardening.userNamespaces=true",
			})
			if isolated.Spec.Template.Spec.HostUsers == nil || *isolated.Spec.Template.Spec.HostUsers {
				t.Fatal("API server did not preserve the requested user namespace isolation")
			}
		}
		installCompatibilityChart(t, ctx, admin, chart, version, []string{
			"--set", "profile=enterprise,hub.enabled=true,continuum.enabled=true,keycloak.enabled=false",
			"--set-string", "image.digest=sha256:" + strings.Repeat("0", 64),
			"--set-string", "hub.tenantID=tenant-acme,hub.endpoint=https://hub.mesh.example:9443",
			"--set-string", "continuum.hubAddress=10.250.0.1,continuum.hubHostname=hub.mesh.example",
		})
	})
	t.Run("metrics-service-and-network-boundary", func(t *testing.T) {
		values := filepath.Join(t.TempDir(), "metrics.yaml")
		if err := os.WriteFile(values, []byte(`metrics:
  enabled: true
  networkPolicy:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring
    podSelector:
      matchLabels:
        app: prometheus
`), 0o600); err != nil {
			t.Fatal(err)
		}
		installCompatibilityChart(t, ctx, admin, chart, version, []string{"--values", values})
		service := &corev1.Service{}
		if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "compatibility-hanko-operator-metrics"}, service); err != nil {
			t.Fatal(err)
		}
		if service.Spec.Type != corev1.ServiceTypeClusterIP || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8080 || service.Spec.Ports[0].TargetPort.StrVal != "metrics" {
			t.Fatalf("unexpected metrics Service: %#v", service.Spec)
		}
		policy := &networkingv1.NetworkPolicy{}
		if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "compatibility-hanko-operator"}, policy); err != nil {
			t.Fatal(err)
		}
		if len(policy.Spec.Ingress) != 1 || len(policy.Spec.Ingress[0].From) != 1 || len(policy.Spec.Ingress[0].Ports) != 1 {
			t.Fatalf("metrics ingress must have exactly one peer and port: %#v", policy.Spec.Ingress)
		}
		peer, port := policy.Spec.Ingress[0].From[0], policy.Spec.Ingress[0].Ports[0]
		expected := networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "monitoring"}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "prometheus"}},
		}
		if !reflect.DeepEqual(peer, expected) {
			t.Fatalf("metrics ingress lost conjunctive identity: %#v", peer)
		}
		if port.Port == nil || port.Port.IntVal != 8080 || port.Protocol == nil || *port.Protocol != corev1.ProtocolTCP || port.EndPort != nil {
			t.Fatalf("metrics ingress must allow only TCP/8080: %#v", port)
		}
	})
	user, err := environment.AddUser(envtest.User{
		Name:   "system:serviceaccount:auth:compatibility-hanko-operator",
		Groups: []string{"system:serviceaccounts", "system:serviceaccounts:auth", "system:authenticated"},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := client.New(user.Config(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("server-side-apply-and-status", func(t *testing.T) {
		checkRealmApplyAndStatus(t, ctx, operator)
	})
	t.Run("namespace-and-credential-boundaries", func(t *testing.T) {
		for _, namespace := range []string{"auth", "other"} {
			if err := admin.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Name: "credential", Namespace: namespace,
			}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := operator.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "credential"}, &corev1.Secret{}); err != nil {
			t.Fatalf("read configured namespace credential: %v", err)
		}
		denials := []error{
			operator.Get(ctx, client.ObjectKey{Namespace: "other", Name: "credential"}, &corev1.Secret{}),
			operator.List(ctx, &corev1.SecretList{}, client.InNamespace("auth")),
			operator.List(ctx, &corev1.NodeList{}),
			operator.Create(ctx, &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "escape", Namespace: "other"}}),
		}
		for _, err := range denials {
			if !apierrors.IsForbidden(err) {
				t.Errorf("expected RBAC denial, got %v", err)
			}
		}
	})
}

func installCompatibilityChart(t *testing.T, ctx context.Context, admin client.Client, chart, version string, extra []string) *appsv1.Deployment {
	t.Helper()
	args := append([]string{"template", "compatibility", chart, "--namespace", "auth", "--kube-version", version,
		"--set-string", "image.tag=fixture"}, extra...)
	var diagnostics bytes.Buffer
	// #nosec G702 -- Fixed executable and argument vector; fixture values never pass through a shell.
	command := exec.CommandContext(ctx, "helm", args...)
	command.Stderr = &diagnostics
	manifest, err := command.Output()
	if err != nil {
		t.Fatalf("render chart: %v: %s", err, &diagnostics)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	var deployment *appsv1.Deployment
	for {
		resource := &unstructured.Unstructured{}
		if err := decoder.Decode(&resource.Object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(resource.Object) == 0 {
			continue
		}
		// Strict server validation rejects fields unavailable on this API version.
		if err := admin.Create(ctx, resource.DeepCopy(), client.DryRunAll, client.FieldValidation("Strict")); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("validate %s/%s: %v", resource.GetKind(), resource.GetName(), err)
		}
		if err := admin.Apply(ctx, client.ApplyConfigurationFromUnstructured(resource), client.FieldOwner("compatibility"), client.ForceOwnership); err != nil {
			t.Fatalf("apply %s/%s: %v", resource.GetKind(), resource.GetName(), err)
		}
		if resource.GetKind() == "Deployment" {
			deployment = &appsv1.Deployment{}
			if err := admin.Get(ctx, client.ObjectKeyFromObject(resource), deployment); err != nil {
				t.Fatal(err)
			}
		}
	}
	if deployment == nil {
		t.Fatal("chart did not render the operator deployment")
	}
	// A Deployment alone does not prove PodSecurity admission accepts its pods.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "qualified", Namespace: "auth"}, Spec: deployment.Spec.Template.Spec}
	if err := admin.Create(ctx, pod, client.DryRunAll, client.FieldValidation("Strict")); err != nil {
		t.Fatalf("Restricted pod admission: %v", err)
	}
	return deployment
}

func checkRestrictedAdmission(t *testing.T, ctx context.Context, admin client.Client, deployment *appsv1.Deployment) {
	t.Helper()
	for name, mutate := range map[string]func(*corev1.Pod){
		"host-network": func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"host-probe":   func(p *corev1.Pod) { p.Spec.Containers[0].LivenessProbe.HTTPGet.Host = "127.0.0.1" },
		"privileged": func(p *corev1.Pod) {
			enabled := true
			p.Spec.Containers[0].SecurityContext.Privileged = &enabled
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = &enabled
		},
		"bpf": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"BPF"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}, Spec: *deployment.Spec.Template.Spec.DeepCopy()}
			mutate(pod)
			if err := admin.Create(ctx, pod, client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "violates PodSecurity") {
				t.Fatalf("expected Restricted admission denial, got %v", err)
			}
		})
	}
}

func checkRealmApplyAndStatus(t *testing.T, ctx context.Context, operator client.Client) {
	t.Helper()
	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm",
		"metadata": map[string]interface{}{"name": "qualified", "namespace": "auth"},
		"spec":     map[string]interface{}{"otpRequired": false, "securityProfile": map[string]interface{}{"passwordExpiryDays": int64(0)}},
	}}
	if err := operator.Apply(ctx, client.ApplyConfigurationFromUnstructured(desired), client.FieldOwner("hanko-operator")); err != nil {
		t.Fatalf("operator server-side apply: %v", err)
	}
	stored := &unstructured.Unstructured{}
	stored.SetGroupVersionKind(desired.GroupVersionKind())
	if err := operator.Get(ctx, client.ObjectKeyFromObject(desired), stored); err != nil {
		t.Fatal(err)
	}
	if value, present, err := unstructured.NestedBool(stored.Object, "spec", "otpRequired"); err != nil || !present || value {
		t.Fatalf("explicit false did not survive server-side apply: %v", stored.Object)
	}
	if value, present, err := unstructured.NestedInt64(stored.Object, "spec", "securityProfile", "passwordExpiryDays"); err != nil || !present || value != 0 {
		t.Fatalf("explicit zero did not survive server-side apply: %v", stored.Object)
	}
	realm := &hankoshv1alpha1.HankoRealm{}
	if err := operator.Get(ctx, client.ObjectKeyFromObject(desired), realm); err != nil {
		t.Fatal(err)
	}
	realm.Status.Phase = "Ready"
	if err := operator.Status().Update(ctx, realm); err != nil {
		t.Fatalf("status subresource: %v", err)
	}
	invalid := desired.DeepCopy()
	invalid.SetName("invalid")
	_ = unstructured.SetNestedField(invalid.Object, "profile", "spec", "iamProfileRef")
	if err := operator.Create(ctx, invalid); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected CEL rejection for conflicting IAM profiles, got %v", err)
	}
}
