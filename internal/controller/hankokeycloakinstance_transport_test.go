package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func managedTestCertificate(t *testing.T, hostname string, before, after time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{hostname}, NotBefore: before, NotAfter: after,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}

func managedTestSecrets(t *testing.T, instance *hanko.HankoKeycloakInstance) []client.Object {
	t.Helper()
	cert, key := managedTestCertificate(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	return []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: instance.Spec.AdminRef.Name, Namespace: instance.Namespace}, Data: map[string][]byte{
			"HANKO_KEYCLOAK_URL": []byte("https://localhost:8443"), "HANKO_KC_CLIENT_ID": []byte("fixture"), "HANKO_KC_CLIENT_SECRET": []byte("synthetic")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "serving-tls", Namespace: instance.Namespace}, Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key}},
	}
}

func TestManagedTransportContract(t *testing.T) {
	for _, name := range []string{"https", "enterprise-https", "context-path", "missing-reference", "missing-secret", "wrong-type", "missing-key", "mismatched-key", "wrong-hostname", "expired", "not-yet-valid", "http-default", "http-process-only", "http-spec-only", "http-explicit", "http-enterprise", "http-client-ca", "mixed-tls-http", "shared-secret"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HANKO_SECURITY_PROFILE", "standard")
			t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "false")
			instance := managedTestInstance("test", "keycloak")
			objects := managedTestSecrets(t, instance)
			admin, serving := objects[0].(*corev1.Secret), objects[1].(*corev1.Secret)
			enterprise := name == "enterprise-https" || name == "http-enterprise"
			if enterprise {
				t.Setenv("HANKO_SECURITY_PROFILE", "enterprise")
			}
			if strings.HasPrefix(name, "http-") || name == "mixed-tls-http" {
				admin.Data["HANKO_KEYCLOAK_URL"] = []byte("http://localhost:8080")
				instance.Spec.Managed.TLSSecretRef = ""
			}
			switch name {
			case "context-path":
				admin.Data["HANKO_KEYCLOAK_URL"] = []byte("https://localhost:8443/auth")
			case "missing-reference":
				instance.Spec.Managed.TLSSecretRef = ""
			case "missing-secret":
				objects = objects[:1]
			case "wrong-type":
				serving.Type = corev1.SecretTypeOpaque
			case "missing-key":
				delete(serving.Data, corev1.TLSPrivateKeyKey)
			case "mismatched-key":
				_, serving.Data[corev1.TLSPrivateKeyKey] = managedTestCertificate(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			case "wrong-hostname":
				serving.Data[corev1.TLSCertKey], serving.Data[corev1.TLSPrivateKeyKey] = managedTestCertificate(t, "other.example", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			case "expired":
				serving.Data[corev1.TLSCertKey], serving.Data[corev1.TLSPrivateKeyKey] = managedTestCertificate(t, "localhost", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
			case "not-yet-valid":
				serving.Data[corev1.TLSCertKey], serving.Data[corev1.TLSPrivateKeyKey] = managedTestCertificate(t, "localhost", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
			case "http-process-only":
				t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
			case "http-spec-only":
				instance.Spec.Managed.AllowInsecureHTTP = true
			case "http-explicit", "http-enterprise", "http-client-ca", "mixed-tls-http":
				t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
				instance.Spec.Managed.AllowInsecureHTTP = true
				if name == "mixed-tls-http" {
					instance.Spec.Managed.TLSSecretRef = serving.Name
				}
				if name == "http-client-ca" {
					instance.Spec.TLSCARef = "client-ca"
				}
			case "shared-secret":
				instance.Spec.Managed.TLSSecretRef = instance.Spec.AdminRef.Name
			}
			scheme := controllerTestScheme(t)
			kube := controllerTestClient(scheme, append([]client.Object{instance}, objects...)...)
			r := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, ImageValidator: approvedFixtureValidator(t), RequireHTTPS: enterprise}
			_, handled, err := r.reconcileManagedInstance(context.Background(), instance, client.MergeFrom(instance.DeepCopy()))
			accepted := name == "https" || name == "enterprise-https" || name == "http-explicit"
			if err != nil || handled == accepted {
				t.Fatalf("accepted=%t handled=%t err=%v", accepted, handled, err)
			}
			var deployments appsv1.DeploymentList
			var services corev1.ServiceList
			var policies networkingv1.NetworkPolicyList
			for _, list := range []client.ObjectList{&deployments, &services, &policies} {
				if err := kube.List(context.Background(), list); err != nil {
					t.Fatal(err)
				}
			}
			if !accepted {
				if len(deployments.Items)+len(services.Items)+len(policies.Items) != 0 {
					t.Fatal("invalid transport mutated infrastructure")
				}
				return
			}
			port, listener := int32(8443), "https"
			if name == "http-explicit" {
				port, listener = 8080, "http"
			}
			pod := deployments.Items[0].Spec.Template.Spec
			container := pod.Containers[0]
			if container.Ports[0].ContainerPort != port || container.Ports[0].Name != listener || services.Items[0].Spec.Ports[0].Port != port || services.Items[0].Spec.Ports[0].TargetPort.IntVal != port {
				t.Fatal("listener, pod and Service disagree")
			}
			for _, rule := range policies.Items[0].Spec.Ingress {
				for _, allowed := range rule.Ports {
					if allowed.Port.IntVal != port {
						t.Fatal("unexpected ingress port, including remotely exposed management")
					}
				}
			}
			if !slices.Contains(container.Args, "--http-enabled="+map[bool]string{true: "true", false: "false"}[name == "http-explicit"]) {
				t.Fatal("listener not explicitly forced")
			}
			if !slices.Contains(container.Args, "--http-management-scheme=http") || container.ReadinessProbe.HTTPGet.Port.IntVal != 9000 || container.LivenessProbe.HTTPGet.Port.IntVal != 9000 {
				t.Fatal("probes disagree with the isolated health listener")
			}
			if name != "http-explicit" {
				if pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 1000 {
					t.Fatal("serving key is unreadable to Keycloak UID")
				}
				if !slices.ContainsFunc(container.VolumeMounts, func(m corev1.VolumeMount) bool {
					return m.Name == "serving-tls" && m.ReadOnly && m.MountPath == managedTLSMount
				}) {
					t.Fatal("missing read-only server TLS mount")
				}
				if name == "enterprise-https" && !slices.Contains(container.Args, "--https-protocols=TLSv1.3") {
					t.Fatal("enterprise permits older TLS")
				}
			}
		})
	}
}

func TestInvalidManagedTransportLeavesExistingInfrastructureUntouched(t *testing.T) {
	instance := managedTestInstance("test", "keycloak")
	scheme := controllerTestScheme(t)
	kube := controllerTestClient(scheme, append([]client.Object{instance}, managedTestSecrets(t, instance)...)...)
	r := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
	ctx := context.Background()
	if _, handled, err := r.reconcileManagedInstance(ctx, instance, client.MergeFrom(instance.DeepCopy())); err != nil || handled {
		t.Fatalf("initial transport: handled=%t err=%v", handled, err)
	}
	before := []client.Object{&appsv1.Deployment{}, &corev1.Service{}, &networkingv1.NetworkPolicy{}}
	keys := []client.ObjectKey{client.ObjectKeyFromObject(instance), client.ObjectKeyFromObject(instance), {Namespace: instance.Namespace, Name: instance.Name + "-isolation"}}
	for index, object := range before {
		if err := kube.Get(ctx, keys[index], object); err != nil {
			t.Fatal(err)
		}
	}
	instance.Spec.Managed.TLSSecretRef = "missing-serving-secret"
	instance.Spec.Managed.ThemePVC = "a-rollout-must-not-happen"
	if err := kube.Update(ctx, instance); err != nil {
		t.Fatal(err)
	}
	if _, handled, err := r.reconcileManagedInstance(ctx, instance, client.MergeFrom(instance.DeepCopy())); err != nil || !handled {
		t.Fatalf("invalid upgrade proceeded: handled=%t err=%v", handled, err)
	}
	if instance.Status.Phase != "Error" || conditionReason(instance.Status.Conditions, "ManagedTransportConfigured") != "TransportError" {
		t.Fatal("invalid transport did not report an error")
	}
	for index, object := range before {
		after := object.DeepCopyObject().(client.Object)
		if err := kube.Get(ctx, keys[index], after); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(object, after) {
			t.Fatalf("invalid transport changed resource %T", object)
		}
	}
}
