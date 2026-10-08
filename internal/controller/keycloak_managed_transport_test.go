//go:build keycloak_integration

package controller_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

// Local registry verification is isolated here; existing trust-boundary tests
// cover publisher signatures. This fixture qualifies the generated server args.
type managedFixtureVerifier struct{ image string }

func (v managedFixtureVerifier) Verify(_ context.Context, image, _, _ string) error {
	if image != v.image {
		return imagevalidator.ErrVerificationDenied
	}
	return nil
}

func managedFixtureTemplate(t *testing.T, image string, cert, key []byte) ([]string, string) {
	t.Helper()
	named, err := reference.ParseNamed(image)
	if err != nil {
		t.Fatal(err)
	}
	digested, ok := named.(reference.Digested)
	if !ok {
		t.Fatal("managed fixture base is not pinned")
	}
	image = reference.TrimNamed(named).String() + "@" + digested.Digest().String()
	directory := t.TempDir()
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("managed fixture certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0600); err != nil {
		t.Fatal(err)
	}
	policy := fixtureJSON(t, map[string]any{"version": 1, "approvals": []imagevalidator.Approval{{Purpose: imagevalidator.Keycloak, Image: image, Revision: strings.Repeat("1", 40), KeyFile: "publisher.pub"}}})
	policyFile := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	instance := &hanko.HankoKeycloakInstance{ObjectMeta: fixtureMeta("native-managed"), Spec: hanko.HankoKeycloakInstanceSpec{
		Mode: "managed", AdminRef: corev1.LocalObjectReference{Name: "native-admin"}, TLSCARef: "native-ca",
		Managed: &hanko.ManagedKeycloakSpec{Image: image, Database: corev1.LocalObjectReference{Name: "native-db"}, TLSSecretRef: "native-serving"}}}
	admin := &corev1.Secret{ObjectMeta: fixtureMeta("native-admin"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte("https://localhost:8443"), "HANKO_KC_CLIENT_ID": []byte("fixture"), "HANKO_KC_CLIENT_SECRET": []byte("synthetic")}}
	serving := &corev1.Secret{ObjectMeta: fixtureMeta("native-serving"), Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key}}
	ca := &corev1.Secret{ObjectMeta: fixtureMeta("native-ca"), Data: map[string][]byte{"ca.crt": cert}}
	scheme := newScheme(t)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(instance).WithObjects(instance, admin, serving, ca).Build()
	r := &controller.HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, RequireHTTPS: true, ImageValidator: imagevalidator.NewWithPolicy(policyFile, managedFixtureVerifier{image})}
	// Provisioning precedes the diagnostic probe. There is no server yet; its
	// bounded probe may fail, but the generated template must be available.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fixtureReconcile(&keycloakFixture{t: t}, ctx, r, instance)
	var deployment appsv1.Deployment
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(instance), &deployment); err != nil {
		t.Fatal(err)
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	for _, mount := range container.VolumeMounts {
		if mount.Name == "serving-tls" {
			return container.Args, mount.MountPath
		}
	}
	t.Fatal("generated managed template has no serving TLS mount")
	return nil, ""
}

func (f *keycloakFixture) buildManagedFixture(base string) string {
	f.t.Helper()
	directory := f.t.TempDir() // TLS material never enters this build context.
	if err := os.WriteFile(filepath.Join(directory, "Dockerfile"), []byte("FROM "+base+"\nRUN /opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true --http-relative-path=/ --http-management-relative-path=/\n"), 0600); err != nil {
		f.t.Fatal(err)
	}
	image := "hankoshell-managed-test:" + fixtureSecret(f.t)[:12]
	f.t.Cleanup(func() {
		output, err := f.docker(15*time.Second, nil, "image", "rm", image)
		if err != nil && !strings.Contains(string(output), "No such image") {
			f.t.Errorf("managed fixture image cleanup failed: %s", f.redact(output))
		}
	})
	output, err := f.docker(3*time.Minute, nil, "build", "--tag", image, directory)
	if err != nil {
		f.t.Fatalf("build optimized managed fixture: %s", f.redact(output))
	}
	return image
}

func (f *keycloakFixture) fixturePortURL(name, port string) string {
	f.t.Helper()
	output, err := f.docker(10*time.Second, nil, "port", name, port)
	if err != nil {
		f.t.Fatal("resolve managed fixture port")
	}
	host, mapped, err := net.SplitHostPort(strings.TrimSpace(string(output)))
	if err != nil || host != "127.0.0.1" {
		f.t.Fatal("managed fixture port is not exclusively loopback")
	}
	return "http://localhost:" + mapped
}

func TestRealKeycloakManagedTransport(t *testing.T) {
	f := newKeycloakFixtureWithManagedTransport(t, true)
	response, err := f.http.Get(f.healthURL + "/health/ready")
	if err != nil {
		t.Fatal("generated HTTP health probe cannot reach the management listener")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("management readiness HTTP %d", response.StatusCode)
	}
	response, err = f.http.Get(f.plainURL + "/realms/master/.well-known/openid-configuration")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("generated managed configuration exposed a plaintext IAM listener")
	}
	if _, err := f.kc.ServerVersion(context.Background()); err != nil {
		t.Fatal("constrained service account cannot use the generated HTTPS Admin API")
	}
}
