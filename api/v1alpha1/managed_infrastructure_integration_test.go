//go:build integration

package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Registry cryptography is isolated from API write concurrency. No workload is
// executed here; the normal runtime verifier and installed image gates remain.
type managedAPIVerifier struct{ image string }

func (v managedAPIVerifier) Verify(_ context.Context, image, _, _ string) error {
	if image != v.image {
		return imagevalidator.ErrVerificationDenied
	}
	return nil
}

type managedOwnerRaceClient struct {
	client.Client
	t          *testing.T
	target     client.Object
	changed    client.Object
	conflicted bool
}

func (c *managedOwnerRaceClient) matches(object client.Object) bool {
	return reflect.TypeOf(object) == reflect.TypeOf(c.target) && client.ObjectKeyFromObject(object) == client.ObjectKeyFromObject(c.target)
}

func (c *managedOwnerRaceClient) changeOwner(ctx context.Context) {
	c.t.Helper()
	c.changed = c.target.DeepCopyObject().(client.Object)
	if err := c.Client.Get(ctx, client.ObjectKeyFromObject(c.target), c.changed); err != nil {
		c.t.Fatal(err)
	}
	owners := c.changed.GetOwnerReferences()
	owners[0].UID = "concurrent-foreign-owner"
	c.changed.SetOwnerReferences(owners)
	if err := c.Client.Update(ctx, c.changed); err != nil {
		c.t.Fatal(err)
	}
}

func (c *managedOwnerRaceClient) Patch(ctx context.Context, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if !c.matches(object) {
		return c.Client.Patch(ctx, object, patch, opts...)
	}
	c.changeOwner(ctx)
	err := c.Client.Patch(ctx, object, patch, opts...)
	c.conflicted = apierrors.IsConflict(err)
	return err
}

func (c *managedOwnerRaceClient) Delete(ctx context.Context, object client.Object, opts ...client.DeleteOption) error {
	if !c.matches(object) {
		return c.Client.Delete(ctx, object, opts...)
	}
	options := (&client.DeleteOptions{}).ApplyOptions(opts)
	if options.Preconditions == nil || options.Preconditions.UID == nil || options.Preconditions.ResourceVersion == nil {
		c.t.Fatal("managed deletion did not bind UID and resourceVersion")
	}
	c.changeOwner(ctx)
	err := c.Client.Delete(ctx, object, opts...)
	c.conflicted = apierrors.IsConflict(err)
	return err
}

func checkManagedInfrastructureConcurrency(t *testing.T, ctx context.Context, kube client.Client) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unready managed infrastructure reached provider probe")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	pair := server.TLS.Certificates[0]
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(server.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		target client.Object
	}{
		{"deployment", &appsv1.Deployment{}}, {"service", &corev1.Service{}},
		{"networkpolicy", &networkingv1.NetworkPolicy{}},
		{"pdb-update", &policyv1.PodDisruptionBudget{}}, {"pdb-delete", &policyv1.PodDisruptionBudget{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, source := operationAPIFixture(t, ctx, kube, "infra-race-"+tc.name, false)
			source.Spec.Managed.Replicas = new(int32(2))
			if err := kube.Update(ctx, source); err != nil {
				t.Fatal(err)
			}
			for _, secret := range []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: source.Spec.AdminRef.Name, Namespace: source.Namespace}, Data: map[string][]byte{
					"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("fixture"), "HANKO_KC_CLIENT_SECRET": []byte("synthetic")}},
				{ObjectMeta: metav1.ObjectMeta{Name: source.Spec.Managed.TLSSecretRef, Namespace: source.Namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{
					corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}},
				{ObjectMeta: metav1.ObjectMeta{Name: source.Spec.TLSCARef, Namespace: source.Namespace}, Data: map[string][]byte{"ca.crt": cert}},
			} {
				if err := kube.Create(ctx, secret); err != nil {
					t.Fatal(err)
				}
			}
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0600); err != nil {
				t.Fatal(err)
			}
			policy, err := json.Marshal(map[string]any{"version": 1, "approvals": []imagevalidator.Approval{{Purpose: imagevalidator.Keycloak,
				Image: source.Spec.Managed.Image, Revision: strings.Repeat("1", 40), KeyFile: "publisher.pub"}}})
			if err != nil {
				t.Fatal(err)
			}
			policyFile := filepath.Join(directory, "policy.json")
			if err := os.WriteFile(policyFile, policy, 0600); err != nil {
				t.Fatal(err)
			}
			r := &controller.HankoKeycloakInstanceReconciler{Client: kube, APIReader: kube, Scheme: kube.Scheme(), RequireHTTPS: true,
				ImageValidator: imagevalidator.NewWithPolicy(policyFile, managedAPIVerifier{source.Spec.Managed.Image})}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)}
			if _, err := r.Reconcile(ctx, request); err != nil {
				t.Fatal(err)
			}
			name := source.Name
			if tc.name == "networkpolicy" {
				name += "-isolation"
			}
			if err := kube.Get(ctx, client.ObjectKey{Namespace: source.Namespace, Name: name}, tc.target); err != nil {
				t.Fatal(err)
			}
			switch target := tc.target.(type) {
			case *appsv1.Deployment:
				target.Spec.Replicas = new(int32(1))
			case *corev1.Service:
				target.Spec.Selector = map[string]string{"app": "old"}
			case *networkingv1.NetworkPolicy:
				target.Spec.Ingress = nil
			case *policyv1.PodDisruptionBudget:
				target.Spec.MinAvailable = new(intstr.FromInt32(0))
			}
			if err := kube.Update(ctx, tc.target); err != nil {
				t.Fatal(err)
			}
			if tc.name == "pdb-delete" {
				if err := kube.Get(ctx, client.ObjectKeyFromObject(source), source); err != nil {
					t.Fatal(err)
				}
				source.Spec.Managed.Replicas = new(int32(1))
				if err := kube.Update(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			fault := &managedOwnerRaceClient{Client: kube, t: t, target: tc.target}
			r.Client = fault
			if _, err := r.Reconcile(ctx, request); err != nil {
				t.Fatal(err)
			}
			if !fault.conflicted || fault.changed == nil {
				t.Fatal("concurrent owner change was not rejected by the API precondition")
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(tc.target), tc.target); err != nil || !reflect.DeepEqual(fault.changed, tc.target) {
				t.Fatalf("foreign infrastructure was modified or removed: %v", err)
			}
		})
	}
}
