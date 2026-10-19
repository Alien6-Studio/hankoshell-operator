package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func readyManagedTestDeployment(instance *api.HankoKeycloakInstance) *appsv1.Deployment {
	control := true
	replicas := int32(1)
	if instance.Spec.Managed.Replicas != nil {
		replicas = *instance.Spec.Managed.Replicas
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace, UID: "deployment-uid", Generation: 3,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "HankoKeycloakInstance", Name: instance.Name, UID: instance.UID, Controller: &control}}},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "keycloak", Image: instance.Spec.Managed.Image, EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: instance.Spec.Managed.Database}}},
		}}}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: replicas, UpdatedReplicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas},
	}
}

func TestOperationProviderObservationBindsManagedRollout(t *testing.T) {
	for _, kind := range []api.HankoOperationType{api.OperationUpgrade, api.OperationDBSwitch} {
		for _, boundary := range []string{"current", "legacy", "old-generation", "replaced-deployment", "new-rollout", "unavailable", "foreign-owner"} {
			t.Run(string(kind)+"/"+boundary, func(t *testing.T) {
				ctx := context.Background()
				op, instance := operationRecoveryFixture()
				op.Spec.Type = kind
				if kind == api.OperationUpgrade {
					op.Spec.DBSwitch = nil
					op.Spec.Upgrade = &api.UpgradeSpec{ToImage: instance.Spec.Managed.Image}
				} else {
					instance.Spec.Managed.Database.Name = op.Spec.DBSwitch.NewDatabaseSecretRef
				}
				instance.Status.Phase = "Ready"
				iamCondition(&instance.Status.Conditions, instance.Generation, "AdminAPIReachable", metav1.ConditionTrue, "ProbeSucceeded", "current instance generation")
				deployment := readyManagedTestDeployment(instance)
				instance.Status.ManagedObservation = &api.ManagedDeploymentObservation{DeploymentUID: string(deployment.UID), DeploymentGeneration: deployment.Generation}
				cached := controllerTestClient(controllerTestScheme(t), deployment.DeepCopy())
				switch boundary {
				case "legacy":
					instance.Status.ManagedObservation = nil
				case "old-generation":
					instance.Status.ManagedObservation.DeploymentGeneration--
				case "replaced-deployment":
					deployment.UID = "replacement-uid"
				case "new-rollout":
					deployment.Generation++
					deployment.Status.ObservedGeneration = deployment.Generation
				case "unavailable":
					deployment.Status.AvailableReplicas = 0
				case "foreign-owner":
					deployment.OwnerReferences[0].UID = "foreign"
				}
				live := controllerTestClient(controllerTestScheme(t), deployment)
				r := &HankoOperationReconciler{Client: cached, APIReader: live}
				step, now := &api.OperationStep{Name: "Validate", Status: "Pending"}, metav1.Now()
				_, _, err := r.advanceValidationStep(ctx, op, instance, step, &now)
				if err != nil || (step.Status == "Done") != (boundary == "current") {
					t.Fatalf("provider observation boundary %s: status=%s err=%v", boundary, step.Status, err)
				}
			})
		}
	}
}

// Registry cryptography is isolated by the existing unit-test verifier. The
// real TLS client, reconciler ordering and persisted probe evidence run here.
func TestManagedProbeRequiresStableDeployment(t *testing.T) {
	for _, boundary := range []string{"current", "rolling", "changed-during-probe"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			_, instance := operationRecoveryFixture()
			instance.Spec.TLSCARef = "provider-ca"
			deployment := readyManagedTestDeployment(instance)
			var backend client.Client
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests++
				switch request.URL.Path {
				case "/realms/master/protocol/openid-connect/token":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic", "expires_in": 300})
				case "/admin/serverinfo":
					_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.8.0"}})
				case "/admin/realms":
					if boundary == "changed-during-probe" {
						var changed appsv1.Deployment
						if err := backend.Get(ctx, client.ObjectKeyFromObject(deployment), &changed); err != nil {
							t.Error(err)
						}
						changed.Generation++
						changed.Status.ObservedGeneration = changed.Generation
						if err := backend.Update(ctx, &changed); err != nil {
							t.Error(err)
						}
						changed.Status.ObservedGeneration = changed.Generation
						if err := backend.Status().Update(ctx, &changed); err != nil {
							t.Error(err)
						}
					}
					_ = json.NewEncoder(w).Encode([]map[string]string{{"realm": "master"}})
				default:
					http.Error(w, "unexpected request", http.StatusNotFound)
				}
			}))
			defer server.Close()
			pair := server.TLS.Certificates[0]
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
			key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			admin := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: instance.Spec.AdminRef.Name, Namespace: instance.Namespace}, Data: map[string][]byte{
				"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("fixture"), "HANKO_KC_CLIENT_SECRET": []byte("synthetic")}}
			serving := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: instance.Spec.Managed.TLSSecretRef, Namespace: instance.Namespace}, Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}}
			ca := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: instance.Spec.TLSCARef, Namespace: instance.Namespace}, Data: map[string][]byte{"ca.crt": cert}}
			if boundary == "rolling" {
				deployment.Status.UpdatedReplicas--
			}
			backend = controllerTestClient(controllerTestScheme(t), instance, deployment, admin, serving, ca)
			r := &HankoKeycloakInstanceReconciler{Client: backend, APIReader: backend, Scheme: backend.Scheme(), RequireHTTPS: true, ImageValidator: approvedFixtureValidator(t)}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)}); err != nil {
				t.Fatal(err)
			}
			if err := backend.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
				t.Fatal(err)
			}
			if (instance.Status.Phase == "Ready") != (boundary == "current") || (instance.Status.ManagedObservation != nil) != (boundary == "current") {
				t.Fatalf("unstable or missing probe accepted: %#v", instance.Status)
			}
			if (requests == 0) != (boundary == "rolling") {
				t.Fatalf("provider probe ordering: %d requests at %s", requests, boundary)
			}
		})
	}
}
