package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestInstanceUsesOnlyExplicitlyRequestedCapabilities(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	for _, mode := range []string{"external", "adopted", "managed"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.URL.Path == "/realms/master/protocol/openid-connect/token":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "privileged", "expires_in": 300})
				case req.Method == http.MethodGet && req.URL.Path == "/admin/serverinfo":
					_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.8.0"}})
				case req.Method == http.MethodGet && req.URL.Path == "/admin/realms":
					_ = json.NewEncoder(w).Encode([]any{})
				default:
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent) // Available authority must not trigger a write.
				}
			}))
			t.Cleanup(server.Close)
			instance, secret := rotationObjects(server.URL, "synthetic-admin", time.Now().Add(-365*24*time.Hour).Format(time.RFC3339))
			instance.Spec.RotateAdminCredentials = false
			instance.Spec.Mode = mode
			service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: instance.Namespace, Name: "adopted-service"}}
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: instance.Namespace, Name: "adopted-deployment"}}
			if mode == "managed" {
				instance.Spec.Managed = managedTestInstance(instance.Namespace, instance.Name).Spec.Managed
				instance.Spec.Managed.TLSSecretRef = ""
				instance.Spec.Managed.AllowInsecureHTTP = true
			}
			if mode == "adopted" {
				instance.Spec.Adopted = &hanko.AdoptedKeycloakSpec{DeploymentRef: deployment.Name, ServiceRef: service.Name}
			}
			scheme := controllerTestScheme(t)
			kube := controllerTestClient(scheme, instance, secret, service, deployment)
			var before corev1.Secret
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(secret), &before); err != nil {
				t.Fatal(err)
			}
			r := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)}); err != nil {
				t.Fatal(err)
			}
			current, after := getRotationObjects(t, kube)
			if current.Status.Phase != "Ready" || writes.Load() != 0 {
				t.Fatalf("unrequested administrative activity: phase=%s writes=%d", current.Status.Phase, writes.Load())
			}
			if !reflect.DeepEqual(before.Data, after.Data) || !reflect.DeepEqual(before.Annotations, after.Annotations) || before.ResourceVersion != after.ResourceVersion {
				t.Fatal("unrequested rotation modified AdminRef")
			}
			if current.Status.NextCredentialRotation != nil || conditionReason(current.Status.Conditions, "MasterRealmHardened") != "NotRequested" {
				t.Fatalf("disabled capabilities reported incorrectly: %+v", current.Status)
			}
			var observedService corev1.Service
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(service), &observedService); err != nil {
				t.Fatal(err)
			}
			if len(observedService.Labels) != 0 || len(observedService.Annotations) != 0 {
				t.Fatal("adopted reference authorized an unrequested Service patch")
			}
		})
	}
}

func TestExplicitMasterHardeningMustSucceedBeforeReady(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "authorized", true: "denied"}[denied], func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/realms/master/protocol/openid-connect/token":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
				case "/admin/serverinfo":
					_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.8.0"}})
				case "/admin/realms":
					_ = json.NewEncoder(w).Encode([]any{})
				case "/admin/realms/master":
					writes.Add(1)
					if denied {
						w.WriteHeader(http.StatusForbidden)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					http.NotFound(w, req)
				}
			}))
			t.Cleanup(server.Close)
			instance, secret := rotationObjects(server.URL, "synthetic-admin", "")
			instance.Spec.RotateAdminCredentials = false
			instance.Spec.HardenMasterRealm = true
			scheme := controllerTestScheme(t)
			kube := controllerTestClient(scheme, instance, secret)
			r := &HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)}); err != nil {
				t.Fatal(err)
			}
			current, _ := getRotationObjects(t, kube)
			want := "Ready"
			if denied {
				want = "Degraded"
			}
			if current.Status.Phase != want || writes.Load() != 1 {
				t.Fatalf("explicit hardening: phase=%s writes=%d", current.Status.Phase, writes.Load())
			}
		})
	}
}

func TestDisablingRotationDoesNotResumeAPendingCredentialWrite(t *testing.T) {
	instance, secret := rotationObjects("https://keycloak.invalid", "synthetic-admin", "")
	instance.Spec.RotateAdminCredentials = false
	secret.Data[pendingClientSecretKey] = []byte("synthetic-pending")
	kube := controllerTestClient(controllerTestScheme(t), instance, secret)
	r := &HankoKeycloakInstanceReconciler{Client: kube}
	_, handled, err := r.reconcileServiceAccountCredential(context.Background(), instance, nil, client.MergeFrom(instance.DeepCopy()))
	if err != nil || !handled || conditionReason(instance.Status.Conditions, credentialRotationCondition) != "RotationNotRequested" {
		t.Fatalf("pending rotation proceeded without authorization: handled=%t err=%v", handled, err)
	}
}
