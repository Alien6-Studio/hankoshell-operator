package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestManagedServiceAccountCreatesCredentialAndSchedulesRotation(t *testing.T) {
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients" && request.URL.Query().Get("clientId") == "automation":
			if created {
				_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "automation-uuid", "clientId": "automation"}})
			} else {
				_ = json.NewEncoder(w).Encode([]map[string]string{})
			}
		case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/clients":
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode service-account client: %v", err)
			}
			if payload["serviceAccountsEnabled"] != true || payload["fullScopeAllowed"] != false {
				t.Fatalf("unsafe service-account client: %#v", payload)
			}
			created = true
			w.WriteHeader(http.StatusCreated)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/automation-uuid/client-secret":
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "generated-secret"})
		case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/clients/automation-uuid/client-secret":
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "rotated-secret"})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	serviceAccount := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "automation", Namespace: "test", Generation: 2},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: "acme", ClientID: "automation",
			SecretRotationPolicy: &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 30},
		},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, serviceAccount)
	reconciler := &HankoServiceAccountReconciler{
		Client: k8sClient, Scheme: scheme, Pool: keycloak.NewPool(keycloak.New(server.URL, "operator", "secret")), Recorder: record.NewFakeRecorder(2),
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(serviceAccount)}
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("create managed service account: %v", err)
	}
	if result.RequeueAfter <= 0 || !created {
		t.Fatalf("service-account result=%v created=%t", result, created)
	}

	var actual hankoshv1alpha1.HankoServiceAccount
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(serviceAccount), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.SecretRef == nil || actual.Status.LastRotated == nil || actual.Status.NextRotation == nil {
		t.Fatalf("unexpected service-account status: %#v", actual.Status)
	}
	var secret corev1.Secret
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: "hanko-sa-automation"}, &secret); err != nil {
		t.Fatalf("get generated client secret: %v", err)
	}
	if secret.StringData["client_secret"] != "generated-secret" {
		t.Fatalf("stored client secret = %#v", secret.StringData)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("idempotent service-account reconcile: %v", err)
	}
	if err := reconciler.upsertSASecret(context.Background(), &actual, "recovered-secret"); err != nil {
		t.Fatalf("update existing Kubernetes secret: %v", err)
	}
	rotationTime := metav1.Now()
	actual.Status.LastRotated = &metav1.Time{Time: rotationTime.AddDate(0, 0, -31)}
	if err := reconciler.maybeRotate(context.Background(), &actual, actual.Spec.SecretRotationPolicy, &rotationTime, keycloak.New(server.URL, "operator", "secret")); err != nil {
		t.Fatalf("rotate expired service-account secret: %v", err)
	}
	if actual.Status.LastRotated == nil || !actual.Status.LastRotated.Equal(&rotationTime) {
		t.Fatalf("rotation timestamp = %#v", actual.Status.LastRotated)
	}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "test", Name: "hanko-sa-automation"}, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.StringData["client_secret"] != "rotated-secret" {
		t.Fatalf("rotated Kubernetes secret = %#v", secret.StringData)
	}
}

func TestServiceAccountRotationPolicyBoundaries(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	past := metav1.NewTime(now.Add(-time.Hour))
	future := metav1.NewTime(now.Add(time.Hour))
	policy := &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 30, ForceRotateAt: &past}
	serviceAccount := &hankoshv1alpha1.HankoServiceAccount{}
	if !serviceAccountRotationDue(serviceAccount, policy, &now) {
		t.Fatal("past forced rotation must be due when no rotation was recorded")
	}
	serviceAccount.Status.LastRotated = &now
	if serviceAccountRotationDue(serviceAccount, policy, &now) {
		t.Fatal("a force timestamp older than the last rotation must not rotate again")
	}
	policy.ForceRotateAt = &future
	policy.IntervalDays = 0
	if serviceAccountRotationDue(serviceAccount, policy, &now) {
		t.Fatal("future force timestamp with no interval must not be due")
	}
	policy.ForceRotateAt = nil
	policy.IntervalDays = 30
	serviceAccount.Status.LastRotated = nil
	if !serviceAccountRotationDue(serviceAccount, policy, &now) {
		t.Fatal("enabled interval with no prior rotation must rotate")
	}
	serviceAccount.Status.LastRotated = &metav1.Time{Time: now.AddDate(0, 0, -31)}
	if !serviceAccountRotationDue(serviceAccount, policy, &now) {
		t.Fatal("expired interval must rotate")
	}
}
