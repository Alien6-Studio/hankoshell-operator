package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

type rotationAuditRecorder struct {
	calls      int
	rotationID string
	err        error
}

func (r *rotationAuditRecorder) RecordServiceAccountRotation(_ context.Context, _, _, _, rotationID string, _ time.Time) error {
	r.calls++
	r.rotationID = rotationID
	return r.err
}

type credentialRotationKeycloak struct {
	server       *httptest.Server
	activeSecret string
	updates      int
}

func newCredentialRotationKeycloak(t *testing.T, activeSecret string) *credentialRotationKeycloak {
	t.Helper()
	fixture := &credentialRotationKeycloak{activeSecret: activeSecret}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fixture.serveHTTP(t, w, request)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *credentialRotationKeycloak) serveHTTP(t *testing.T, w http.ResponseWriter, request *http.Request) {
	t.Helper()
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("client_id") != "operator" || request.Form.Get("client_secret") != f.activeSecret {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 300})
	case request.Header.Get("Authorization") != "Bearer admin-token":
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case request.Method == http.MethodGet && request.URL.Path == "/admin/serverinfo":
		_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.4.0"}})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "operator-uuid", "clientId": "operator"}})
	case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients/operator-uuid":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "operator-uuid", "clientId": "operator", "enabled": true,
			"serviceAccountsEnabled": true, "fullScopeAllowed": false,
		})
	case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/master/clients/operator-uuid":
		var representation map[string]any
		if err := json.NewDecoder(request.Body).Decode(&representation); err != nil {
			t.Fatal(err)
		}
		replacement, _ := representation["secret"].(string)
		if len(replacement) < 32 || representation["clientId"] != "operator" {
			http.Error(w, "invalid replacement", http.StatusBadRequest)
			return
		}
		f.activeSecret = replacement
		f.updates++
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, request)
	}
}

func rotationObjects(serverURL, activeSecret, rotatedAt string) (*hankoshv1alpha1.HankoKeycloakInstance, *corev1.Secret) {
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: "auth"},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "keycloak-admin"},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "keycloak-admin", Namespace: "auth",
			Annotations: map[string]string{rotatedAtAnnotation: rotatedAt},
		},
		Data: map[string][]byte{
			"HANKO_KEYCLOAK_URL": []byte(serverURL), "HANKO_KC_CLIENT_ID": []byte("operator"),
			adminClientSecretKey: []byte(activeSecret),
		},
	}
	return instance, secret
}

func getRotationObjects(t *testing.T, c client.Client) (*hankoshv1alpha1.HankoKeycloakInstance, *corev1.Secret) {
	t.Helper()
	ctx := context.Background()
	var instance hankoshv1alpha1.HankoKeycloakInstance
	if err := c.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "keycloak"}, &instance); err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "keycloak-admin"}, &secret); err != nil {
		t.Fatal(err)
	}
	return &instance, &secret
}

func TestServiceAccountRotationPersistsAppliesVerifiesPromotesAndAudits(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	activeSecret := strings.Repeat("o", 48)
	keycloakFixture := newCredentialRotationKeycloak(t, activeSecret)
	instance, secret := rotationObjects(keycloakFixture.server.URL, activeSecret, now.Add(-48*time.Hour).Format(time.RFC3339Nano))
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, instance, secret)
	auditRecorder := &rotationAuditRecorder{}
	reconciler := &HankoKeycloakInstanceReconciler{
		Client: k8sClient, Scheme: scheme, CredentialRotationAudit: auditRecorder,
		ServiceAccountMaxAge: 24 * time.Hour, Now: func() time.Time { return now },
	}

	current, _ := getRotationObjects(t, k8sClient)
	activeClient, err := reconciler.buildKCClient(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	result, handled, err := reconciler.reconcileServiceAccountCredential(ctx, current, activeClient, client.MergeFrom(current.DeepCopy()))
	if err != nil || !handled || result.RequeueAfter != rotationRetryDelay {
		t.Fatalf("prepare rotation: handled=%t result=%#v err=%v", handled, result, err)
	}
	_, prepared := getRotationObjects(t, k8sClient)
	if len(prepared.Data[pendingClientSecretKey]) < 32 || string(prepared.Data[adminClientSecretKey]) != activeSecret {
		t.Fatalf("pending credential was not durably staged: data keys=%v", prepared.Data)
	}
	rotationID := prepared.Annotations[rotationIDAnnotation]

	current, _ = getRotationObjects(t, k8sClient)
	activeClient, err = reconciler.buildKCClient(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	result, handled, err = reconciler.reconcileServiceAccountCredential(ctx, current, activeClient, client.MergeFrom(current.DeepCopy()))
	if err != nil || !handled || !result.Requeue {
		t.Fatalf("complete rotation must rebuild the promoted client: handled=%t result=%#v err=%v", handled, result, err)
	}
	_, promoted := getRotationObjects(t, k8sClient)
	if len(promoted.Data[pendingClientSecretKey]) != 0 || string(promoted.Data[adminClientSecretKey]) != keycloakFixture.activeSecret {
		t.Fatalf("credential was not promoted consistently: %#v", promoted.Data)
	}
	if keycloakFixture.updates != 1 || auditRecorder.calls != 1 || auditRecorder.rotationID != rotationID {
		t.Fatalf("updates=%d audit=%d rotationID=%q", keycloakFixture.updates, auditRecorder.calls, auditRecorder.rotationID)
	}
	if promoted.Annotations[rotationAuditAnnotation] != "" || current.Status.LastCredentialRotation == nil || current.Status.NextCredentialRotation == nil {
		t.Fatalf("rotation receipt or schedule incomplete: annotations=%v status=%#v", promoted.Annotations, current.Status)
	}
}

func TestServiceAccountRotationRecoversAfterKeycloakUpdateBeforePromotion(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	oldSecret := strings.Repeat("o", 48)
	pendingSecret := strings.Repeat("p", 48)
	keycloakFixture := newCredentialRotationKeycloak(t, pendingSecret)
	instance, secret := rotationObjects(keycloakFixture.server.URL, oldSecret, now.Add(-48*time.Hour).Format(time.RFC3339Nano))
	secret.Data[pendingClientSecretKey] = []byte(pendingSecret)
	secret.Annotations[rotationStateAnnotation] = rotationStatePrepared
	secret.Annotations[rotationIDAnnotation] = "rot_recovery"
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, instance, secret)
	auditRecorder := &rotationAuditRecorder{}
	reconciler := &HankoKeycloakInstanceReconciler{
		Client: k8sClient, Scheme: scheme, CredentialRotationAudit: auditRecorder,
		ServiceAccountMaxAge: 24 * time.Hour, Now: func() time.Time { return now },
	}
	current, _ := getRotationObjects(t, k8sClient)
	activeClient, err := reconciler.buildKCClient(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	result, handled, err := reconciler.reconcileServiceAccountCredential(ctx, current, activeClient, client.MergeFrom(current.DeepCopy()))
	if err != nil || !handled || !result.Requeue {
		t.Fatalf("recover rotation must rebuild the promoted client: handled=%t result=%#v err=%v", handled, result, err)
	}
	_, promoted := getRotationObjects(t, k8sClient)
	if string(promoted.Data[adminClientSecretKey]) != pendingSecret || len(promoted.Data[pendingClientSecretKey]) != 0 {
		t.Fatalf("pending credential was not recovered: %#v", promoted.Data)
	}
	if keycloakFixture.updates != 0 || auditRecorder.calls != 1 {
		t.Fatalf("recovery repeated Keycloak mutation: updates=%d audit=%d", keycloakFixture.updates, auditRecorder.calls)
	}
}

func TestServiceAccountRotationKeepsAuditReceiptPendingUntilHankoRecovers(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	newSecret := strings.Repeat("n", 48)
	keycloakFixture := newCredentialRotationKeycloak(t, newSecret)
	instance, secret := rotationObjects(keycloakFixture.server.URL, newSecret, now.Format(time.RFC3339Nano))
	secret.Annotations[rotationAuditAnnotation] = "rot_audit_retry"
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, instance, secret)
	auditRecorder := &rotationAuditRecorder{err: errors.New("audit unavailable")}
	reconciler := &HankoKeycloakInstanceReconciler{
		Client: k8sClient, Scheme: scheme, CredentialRotationAudit: auditRecorder,
		ServiceAccountMaxAge: 24 * time.Hour, Now: func() time.Time { return now },
	}
	current, _ := getRotationObjects(t, k8sClient)
	activeClient, err := reconciler.buildKCClient(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	_, handled, err := reconciler.reconcileServiceAccountCredential(ctx, current, activeClient, client.MergeFrom(current.DeepCopy()))
	if err != nil || !handled {
		t.Fatalf("failed audit must degrade without losing receipt: handled=%t err=%v", handled, err)
	}
	degraded, pendingAudit := getRotationObjects(t, k8sClient)
	if degraded.Status.Phase != "Degraded" || pendingAudit.Annotations[rotationAuditAnnotation] != "rot_audit_retry" {
		t.Fatalf("audit failure was not retained: status=%#v annotations=%v", degraded.Status, pendingAudit.Annotations)
	}

	auditRecorder.err = nil
	current, _ = getRotationObjects(t, k8sClient)
	activeClient, _ = reconciler.buildKCClient(ctx, current)
	_, handled, err = reconciler.reconcileServiceAccountCredential(ctx, current, activeClient, client.MergeFrom(current.DeepCopy()))
	if err != nil || handled {
		t.Fatalf("audit retry: handled=%t err=%v", handled, err)
	}
	_, completed := getRotationObjects(t, k8sClient)
	if completed.Annotations[rotationAuditAnnotation] != "" || keycloakFixture.updates != 0 {
		t.Fatalf("audit recovery changed credential state: annotations=%v updates=%d", completed.Annotations, keycloakFixture.updates)
	}
}

func TestParseServiceAccountMaxAge(t *testing.T) {
	for input, want := range map[string]time.Duration{"": defaultServiceAccountMaxAge, "90d": 90 * 24 * time.Hour, "12h": 12 * time.Hour} {
		got, err := ParseServiceAccountMaxAge(input)
		if err != nil || got != want {
			t.Fatalf("ParseServiceAccountMaxAge(%q) = %s, %v; want %s", input, got, err, want)
		}
	}
	for _, input := range []string{"0d", "200000d", "-1h", "invalid"} {
		if _, err := ParseServiceAccountMaxAge(input); err == nil {
			t.Fatalf("invalid max age %q was accepted", input)
		}
	}
}
