package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestApplicationDependencyWatchMappingIsScoped(t *testing.T) {
	applications := []clientObject{
		{name: "web", kind: "web", theme: "brand"},
		{name: "spa", kind: "spa", theme: "brand"},
		{name: "explicit", kind: "web", theme: "other", explicitRotation: true},
	}
	objects := make([]*hankoshv1alpha1.HankoApplication, 0, len(applications))
	for _, item := range applications {
		application := &hankoshv1alpha1.HankoApplication{
			ObjectMeta: metav1.ObjectMeta{Name: item.name, Namespace: "test"},
			Spec: hankoshv1alpha1.HankoApplicationSpec{
				RealmRef: "acme", ClientID: item.name, Type: item.kind, Theme: item.theme,
			},
		}
		if item.explicitRotation {
			application.Spec.SecretRotationPolicy = &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 30}
		}
		objects = append(objects, application)
	}
	scheme := controllerTestScheme(t)
	reconciler := &HankoApplicationReconciler{Client: controllerTestClient(scheme, objects[0], objects[1], objects[2]), Scheme: scheme}
	ctx := context.Background()

	themeRequests := reconciler.requestsForApplicationTheme(ctx, &hankoshv1alpha1.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "brand", Namespace: "test"}})
	if len(themeRequests) != 2 {
		t.Fatalf("theme requests = %#v", themeRequests)
	}
	realmRequests := reconciler.requestsForApplicationRealm(ctx, &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test"}})
	if len(realmRequests) != 1 || realmRequests[0].Name != "web" {
		t.Fatalf("realm rotation requests = %#v", realmRequests)
	}
	if got := applicationRealmClientIndex(objects[0]); len(got) != 1 || got[0] != realmClientKey("acme", "web") {
		t.Fatalf("application index = %#v", got)
	}
	if got := applicationRealmClientIndex(&corev1.ConfigMap{}); got != nil {
		t.Fatalf("non-application index = %#v", got)
	}
	if got := reconciler.requestsForApplicationTheme(ctx, &corev1.ConfigMap{}); got != nil {
		t.Fatalf("non-theme requests = %#v", got)
	}
	if got := reconciler.requestsForApplicationRealm(ctx, &corev1.ConfigMap{}); got != nil {
		t.Fatalf("non-realm requests = %#v", got)
	}
}

type clientObject struct {
	name, kind, theme string
	explicitRotation  bool
}

func TestApplicationSecretRotationBookkeeping(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	policy := &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 30}
	application := &hankoshv1alpha1.HankoApplication{Spec: hankoshv1alpha1.HankoApplicationSpec{ClientID: "web"}}
	setApplicationSecretStatus(application, &now, policy)
	if application.Status.ClientSecret == nil || application.Status.ClientSecret.SecretRef.Name != "hanko-app-web" || application.Status.NextRotation == nil {
		t.Fatalf("secret rotation status = %#v", application.Status)
	}
	setApplicationNextRotation(application, nil)
	if application.Status.NextRotation != nil {
		t.Fatal("disabled rotation must clear the next timestamp")
	}

	past := metav1.NewTime(now.Add(-time.Hour))
	future := metav1.NewTime(now.Add(time.Hour))
	policy.ForceRotateAt = &past
	application.Status.LastRotated = nil
	if !applicationRotationDue(application, policy, &now) {
		t.Fatal("past forced rotation must be due")
	}
	application.Status.LastRotated = &now
	if applicationRotationDue(application, policy, &now) {
		t.Fatal("completed forced rotation must not repeat")
	}
	policy.ForceRotateAt = &future
	policy.IntervalDays = 0
	if applicationRotationDue(application, policy, &now) {
		t.Fatal("future forced rotation must not run early")
	}
	policy.ForceRotateAt = nil
	policy.IntervalDays = 30
	application.Status.LastRotated = nil
	if !applicationRotationDue(application, policy, &now) {
		t.Fatal("new confidential client must establish interval rotation")
	}
}

func TestApplicationSecretProjectionFollowsRotationAndRemoval(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: types.UID("app-uid")},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			ClientID: "portal",
			Type:     "web",
			ClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{
				{Namespace: "workload", Name: "hanko-app-portal"},
			},
		},
	}
	preprovisioned := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "hanko-app-portal", Namespace: "workload",
		Labels: map[string]string{clientSecretProjectionLabel: "true"},
		Annotations: map[string]string{
			clientSecretProjectionOwnerName: "portal", clientSecretProjectionOwnerNamespace: "auth",
			clientSecretProjectionClientID: "portal",
		},
	}}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, application, preprovisioned)
	reconciler := &HankoApplicationReconciler{Client: k8sClient, Scheme: scheme}
	ctx := context.Background()

	if err := reconciler.reconcileSecretProjections(ctx, application, "first-secret"); err != nil {
		t.Fatalf("create projection: %v", err)
	}
	key := types.NamespacedName{Namespace: "workload", Name: "hanko-app-portal"}
	var projected corev1.Secret
	if err := k8sClient.Get(ctx, key, &projected); err != nil {
		t.Fatalf("get projection: %v", err)
	}
	if got := string(projected.Data["client_secret"]); got != "first-secret" {
		t.Fatalf("projected secret = %q, want first-secret", got)
	}
	if !secretProjectionOwnedBy(&projected, application) {
		t.Fatalf("projection ownership metadata = labels=%#v annotations=%#v", projected.Labels, projected.Annotations)
	}
	if len(projected.OwnerReferences) != 0 {
		t.Fatalf("cross-namespace projection must not use ownerReferences: %#v", projected.OwnerReferences)
	}

	projected.Data["client_secret"] = []byte("tampered")
	projected.Data["unmanaged"] = []byte("must-be-removed")
	if err := k8sClient.Update(ctx, &projected); err != nil {
		t.Fatalf("tamper projection: %v", err)
	}
	if err := reconciler.reconcileSecretProjections(ctx, application, "rotated-secret"); err != nil {
		t.Fatalf("reconcile rotated projection: %v", err)
	}
	if err := k8sClient.Get(ctx, key, &projected); err != nil {
		t.Fatalf("get rotated projection: %v", err)
	}
	if got := string(projected.Data["client_secret"]); got != "rotated-secret" || len(projected.Data) != 1 {
		t.Fatalf("rotated projection data = %#v", projected.Data)
	}

	application.Spec.ClientSecretProjections = nil
	if err := reconciler.reconcileSecretProjections(ctx, application, "rotated-secret"); err != nil {
		t.Fatalf("remove stale projection: %v", err)
	}
	if err := k8sClient.Get(ctx, key, &projected); err != nil {
		t.Fatalf("get cleared projection: %v", err)
	}
	if len(projected.Data) != 0 {
		t.Fatalf("removed projection retained credentials: %#v", projected.Data)
	}
}

func TestApplicationSecretProjectionRefusesUnownedSecret(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: types.UID("app-uid")},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			ClientID: "portal",
			Type:     "web",
			ClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{
				{Namespace: "workload", Name: "existing"},
			},
		},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "workload"},
		Data:       map[string][]byte{"client_secret": []byte("do-not-overwrite")},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, application, existing)
	reconciler := &HankoApplicationReconciler{Client: k8sClient, Scheme: scheme}

	err := reconciler.reconcileSecretProjections(context.Background(), application, "new-secret")
	if err == nil || !strings.Contains(err.Error(), "not pre-authorized") {
		t.Fatalf("projection collision error = %v", err)
	}
	var unchanged corev1.Secret
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: "workload", Name: "existing"}, &unchanged); err != nil {
		t.Fatal(err)
	}
	if got := string(unchanged.Data["client_secret"]); got != "do-not-overwrite" {
		t.Fatalf("unowned secret was overwritten with %q", got)
	}
}

func TestApplicationSecretProjectionRequiresPreprovisionedTarget(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: types.UID("app-uid")},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			ClientID: "portal", Type: "web",
			ClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{{Namespace: "workload", Name: "missing"}},
		},
	}
	scheme := controllerTestScheme(t)
	reconciler := &HankoApplicationReconciler{Client: controllerTestClient(scheme, application), Scheme: scheme}
	err := reconciler.reconcileSecretProjections(context.Background(), application, "secret")
	if err == nil || !strings.Contains(err.Error(), "not pre-provisioned") {
		t.Fatalf("missing projection error = %v", err)
	}
}

func TestApplicationSecretProjectionCleanupCoversDesiredAndRecordedTargets(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: types.UID("app-uid")},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			ClientID: "portal",
			Type:     "web",
			ClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{
				{Namespace: "frontend", Name: "hanko-app-portal"},
			},
		},
		Status: hankoshv1alpha1.HankoApplicationStatus{
			ManagedClientSecretProjections: []hankoshv1alpha1.ApplicationSecretProjection{
				{Namespace: "worker", Name: "hanko-app-portal"},
			},
		},
	}
	preauthorized := func(namespace string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "hanko-app-portal",
				Namespace: namespace,
				Labels:    map[string]string{clientSecretProjectionLabel: "true"},
				Annotations: map[string]string{
					clientSecretProjectionOwnerName:      "portal",
					clientSecretProjectionOwnerNamespace: "auth",
					clientSecretProjectionOwnerUID:       "app-uid",
					clientSecretProjectionClientID:       "portal",
				},
			},
			Data: map[string][]byte{"client_secret": []byte("credential")},
		}
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, application, preauthorized("frontend"), preauthorized("worker"))
	reconciler := &HankoApplicationReconciler{
		Client:                 k8sClient,
		SecretProjectionClient: k8sClient,
		Scheme:                 scheme,
	}

	if err := reconciler.cleanupSecretProjections(context.Background(), application); err != nil {
		t.Fatalf("cleanup projections: %v", err)
	}
	for _, namespace := range []string{"frontend", "worker"} {
		var projected corev1.Secret
		key := types.NamespacedName{Namespace: namespace, Name: "hanko-app-portal"}
		if err := k8sClient.Get(context.Background(), key, &projected); err != nil {
			t.Fatalf("get cleaned projection %s: %v", namespace, err)
		}
		if len(projected.Data) != 0 {
			t.Fatalf("cleaned projection %s retained credentials: %#v", namespace, projected.Data)
		}
	}
}

func TestObservedApplicationDeletionDropsOnlyFinalizer(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: "test", Finalizers: []string{finalizerName}},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "observed"},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, application)
	reconciler := &HankoApplicationReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.reconcileApplicationDeletion(context.Background(), application, keycloak.New("https://unused.example", "operator", "secret"), ModeObserve); err != nil {
		t.Fatalf("drop observed application finalizer: %v", err)
	}
	if len(application.Finalizers) != 0 {
		t.Fatalf("observed application finalizers = %#v", application.Finalizers)
	}
}

func TestApplicationDeletionWithoutFinalizerIsNoop(t *testing.T) {
	application := &hankoshv1alpha1.HankoApplication{}
	reconciler := &HankoApplicationReconciler{}
	if result, err := reconciler.reconcileApplicationDeletion(context.Background(), application, nil, ModeManage); err != nil || !result.IsZero() {
		t.Fatalf("finalizer-free deletion result=%v err=%v", result, err)
	}
}

func TestManagedApplicationDeletionRemovesProviderClientBeforeFinalizer(t *testing.T) {
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "portal-uuid", "clientId": "portal"}})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/portal-uuid":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "portal-uuid", "clientId": "portal", "protocol": "openid-connect", "attributes": map[string]string{"hanko.sh/application-owner": "fixture-test-portal"}})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/clients/portal-uuid":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "test", Finalizers: []string{finalizerName}},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "portal"},
	}
	scheme := controllerTestScheme(t)
	k8sClient := controllerTestClient(scheme, application)
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(application), application); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Delete(context.Background(), application); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(application), application); err != nil {
		t.Fatal(err)
	}
	reconciler := &HankoApplicationReconciler{Client: k8sClient, Scheme: scheme}
	if result, err := reconciler.reconcileApplicationDeletion(context.Background(), application, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP()), ModeManage); err != nil || !result.IsZero() {
		t.Fatalf("managed deletion result=%v err=%v", result, err)
	}
	if !deleted || len(application.Finalizers) != 0 {
		t.Fatalf("managed deletion deleted=%t finalizers=%#v", deleted, application.Finalizers)
	}
}

func TestManagedApplicationDeletionCleansOnlyRecordedMappers(t *testing.T) {
	deleted := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers":
			_ = json.NewEncoder(w).Encode([]keycloak.IdentityProviderMapper{{ID: "idp-uuid", Config: map[string]string{"hanko.sh/application-owner": "application-uid"}}, {ID: "foreign-idp", Config: map[string]string{"hanko.sh/application-owner": "foreign-uid"}}})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/client-uuid/protocol-mappers/models":
			_ = json.NewEncoder(w).Encode([]keycloak.ProtocolMapper{{ID: "claim-uuid", Config: map[string]string{"hanko.sh/application-owner": "application-uid"}}, {ID: "foreign-claim", Config: map[string]string{"hanko.sh/application-owner": "foreign-uid"}}})
		case request.Method == http.MethodDelete && strings.Contains(request.URL.Path, "foreign-"):
			t.Error("forged status authorized foreign mapper deletion")
			w.WriteHeader(http.StatusNoContent)

		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers/idp-uuid":
			deleted["identity"] = true
			w.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients" && request.URL.Query().Get("clientId") == "web":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "web"}})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/clients/client-uuid/protocol-mappers/models/claim-uuid":
			deleted["claim"] = true
			w.WriteHeader(http.StatusNotFound)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{UID: "application-uid"},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme", ClientID: "web"},
		Status: hankoshv1alpha1.HankoApplicationStatus{
			ManagedIdentityMappings: []hankoshv1alpha1.ManagedIdentityMappingReference{
				{Name: "department", IdentityProvider: "entra", KeycloakID: "idp-uuid"},
				{Name: "forged", IdentityProvider: "entra", KeycloakID: "foreign-idp"},
				{Name: "not-created", IdentityProvider: "entra"},
			},
			ManagedTokenClaims: []hankoshv1alpha1.ManagedTokenClaimReference{
				{Name: "tenant", KeycloakID: "claim-uuid"},
				{Name: "forged", KeycloakID: "foreign-claim"},
				{Name: "not-created"},
			},
		},
	}
	reconciler := &HankoApplicationReconciler{}
	if err := reconciler.cleanupApplicationMappings(context.Background(), application, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP())); err != nil {
		t.Fatalf("clean recorded application mappers: %v", err)
	}
	if !deleted["identity"] || !deleted["claim"] || len(deleted) != 2 {
		t.Fatalf("mapper deletion scope = %#v", deleted)
	}
}

func TestApplicationMapperValidationCheckpointsPartialProgress(t *testing.T) {
	identityMappers := []keycloak.IdentityProviderMapper{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers":
			_ = json.NewEncoder(w).Encode(identityMappers)
		case request.Method == http.MethodPost && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers":
			var mapper keycloak.IdentityProviderMapper
			_ = json.NewDecoder(request.Body).Decode(&mapper)
			mapper.ID = "first-uuid"
			identityMappers = append(identityMappers, mapper)
			w.Header().Set("Location", request.URL.Path+"/"+mapper.ID)
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	mapping := hankoshv1alpha1.ApplicationIdentityMapping{
		Name: "duplicate", IdentityProvider: "entra", Claim: "groups", MatchValue: "admins",
		Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
	}
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "test", Generation: 3},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "acme", ClientID: "portal", IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{mapping, mapping},
		},
	}
	reconciler := &HankoApplicationReconciler{}
	if err := reconciler.reconcileIdentityMappings(context.Background(), application, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP())); err == nil {
		t.Fatal("duplicate identity mapping must fail closed")
	}
	if len(application.Status.ManagedIdentityMappings) != 2 || application.Status.ManagedIdentityMappings[0].KeycloakID != "first-uuid" ||
		conditionReason(application.Status.ManagedIdentityMappings[1].Conditions, "Synced") != "Invalid" {
		t.Fatalf("partial identity-mapper checkpoint = %#v", application.Status.ManagedIdentityMappings)
	}
	invalidApplication := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Spec: hankoshv1alpha1.HankoApplicationSpec{IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
			Name: "invalid", IdentityProvider: "entra", Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
		}}},
	}
	if err := reconciler.reconcileIdentityMappings(context.Background(), invalidApplication, nil); err == nil ||
		len(invalidApplication.Status.ManagedIdentityMappings) != 1 || conditionReason(invalidApplication.Status.ManagedIdentityMappings[0].Conditions, "Synced") != "Invalid" {
		t.Fatalf("invalid identity mapper status=%#v err=%v", invalidApplication.Status.ManagedIdentityMappings, err)
	}

	claim := hankoshv1alpha1.ApplicationTokenClaim{Name: "tenant", Claim: "tenant", UserAttribute: "tenant"}
	if status, err := preflightTokenClaims("test", "portal", 3, []hankoshv1alpha1.ApplicationTokenClaim{claim, claim}, nil); err == nil || len(status) != 1 || conditionReason(status[0].Conditions, "Synced") != "Invalid" {
		t.Fatalf("duplicate token preflight status=%#v err=%v", status, err)
	}
	owner := tokenClaimOwner{namespace: "test", name: "portal", generation: 3, realm: "acme", clientID: "portal"}
	seen := map[string]struct{}{"tenant": {}}
	if status, err := reconcileClientTokenClaim(context.Background(), nil, owner, claim, nil, seen); err == nil || conditionReason(status.Conditions, "Synced") != "Invalid" {
		t.Fatalf("duplicate runtime token claim status=%#v err=%v", status, err)
	}
	invalid := hankoshv1alpha1.ApplicationTokenClaim{Name: "unsafe", Claim: "sub", UserAttribute: "subject"}
	if status, err := reconcileClientTokenClaim(context.Background(), nil, owner, invalid, nil, map[string]struct{}{}); err == nil || conditionReason(status.Conditions, "Synced") != "Invalid" {
		t.Fatalf("reserved runtime token claim status=%#v err=%v", status, err)
	}
}

func TestApplicationStaleTokenCleanupFailureRetainsOwnership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "portal"}})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/clients/client-uuid/protocol-mappers/models/stale-uuid":
			http.Error(w, "denied", http.StatusForbidden)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	previous := []hankoshv1alpha1.ManagedTokenClaimReference{{Name: "stale", KeycloakID: "stale-uuid"}}
	owner := tokenClaimOwner{generation: 4, realm: "acme", clientID: "portal"}
	managed, err := deleteStaleClientTokenClaims(context.Background(), keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP()), owner, nil, previous)
	if err == nil || len(managed) != 1 || managed[0].KeycloakID != "stale-uuid" || conditionReason(managed[0].Conditions, "Synced") != "DeleteFailed" {
		t.Fatalf("failed stale cleanup managed=%#v err=%v", managed, err)
	}
}

func TestApplicationProviderMapperFailuresRetainCleanupOwnership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers":
			_ = json.NewEncoder(w).Encode([]keycloak.IdentityProviderMapper{{ID: "stale-idp", Config: map[string]string{"hanko.sh/application-owner": "application-uid"}}})

		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra/mappers/stale-idp":
			http.Error(w, "identity cleanup denied", http.StatusForbidden)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "client-uuid", "clientId": "portal"}})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/client-uuid/protocol-mappers/models":
			http.Error(w, "mapper inventory unavailable", http.StatusServiceUnavailable)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	kc := keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP())
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Generation: 5, UID: "application-uid"},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: "acme"},
		Status: hankoshv1alpha1.HankoApplicationStatus{ManagedIdentityMappings: []hankoshv1alpha1.ManagedIdentityMappingReference{{
			Name: "stale", IdentityProvider: "entra", KeycloakID: "stale-idp",
		}}},
	}
	reconciler := &HankoApplicationReconciler{}
	if err := reconciler.reconcileIdentityMappings(context.Background(), application, kc); err == nil ||
		len(application.Status.ManagedIdentityMappings) != 1 || conditionReason(application.Status.ManagedIdentityMappings[0].Conditions, "Synced") != "DeleteFailed" {
		t.Fatalf("failed identity cleanup status=%#v err=%v", application.Status.ManagedIdentityMappings, err)
	}
	claim := hankoshv1alpha1.ApplicationTokenClaim{Name: "tenant", Claim: "tenant", UserAttribute: "tenant"}
	owner := tokenClaimOwner{namespace: "test", name: "portal", generation: 5, realm: "acme", clientID: "portal"}
	managed, err := reconcileClientTokenClaims(context.Background(), kc, owner, []hankoshv1alpha1.ApplicationTokenClaim{claim}, nil)
	if err == nil || len(managed) != 1 || conditionReason(managed[0].Conditions, "Synced") != "EnsureFailed" {
		t.Fatalf("failed token ensure status=%#v err=%v", managed, err)
	}
}
