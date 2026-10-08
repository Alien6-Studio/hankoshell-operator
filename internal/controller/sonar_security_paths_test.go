package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestKeycloakInstanceReconcileExternalProbe(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/serverinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.0.0"}})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms":
			_ = json.NewEncoder(w).Encode([]keycloak.Realm{{ID: "master", RealmName: "master"}})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/master":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "admin"},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "test"},
		Data: map[string][]byte{
			"HANKO_KEYCLOAK_URL":     []byte(server.URL),
			"HANKO_KC_CLIENT_ID":     []byte("operator"),
			"HANKO_KC_CLIENT_SECRET": []byte("secret"),
		},
	}
	// The official operator may own a StatefulSet; external mode must leave it
	// untouched and work without installing any k8s.keycloak.org CRDs here.
	owned := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "official-keycloak", Namespace: "test", OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "k8s.keycloak.org/v2beta1", Kind: "Keycloak", Name: "official-keycloak", UID: "official-owner",
		}}},
		Spec: appsv1.StatefulSetSpec{ServiceName: "official-keycloak"},
	}
	k8sClient := controllerTestClient(scheme, instance, secret, owned)
	reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)})
	if err != nil {
		t.Fatalf("reconcile external instance: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("successful probe must schedule a future reconciliation")
	}
	var actual hankoshv1alpha1.HankoKeycloakInstance
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.KeycloakVersion != "26.0.0" || actual.Status.RealmCount != 1 {
		t.Fatalf("unexpected instance status: %#v", actual.Status)
	}
	var after appsv1.StatefulSet
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(owned), &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(owned.Spec, after.Spec) || !reflect.DeepEqual(owned.OwnerReferences, after.OwnerReferences) {
		t.Fatal("external mode must preserve the other operator's workload")
	}
	var deployments appsv1.DeploymentList
	if err := k8sClient.List(ctx, &deployments); err != nil || len(deployments.Items) != 0 {
		t.Fatalf("external mode must not create a Deployment: %v", err)
	}
}

func TestRealmRefactoringHelpersPreserveLifecycle(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "realm", Namespace: "test", Generation: 2},
	}
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{RealmRef: realm.Name, ClientID: "client"},
	}
	account := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: realm.Name, ClientID: "service"},
	}
	issuer := &hankoshv1alpha1.HankoIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoIssuerSpec{RealmRef: realm.Name, Host: "issuer.example.com"},
	}
	k8sClient := controllerTestClient(scheme, realm, application, account, issuer)
	reconciler := &HankoRealmReconciler{Client: k8sClient, Scheme: scheme}
	patch := client.MergeFrom(realm.DeepCopy())

	nextPatch, err := reconciler.markRealmGeneration(ctx, realm, patch)
	if err != nil {
		t.Fatalf("mark realm generation: %v", err)
	}
	if realm.Status.Phase != "Reconciling" || realm.Status.ObservedGeneration != realm.Generation {
		t.Fatalf("generation was not checkpointed: %#v", realm.Status)
	}
	handled, _, err := reconciler.waitForRealmTheme(ctx, realm, nextPatch)
	if err != nil || handled {
		t.Fatalf("default theme should be ready: handled=%v err=%v", handled, err)
	}
	if err := reconciler.reconcileManagedRealmChildren(ctx, realm, keycloak.New("https://unused.example", "id", "secret"), nextPatch); err != nil {
		t.Fatalf("reconcile empty realm children: %v", err)
	}
	blockers, err := reconciler.realmDeletionBlockers(ctx, realm)
	if err != nil || len(blockers) != 3 {
		t.Fatalf("realm blockers=%v err=%v", blockers, err)
	}
}

func TestRealmSMTPConditionObservesKeycloakWithoutChangingIt(t *testing.T) {
	var conditions []metav1.Condition
	setRealmSMTPCondition(&conditions, map[string]string{"host": "smtp.realm.example", "from": "noreply@example.com"})
	if got := conditionReason(conditions, "EmailDeliveryReady"); got != "RealmSMTPConfigured" {
		t.Fatalf("configured realm SMTP reason = %q", got)
	}
	setRealmSMTPCondition(&conditions, map[string]string{"host": "smtp.realm.example"})
	if got := conditionReason(conditions, "EmailDeliveryReady"); got != "RealmSMTPNotConfigured" {
		t.Fatalf("incomplete realm SMTP reason = %q", got)
	}
}

func TestSnapshotDataValidationBranches(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	for _, testCase := range []struct {
		name     string
		mutate   func(*hankoshv1alpha1.HankoSnapshot, *hankoshv1alpha1.HankoKeycloakInstance)
		expected string
	}{
		{name: "missing pvc", mutate: func(snapshot *hankoshv1alpha1.HankoSnapshot, _ *hankoshv1alpha1.HankoKeycloakInstance) {
			snapshot.Spec.BackupPVC = ""
		}, expected: "BackupPVCMissing"},
		{name: "unmanaged instance", mutate: func(_ *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance) {
			instance.Spec.Managed = nil
		}, expected: "ManagedSpecMissing"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			currentInstance := instance.DeepCopy()
			snapshot := &hankoshv1alpha1.HankoSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "validation", Namespace: "test"},
				Spec:       hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: instance.Name, IncludeData: true, BackupPVC: "backups"},
			}
			testCase.mutate(snapshot, currentInstance)
			k8sClient := controllerTestClient(scheme, snapshot)
			reconciler := &HankoSnapshotReconciler{Client: k8sClient, Scheme: scheme}
			_, handled := reconciler.reconcileSnapshotData(ctx, snapshot, currentInstance, client.MergeFrom(snapshot.DeepCopy()))
			if !handled || snapshot.Status.Phase != "Failed" || realmConditionForSnapshot(snapshot, testCase.expected) == nil {
				t.Fatalf("unexpected validation status: %#v", snapshot.Status)
			}
		})
	}
}

func realmConditionForSnapshot(snapshot *hankoshv1alpha1.HankoSnapshot, reason string) *metav1.Condition {
	for i := range snapshot.Status.Conditions {
		if snapshot.Status.Conditions[i].Reason == reason {
			return &snapshot.Status.Conditions[i]
		}
	}
	return nil
}

func TestKeycloakInstanceFailuresAreReportedWithoutUnsafeFallback(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	t.Run("missing admin secret", func(t *testing.T) {
		instance := &hankoshv1alpha1.HankoKeycloakInstance{
			ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "test"},
			Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
				Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "absent"},
			},
		}
		k8sClient := controllerTestClient(scheme, instance)
		reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)})
		if err != nil || result.RequeueAfter != requeueOnError {
			t.Fatalf("missing secret result=%v err=%v", result, err)
		}
		var actual hankoshv1alpha1.HankoKeycloakInstance
		_ = k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), &actual)
		if actual.Status.Phase != "Error" || conditionReason(actual.Status.Conditions, "AdminAPIReachable") != "SecretError" {
			t.Fatalf("missing secret status: %#v", actual.Status)
		}
	})

	t.Run("untrusted managed image", func(t *testing.T) {
		instance := managedTestInstance("test", "managed")
		k8sClient := controllerTestClient(scheme, instance)
		reconciler := &HankoKeycloakInstanceReconciler{
			Client: k8sClient, Scheme: scheme, ImageValidator: imagevalidator.NewWithPrefixes("registry.example.com/"),
		}
		_, handled, err := reconciler.reconcileInstanceMode(ctx, instance, client.MergeFrom(instance.DeepCopy()))
		if err != nil || !handled || instance.Status.Phase != "Error" || conditionReason(instance.Status.Conditions, "AdminAPIReachable") != "UntrustedImageRef" {
			t.Fatalf("untrusted image status: handled=%t status=%#v err=%v", handled, instance.Status, err)
		}
	})

	for _, testCase := range []struct {
		name       string
		deployment bool
		expected   string
		handled    bool
	}{
		{name: "missing adopted spec", expected: "MissingAdoptedSpec", handled: true},
		{name: "missing adopted deployment", expected: "DeploymentNotFound", handled: true},
		{name: "existing adopted deployment", deployment: true, handled: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			instance := &hankoshv1alpha1.HankoKeycloakInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: "test"},
				Spec:       hankoshv1alpha1.HankoKeycloakInstanceSpec{Mode: "adopted"},
			}
			objects := []client.Object{instance}
			if testCase.name != "missing adopted spec" {
				instance.Spec.Adopted = &hankoshv1alpha1.AdoptedKeycloakSpec{DeploymentRef: "keycloak"}
			}
			if testCase.deployment {
				objects = append(objects, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: "test"}})
			}
			k8sClient := controllerTestClient(scheme, objects...)
			reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}
			_, handled, err := reconciler.reconcileInstanceMode(ctx, instance, client.MergeFrom(instance.DeepCopy()))
			if err != nil || handled != testCase.handled {
				t.Fatalf("adopted mode handled=%t err=%v", handled, err)
			}
			if testCase.expected != "" && conditionReason(instance.Status.Conditions, "AdminAPIReachable") != testCase.expected {
				t.Fatalf("adopted status: %#v", instance.Status)
			}
		})
	}
}

func TestKeycloakInstanceProbeAndHardeningFailuresAreVisible(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	for _, testCase := range []struct {
		name          string
		serverVersion bool
	}{
		{name: "server version failure"},
		{name: "realm list failure", serverVersion: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch {
				case request.URL.Path == "/realms/master/protocol/openid-connect/token":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
				case request.URL.Path == "/admin/serverinfo" && testCase.serverVersion:
					_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]string{"version": "26.0.0"}})
				default:
					http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
				}
			}))
			t.Cleanup(server.Close)
			instance := &hankoshv1alpha1.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: "test"}}
			k8sClient := controllerTestClient(scheme, instance)
			reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}
			_, _, handled := reconciler.probeKeycloakInstance(ctx, instance, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP()), client.MergeFrom(instance.DeepCopy()))
			if !handled || instance.Status.Phase != "Degraded" || conditionReason(instance.Status.Conditions, "AdminAPIReachable") != "ProbeError" {
				t.Fatalf("probe failure status: %#v", instance.Status)
			}
		})
	}
}

func TestManagedRealmSecurityBaselineReconcilesAllProviderControls(t *testing.T) {
	updates := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/events/config":
			var payload map[string]any
			_ = json.NewDecoder(request.Body).Decode(&payload)
			updates["events"] = payload
			w.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "console-uuid", "clientId": "security-admin-console"}})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/clients/console-uuid":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "console-uuid", "enabled": true})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/clients/console-uuid":
			var payload map[string]any
			_ = json.NewDecoder(request.Body).Decode(&payload)
			updates["console"] = payload
			w.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/acme/identity-provider/instances":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"alias": "entra", "trustEmail": true, "config": map[string]any{"validateSignature": "false"},
			}})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/acme/identity-provider/instances/entra":
			var payload map[string]any
			_ = json.NewDecoder(request.Body).Decode(&payload)
			updates["identity-provider"] = payload
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	retentionDays := 30
	exportEnabled := true
	requireSignature := true
	trustEmail := false
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
			AuditRetentionDays: &retentionDays, AuditExportEnabled: &exportEnabled,
			AdminConsoleExposure: "disabled", IDPBrokerRequireSignature: &requireSignature, IDPBrokerTrustEmail: &trustEmail,
		}},
	}
	desired := keycloak.RealmSpec{
		AuditRetentionDays: &retentionDays, AuditExportEnabled: &exportEnabled,
		AdminConsoleExposure: "disabled", IDPBrokerRequireSignature: &requireSignature, IDPBrokerTrustEmail: &trustEmail,
	}
	reconciler := &HankoRealmReconciler{}
	handled, result, err := reconciler.reconcileManagedRealmSecurity(
		context.Background(), realm, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP()), desired, nil,
	)
	if err != nil || handled || !result.IsZero() {
		t.Fatalf("security baseline result=%v handled=%t err=%v", result, handled, err)
	}
	if conditionReason(realm.Status.Conditions, "OperationalSecurity") != "Reconciled" {
		t.Fatalf("security status = %#v", realm.Status.Conditions)
	}
	if updates["events"]["eventsExpiration"] != float64(30*24*60*60) || updates["console"]["enabled"] != false {
		t.Fatalf("security payloads events=%#v console=%#v", updates["events"], updates["console"])
	}
	providerConfig, _ := updates["identity-provider"]["config"].(map[string]any)
	if updates["identity-provider"]["trustEmail"] != false || providerConfig["validateSignature"] != "true" {
		t.Fatalf("identity-provider trust payload = %#v", updates["identity-provider"])
	}
}

func TestManagedRealmSecurityFailuresAreCheckpointed(t *testing.T) {
	retentionDays := 30
	requireSignature := true
	for _, test := range []struct {
		name, reason string
		profile      hankoshv1alpha1.RealmSecurityProfile
		desired      keycloak.RealmSpec
		handler      func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "audit", reason: "AuditPolicyFailed",
			profile: hankoshv1alpha1.RealmSecurityProfile{AuditRetentionDays: &retentionDays},
			desired: keycloak.RealmSpec{AuditRetentionDays: &retentionDays},
			handler: func(w http.ResponseWriter, request *http.Request) {
				http.Error(w, "audit denied", http.StatusForbidden)
			},
		},
		{
			name: "admin console", reason: "AdminConsolePolicyFailed",
			profile: hankoshv1alpha1.RealmSecurityProfile{AdminConsoleExposure: "disabled"},
			desired: keycloak.RealmSpec{AdminConsoleExposure: "disabled"},
			handler: func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/admin/realms/acme/events/config" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				_ = json.NewEncoder(w).Encode([]map[string]string{})
			},
		},
		{
			name: "identity provider trust", reason: "IdentityProviderTrustFailed",
			profile: hankoshv1alpha1.RealmSecurityProfile{IDPBrokerRequireSignature: &requireSignature},
			desired: keycloak.RealmSpec{IDPBrokerRequireSignature: &requireSignature},
			handler: func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/admin/realms/acme/events/config" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.Error(w, "broker policy denied", http.StatusForbidden)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/realms/master/protocol/openid-connect/token" {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
					return
				}
				test.handler(w, request)
			}))
			t.Cleanup(server.Close)
			realm := &hankoshv1alpha1.HankoRealm{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test"},
				Spec:       hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &test.profile},
			}
			k8sClient := controllerTestClient(controllerTestScheme(t), realm)
			reconciler := &HankoRealmReconciler{Client: k8sClient}
			handled, result, err := reconciler.reconcileManagedRealmSecurity(
				context.Background(), realm, keycloak.New(server.URL, "operator", "secret", keycloak.WithInsecureHTTP()), test.desired, client.MergeFrom(realm.DeepCopy()),
			)
			if !handled || err == nil || result.RequeueAfter != requeueOnError || realm.Status.Phase != "Error" || conditionReason(realm.Status.Conditions, "OperationalSecurity") != test.reason {
				t.Fatalf("%s failure result=%v handled=%t status=%#v err=%v", test.name, result, handled, realm.Status, err)
			}
		})
	}
}

func TestRealmIdentityProviderValidationFailsClosed(t *testing.T) {
	seen := map[string]struct{}{}
	if err := validateRealmIdentityProvider(hankoshv1alpha1.RealmIdentityProvider{}, seen); err == nil {
		t.Fatal("identity provider without alias and provider ID must be rejected")
	}
	provider := hankoshv1alpha1.RealmIdentityProvider{Alias: "entra", ProviderID: "oidc"}
	if err := validateRealmIdentityProvider(provider, seen); err != nil {
		t.Fatalf("valid identity provider: %v", err)
	}
	if err := validateRealmIdentityProvider(provider, seen); err == nil {
		t.Fatal("duplicate identity provider alias must be rejected")
	}

	realm := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test"}}
	reconciler := &HankoRealmReconciler{Client: controllerTestClient(controllerTestScheme(t))}
	provider.Config = map[string]string{"clientSecret": "inline-secret"}
	if _, err := reconciler.identityProviderForRealm(context.Background(), realm, provider); err == nil {
		t.Fatal("inline identity-provider secret must be rejected")
	}
	provider.Config = nil
	provider.ClientSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "missing"}, Key: "clientSecret",
	}
	if _, err := reconciler.identityProviderForRealm(context.Background(), realm, provider); err == nil {
		t.Fatal("missing identity-provider secret must fail closed")
	}
	emptySecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "test"}, Data: map[string][]byte{}}
	reconciler.Client = controllerTestClient(controllerTestScheme(t), emptySecret)
	provider.ClientSecretRef.Name = emptySecret.Name
	if _, err := reconciler.identityProviderForRealm(context.Background(), realm, provider); err == nil {
		t.Fatal("missing identity-provider secret key must fail closed")
	}
}

func TestRealmMapperOwnershipConflictIsDetected(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoRealmSpec{IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
			Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{Name: "shared", IdentityProviderMapper: "oidc-role-idp-mapper"}},
		}}},
	}
	application := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef: "acme", ClientID: "portal", Mode: ModeManage,
			IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
				Name: "mapping", KeycloakName: "shared", IdentityProvider: "entra", Claim: "groups", MatchValue: "admins",
				Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "admin"},
			}},
		},
	}
	reconciler := &HankoRealmReconciler{Client: controllerTestClient(controllerTestScheme(t), application)}
	if err := reconciler.findRealmIdentityProviderMapperConflict(context.Background(), realm); err == nil {
		t.Fatal("two managed owners for one Keycloak mapper must be rejected")
	}
}
