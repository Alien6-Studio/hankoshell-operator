//go:build keycloak_integration

package controller_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func fixtureMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: "qualification", UID: types.UID(name), Generation: 1}
}

func fixtureEqual(t *testing.T, label string, actual, expected any) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		// Avoid leaking credentials embedded in full provider representations.
		t.Fatalf("%s differs from the expected state (values withheld)", label)
	}
}

func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type fixtureReconciler interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
}

func fixtureReconcile(f *keycloakFixture, ctx context.Context, r fixtureReconciler, object client.Object) {
	f.t.Helper()
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)})
	f.requireNoError(err)
}

func fixtureGet(f *keycloakFixture, ctx context.Context, k8s client.Client, object client.Object) {
	f.t.Helper()
	f.requireNoError(k8s.Get(ctx, client.ObjectKeyFromObject(object), object))
	if _, secret := object.(*corev1.Secret); !secret {
		f.requireNoCredentials("reconciled CRD spec/status", fixtureJSON(f.t, object))
	}
}

func fixtureSecretValue(secret *corev1.Secret) string {
	if value := secret.Data["client_secret"]; len(value) != 0 {
		return string(value)
	}
	// The fake Kubernetes client does not perform the API server's StringData
	// conversion. Real API storage/RBAC are independently qualified by envtest.
	return secret.StringData["client_secret"]
}

// TestRealKeycloakCompatibility runs actual reconcilers against the pinned
// Keycloak Admin API v1 over verified TLS 1.3. The Kubernetes client is fake;
// Kubernetes storage/admission/security have their own real-server CI matrix.
func TestRealKeycloakCompatibility(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := log.IntoContext(context.Background(), zap.New(zap.WriteTo(&f.logs)))
	version, err := f.kc.ServerVersion(ctx)
	f.requireNoError(err)
	expectedVersion := "" // Both qualified versions restrict systemInfo to master managers.
	fixtureEqual(t, "scoped server discovery", version, expectedVersion)
	t.Logf("qualified fixture: Keycloak %s; verified HTTPS, Admin API v1, client_credentials (version disclosure may be restricted)", f.version)

	t.Log("TLS verification and insufficient-privilege rejection")
	untrusted := keycloak.New(f.baseURL, "fixture-operator", f.credential)
	if _, err := untrusted.ServerVersion(ctx); err == nil {
		t.Fatal("untrusted fixture certificate was accepted")
	}
	wrongCA, _ := fixtureTLS(t)
	wrongTrust, err := keycloak.NewWithTLS(f.baseURL, "fixture-operator", f.credential, wrongCA)
	f.requireNoError(err)
	if _, err := wrongTrust.ServerVersion(ctx); err == nil {
		t.Fatal("incorrect CA was accepted")
	}
	address := strings.TrimPrefix(f.baseURL, "https://")
	// Same real server and trusted CA, but no IP SAN: exercise the production
	// client's hostname verification, not merely the fixture's TLS transport.
	wrongHost, err := keycloak.NewWithTLS(strings.Replace(f.baseURL, "localhost", "127.0.0.1", 1), "fixture-operator", f.credential, f.ca)
	f.requireNoError(err)
	f.requireNoError(wrongHost.RequireHTTPS())
	_, err = wrongHost.ServerVersion(ctx)
	var hostnameError x509.HostnameError
	if !errors.As(err, &hostnameError) {
		t.Fatal("operator client did not reject the real server's certificate hostname mismatch")
	}
	if _, err := keycloak.New("http://"+address, "fixture-operator", f.credential).ServerVersion(ctx); err == nil || !strings.Contains(err.Error(), "requires explicit") {
		t.Fatal("standard client attempted real-Keycloak cleartext traffic without opt-in")
	}
	if err := keycloak.New("http://"+address, "fixture-operator", f.credential).RequireHTTPS(); err == nil {
		t.Fatal("enterprise client accepted cleartext HTTP")
	}
	restricted, _ := f.serviceClient("fixture-no-admin")
	if _, err := restricted.ServerVersion(ctx); err == nil || !keycloak.IsForbidden(err) {
		t.Fatal("unprivileged service account was not rejected by serverinfo")
	}
	if err := restricted.EnsureRealmManagementAccess(ctx, "forbidden-realm"); err == nil {
		t.Fatal("unprivileged service account granted itself realm management access")
	}
	if err := restricted.CreateRealm(ctx, keycloak.RealmSpec{ID: "forbidden-realm"}); err == nil || !keycloak.IsForbidden(err) {
		t.Fatal("unprivileged service account created a realm")
	}
	if f.admin(http.MethodGet, "/admin/realms/forbidden-realm", nil, nil) != http.StatusNotFound {
		t.Fatal("denied realm creation left provider state behind")
	}
	var forbiddenProxies []map[string]any
	f.admin(http.MethodGet, "/admin/realms/master/clients?clientId=forbidden-realm-realm", nil, &forbiddenProxies)
	fixtureEqual(t, "denied management access left no proxy", len(forbiddenProxies), 0)

	scheme := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&hanko.HankoApplication{}, controller.RealmClientIndexKey, realmClientIndexer).
		WithStatusSubresource(&hanko.HankoApplication{}, &hanko.HankoServiceAccount{}, &hanko.HankoRealm{},
			&hanko.HankoRole{}, &hanko.HankoIAMProfile{}, &hanko.HankoImport{}, &hanko.HankoKeycloakInstance{}).Build()
	pool := keycloak.NewPool(f.kc)
	recorder := events.NewFakeRecorder(100)
	rr := &controller.HankoRealmReconciler{Client: k8s, Scheme: scheme, Pool: pool, Recorder: recorder}
	ar := &controller.HankoApplicationReconciler{Client: k8s, OwnershipReader: k8s, Scheme: scheme, Pool: pool, Recorder: recorder}
	sr := &controller.HankoServiceAccountReconciler{Client: k8s, OwnershipReader: k8s, Scheme: scheme, Pool: pool, Recorder: recorder}
	ror := &controller.HankoRoleReconciler{Client: k8s, Scheme: scheme, Pool: pool, Recorder: recorder}

	// Audit logs/events and every CRD (spec AND status), including failure paths.
	// Kubernetes Secrets are the only intended credential storage objects.
	t.Cleanup(func() {
		f.requireNoCredentials("controller logs", f.logs.Bytes())
		for len(recorder.Events) > 0 {
			f.requireNoCredentials("Kubernetes events", []byte(<-recorder.Events))
		}
		for _, list := range []client.ObjectList{&hanko.HankoRealmList{}, &hanko.HankoApplicationList{}, &hanko.HankoServiceAccountList{},
			&hanko.HankoRoleList{}, &hanko.HankoIAMProfileList{}, &hanko.HankoImportList{}, &hanko.HankoKeycloakInstanceList{}} {
			f.requireNoError(k8s.List(ctx, list))
			f.requireNoCredentials("CRD specs/status", fixtureJSON(t, list))
		}
	})

	t.Log("external instance diagnostics expose the existing version status")
	instance := &hanko.HankoKeycloakInstance{ObjectMeta: fixtureMeta("external"), Spec: hanko.HankoKeycloakInstanceSpec{
		Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "admin"}, TLSCARef: "ca",
	}}
	admin := &corev1.Secret{ObjectMeta: fixtureMeta("admin"), Data: map[string][]byte{
		"HANKO_KEYCLOAK_URL": []byte(f.baseURL), "HANKO_KC_CLIENT_ID": []byte("fixture-operator"), "HANKO_KC_CLIENT_SECRET": []byte(f.credential),
	}}
	ca := &corev1.Secret{ObjectMeta: fixtureMeta("ca"), Data: map[string][]byte{"ca.crt": f.ca}}
	for _, object := range []client.Object{admin, ca, instance} {
		f.requireNoError(k8s.Create(ctx, object))
	}
	ir := &controller.HankoKeycloakInstanceReconciler{Client: k8s, Scheme: scheme, Recorder: recorder, RequireHTTPS: true}
	fixtureReconcile(f, ctx, ir, instance)
	fixtureGet(f, ctx, k8s, instance)
	fixtureEqual(t, "instance phase", instance.Status.Phase, "Ready")
	fixtureEqual(t, "instance status version", instance.Status.KeycloakVersion, expectedVersion)
	operatorBefore := f.client("master", "fixture-operator")
	unprivilegedBefore := f.client("master", "fixture-no-admin")

	t.Log("the operator's own credential client cannot be adopted or deleted")
	self := &hanko.HankoServiceAccount{ObjectMeta: fixtureMeta("forbidden-self"), Spec: hanko.HankoServiceAccountSpec{RealmRef: "master", ClientID: "fixture-operator"}}
	f.requireNoError(k8s.Create(ctx, self))
	fixtureReconcile(f, ctx, sr, self)
	fixtureGet(f, ctx, k8s, self)
	fixtureEqual(t, "self-ownership denied", self.Status.Phase, "Error")
	if self.Status.SecretRef != nil || len(self.Finalizers) != 0 {
		t.Fatal("own credential client acquired Secret/destructive ownership")
	}
	f.requireNoError(k8s.Delete(ctx, self))
	fixtureReconcile(f, ctx, sr, self)
	fixtureEqual(t, "own credential client preserved after denied adoption/deletion", f.client("master", "fixture-operator"), operatorBefore)

	t.Log("pre-provisioned realm, IAM/MFA/password/session/brute-force policy, roles and identity provider")
	enabled, disabled := true, false
	profile := &hanko.HankoIAMProfile{ObjectMeta: fixtureMeta("secure"), Spec: hanko.HankoIAMProfileSpec{Security: hanko.RealmSecurityProfile{
		MFAPolicy: "required", PasswordMinLength: 14, PasswordRequireDigit: &enabled,
		SessionLifetime: "8h", SessionIdleTimeout: "20m", SSLRequired: "all", RevokeRefreshToken: true,
		OTPAlgorithm: "HmacSHA256", OTPDigits: 8, OTPPeriodSeconds: 30,
		BruteForce: &hanko.BruteForcePolicy{Enabled: true, MaxFailures: 4}, AdminEventsEnabled: &enabled,
	}}}
	idpSecret := fixtureSecret(t)
	f.secrets = append(f.secrets, idpSecret)
	f.requireNoError(k8s.Create(ctx, &corev1.Secret{ObjectMeta: fixtureMeta("broker-secret"), Data: map[string][]byte{"secret": []byte(idpSecret)}}))
	realm := &hanko.HankoRealm{ObjectMeta: fixtureMeta("managed"), Spec: hanko.HankoRealmSpec{
		DisplayName: "Qualified realm", IAMProfileRef: "secure", Roles: []hanko.RealmRole{{Name: "reader", Description: "Read"}},
		IdentityProviders: []hanko.RealmIdentityProvider{{Alias: "managed-oidc", ProviderID: "oidc", Enabled: &disabled,
			Config:          map[string]string{"clientId": "upstream-client", "authorizationUrl": "https://idp.invalid/authorize", "tokenUrl": "https://idp.invalid/token", "syncMode": "IMPORT"},
			ClientSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "broker-secret"}, Key: "secret"},
			Mappers:         []hanko.RealmIdentityProviderMapper{{Name: "department", IdentityProviderMapper: "oidc-user-attribute-idp-mapper", Config: map[string]string{"claim": "department", "user.attribute": "department", "syncMode": "INHERIT"}}},
		}},
	}}
	f.requireNoError(k8s.Create(ctx, profile))
	f.requireNoError(k8s.Create(ctx, realm))
	fixtureReconcile(f, ctx, rr, realm)
	fixtureGet(f, ctx, k8s, realm)
	fixtureEqual(t, "realm phase", realm.Status.Phase, "Ready")
	fixtureEqual(t, "applied MFA policy", realm.Status.AppliedMFAPolicy, "required")
	if realm.Status.KeycloakRealmID == "" || realm.Status.EffectivePolicyHash == "" {
		t.Fatal("realm provider identity/policy diagnostics missing")
	}
	var actualRealm map[string]any
	getRealm := func() map[string]any {
		var value map[string]any
		f.admin(http.MethodGet, "/admin/realms/managed", nil, &value)
		return value
	}
	actualRealm = getRealm()
	for key, expected := range map[string]any{"displayName": "Qualified realm", "ssoSessionMaxLifespan": float64(28800),
		"ssoSessionIdleTimeout": float64(1200), "bruteForceProtected": true, "failureFactor": float64(4),
		"sslRequired": "all", "revokeRefreshToken": true, "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": float64(8)} {
		fixtureEqual(t, "IAM property "+key, actualRealm[key], expected)
	}
	if !strings.Contains(actualRealm["passwordPolicy"].(string), "length(14)") || !strings.Contains(actualRealm["passwordPolicy"].(string), "digits(1)") {
		t.Fatal("password policy was not applied")
	}
	var actions []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/authentication/required-actions", nil, &actions)
	configuredOTP := false
	for _, action := range actions {
		if action["alias"] == "CONFIGURE_TOTP" {
			fixtureEqual(t, "TOTP default required action", action["defaultAction"], true)
			configuredOTP = true
		}
	}
	if !configuredOTP {
		t.Fatal("TOTP required action missing")
	}
	providers, err := f.kc.ListIdentityProviders(ctx, "managed")
	f.requireNoError(err)
	fixtureEqual(t, "managed IDP count", len(providers), 1)
	fixtureEqual(t, "managed IDP alias", providers[0].Alias, "managed-oidc")
	var mappers []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances/managed-oidc/mappers", nil, &mappers)
	fixtureEqual(t, "managed IDP mapper count", len(mappers), 1)
	policyRevision := realm.Status.PolicyRevision
	fixtureReconcile(f, ctx, rr, realm)
	fixtureGet(f, ctx, k8s, realm)
	fixtureEqual(t, "realm second reconciliation", getRealm(), actualRealm)
	fixtureEqual(t, "policy revision idempotence", realm.Status.PolicyRevision, policyRevision)

	role := &hanko.HankoRole{ObjectMeta: fixtureMeta("editor"), Spec: hanko.HankoRoleSpec{
		RealmRef: "managed", Name: "editor", Description: "Edit", Composite: true, Composites: []string{"reader"},
	}}
	f.requireNoError(k8s.Create(ctx, role))
	fixtureReconcile(f, ctx, ror, role)
	fixtureGet(f, ctx, k8s, role)
	fixtureEqual(t, "composite role phase", role.Status.Phase, "Ready")
	var composites []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/roles/editor/composites/realm", nil, &composites)
	fixtureEqual(t, "composite membership count", len(composites), 1)
	fixtureEqual(t, "composite membership", composites[0]["name"], "reader")
	fixtureReconcile(f, ctx, ror, role)

	t.Log("SPA, confidential web and M2M applications; redirects, logout and client roles")
	var applications []*hanko.HankoApplication
	for _, kind := range []string{"spa", "web", "m2m"} {
		app := &hanko.HankoApplication{ObjectMeta: fixtureMeta("app-" + kind), Spec: hanko.HankoApplicationSpec{
			RealmRef: "managed", ClientID: "app-" + kind, Type: kind,
			RedirectURIs: []string{"https://app.example/callback"}, PostLogoutRedirectURIs: []string{"https://app.example/logout"},
			Roles: []hanko.ApplicationRole{{Name: "use", Description: "Use application"}},
		}}
		f.requireNoError(k8s.Create(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		fixtureGet(f, ctx, k8s, app)
		fixtureEqual(t, "application phase "+kind, app.Status.Phase, "Ready")
		provider := f.client("managed", app.Spec.ClientID)
		fixtureEqual(t, "public client "+kind, provider["publicClient"], kind == "spa")
		fixtureEqual(t, "service account enabled "+kind, provider["serviceAccountsEnabled"], kind == "m2m")
		fixtureEqual(t, "disabled direct grant "+kind, provider["directAccessGrantsEnabled"], false)
		fixtureEqual(t, "disabled full scope "+kind, provider["fullScopeAllowed"], false)
		fixtureEqual(t, "redirects "+kind, provider["redirectUris"], []any{"https://app.example/callback"})
		fixtureEqual(t, "logout redirects "+kind, provider["attributes"].(map[string]any)["post.logout.redirect.uris"], "https://app.example/logout")
		roles, err := f.kc.ListClientRoles(ctx, "managed", app.Spec.ClientID)
		f.requireNoError(err)
		fixtureEqual(t, "client role count "+kind, len(roles), 1)
		if kind == "spa" {
			if app.Status.ClientSecret != nil {
				t.Fatal("public client gained a credential reference")
			}
		} else {
			secret, err := f.kc.GetClientSecret(ctx, "managed", app.Spec.ClientID)
			f.requireNoError(err)
			if secret == "" {
				t.Fatal("confidential client has no credential")
			}
			f.secrets = append(f.secrets, secret)
			if app.Status.ClientSecret == nil {
				t.Fatal("confidential client Secret reference missing")
			}
		}
		fixtureReconcile(f, ctx, ar, app)
		fixtureEqual(t, "application idempotence "+kind, f.client("managed", app.Spec.ClientID), provider)
		applications = append(applications, app)
	}

	t.Log("service-account secret creation, recovery, rotation and no repeated rotation")
	sa := &hanko.HankoServiceAccount{ObjectMeta: fixtureMeta("worker"), Spec: hanko.HankoServiceAccountSpec{
		RealmRef: "managed", ClientID: "worker", SecretRotationPolicy: &hanko.SecretRotationPolicy{Enabled: true, IntervalDays: 30},
	}}
	f.requireNoError(k8s.Create(ctx, sa))
	fixtureReconcile(f, ctx, sr, sa)
	fixtureGet(f, ctx, k8s, sa)
	fixtureEqual(t, "service account phase", sa.Status.Phase, "Ready")
	if sa.Status.SecretRef == nil || sa.Status.LastRotated == nil {
		t.Fatal("service account credential references missing")
	}
	secretObject := &corev1.Secret{ObjectMeta: fixtureMeta(sa.Status.SecretRef.SecretRef.Name)}
	fixtureGet(f, ctx, k8s, secretObject)
	first, err := f.kc.GetClientSecret(ctx, "managed", "worker")
	f.requireNoError(err)
	if first == "" {
		t.Fatal("empty service-account secret")
	}
	f.secrets = append(f.secrets, first)
	fixtureEqual(t, "projected service-account secret", fixtureSecretValue(secretObject), first)
	fixtureReconcile(f, ctx, sr, sa)
	again, err := f.kc.GetClientSecret(ctx, "managed", "worker")
	f.requireNoError(err)
	fixtureEqual(t, "no initial repeated rotation", again, first)
	f.requireNoError(k8s.Delete(ctx, secretObject))
	fixtureReconcile(f, ctx, sr, sa)
	fixtureGet(f, ctx, k8s, secretObject)
	fixtureEqual(t, "lost Secret recovery", fixtureSecretValue(secretObject), first)
	fixtureGet(f, ctx, k8s, sa)
	// ForceRotateAt and persisted timestamps use whole seconds. Schedule the
	// trigger strictly after the initial rotation, avoiding boundary flakiness.
	for !time.Now().Truncate(time.Second).After(sa.Status.LastRotated.Time) {
		time.Sleep(50 * time.Millisecond)
	}
	trigger := metav1.NewTime(time.Now().Truncate(time.Second))
	sa.Spec.SecretRotationPolicy.ForceRotateAt = &trigger
	f.requireNoError(k8s.Update(ctx, sa))
	fixtureReconcile(f, ctx, sr, sa)
	fixtureGet(f, ctx, k8s, sa)
	rotated, err := f.kc.GetClientSecret(ctx, "managed", "worker")
	f.requireNoError(err)
	if rotated == "" || rotated == first {
		t.Fatal("forced rotation did not replace the credential")
	}
	f.secrets = append(f.secrets, rotated)
	fixtureGet(f, ctx, k8s, secretObject)
	fixtureEqual(t, "projected rotated secret", fixtureSecretValue(secretObject), rotated)
	rotatedAt := sa.Status.LastRotated.DeepCopy()
	fixtureReconcile(f, ctx, sr, sa)
	fixtureGet(f, ctx, k8s, sa)
	again, err = f.kc.GetClientSecret(ctx, "managed", "worker")
	f.requireNoError(err)
	fixtureEqual(t, "no repeated forced rotation", again, rotated)
	fixtureEqual(t, "no repeated rotation timestamp", sa.Status.LastRotated, rotatedAt)

	t.Log("unrelated provider objects survive reconciliation and child finalizers")
	f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "unrelated", "enabled": true}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": "unowned", "enabled": true, "publicClient": true, "protocol": "openid-connect"}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/roles", map[string]any{"name": "unowned-role"}, nil)
	f.admin(http.MethodPost, "/admin/realms/managed/identity-provider/instances", map[string]any{"alias": "unowned-idp", "providerId": "oidc", "enabled": false, "config": map[string]string{"clientId": "unowned"}}, nil)
	unowned := f.client("managed", "unowned")
	var masterBefore, unrelatedBefore map[string]any
	f.admin(http.MethodGet, "/admin/realms/master", nil, &masterBefore)
	f.admin(http.MethodGet, "/admin/realms/unrelated", nil, &unrelatedBefore)
	actualRealm = getRealm()
	actualRealm["displayName"] = "drift"
	f.admin(http.MethodPut, "/admin/realms/managed", actualRealm, nil)
	spa := applications[0]
	provider := f.client("managed", spa.Spec.ClientID)
	provider["redirectUris"] = []string{"https://drift.example/callback"}
	provider["attributes"].(map[string]any)["post.logout.redirect.uris"] = "https://drift.example/logout"
	f.admin(http.MethodPut, "/admin/realms/managed/clients/"+provider["id"].(string), provider, nil)
	fixtureReconcile(f, ctx, rr, realm)
	fixtureReconcile(f, ctx, ar, spa)
	fixtureEqual(t, "realm drift restored", getRealm()["displayName"], "Qualified realm")
	provider = f.client("managed", spa.Spec.ClientID)
	fixtureEqual(t, "redirect drift restored", provider["redirectUris"], []any{"https://app.example/callback"})
	fixtureEqual(t, "logout drift restored", provider["attributes"].(map[string]any)["post.logout.redirect.uris"], "https://app.example/logout")
	fixtureEqual(t, "unowned client preserved", f.client("managed", "unowned"), unowned)
	if _, err := f.kc.GetRealmRole(ctx, "managed", "unowned-role"); err != nil {
		f.requireNoError(err)
	}
	f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances/unowned-idp", nil, &provider)
	fixtureEqual(t, "unowned IDP preserved", provider["alias"], "unowned-idp")

	t.Log("real import and observe paths are read-only and omit sensitive credentials")
	observer, _ := f.serviceClient("qualification-observer")
	f.grantClientRoles("qualification-observer", "managed", []string{"view-realm", "view-clients", "view-identity-providers"})
	observePool := keycloak.NewPool(observer)
	observeRealm := &controller.HankoRealmReconciler{Client: k8s, Scheme: scheme, Pool: observePool, Recorder: recorder}
	observeApp := &controller.HankoApplicationReconciler{Client: k8s, OwnershipReader: k8s, Scheme: scheme, Pool: observePool, Recorder: recorder}
	observeAccount := &controller.HankoServiceAccountReconciler{Client: k8s, OwnershipReader: k8s, Scheme: scheme, Pool: observePool, Recorder: recorder}
	beforeObserveRealm := getRealm()
	beforeObserveSPA := f.client("managed", "app-spa")
	beforeObserveWorker := f.client("managed", "worker")
	var beforeEvents []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/admin-events", nil, &beforeEvents)
	if len(beforeEvents) == 0 {
		t.Fatal("Admin API write-event auditing is inactive; observation cannot be qualified")
	}
	importer := &controller.HankoImportReconciler{Client: k8s, Scheme: scheme, Pool: observePool, RequireHTTPS: true}
	importObject := &hanko.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "inventory"}, Spec: hanko.HankoImportSpec{SourceRef: "external", Realms: []string{"managed"}}}
	f.requireNoError(k8s.Create(ctx, importObject))
	fixtureReconcile(f, ctx, importer, importObject)
	fixtureGet(f, ctx, k8s, importObject)
	fixtureEqual(t, "import phase", importObject.Status.Phase, "Done")
	for _, condition := range importObject.Status.Conditions {
		if condition.Reason == "PartialFailure" || condition.Status == metav1.ConditionFalse {
			t.Fatal("import partially failed")
		}
	}
	if importObject.Status.Applied.Applications < 2 || importObject.Status.Applied.ServiceAccounts < 2 || importObject.Status.Applied.IdentityProviders != 2 {
		t.Fatal("import did not inventory all requested provider resources")
	}
	var importedRealms hanko.HankoRealmList
	f.requireNoError(k8s.List(ctx, &importedRealms, client.InNamespace("inventory")))
	fixtureEqual(t, "imported realm count", len(importedRealms.Items), 1)
	for i := range importedRealms.Items {
		observed := &importedRealms.Items[i]
		fixtureEqual(t, "import ownership label", observed.Labels[controller.ImportedByLabel], importObject.Name)
		for _, broker := range observed.Spec.IdentityProviders {
			if broker.ClientSecretRef != nil || broker.Config["clientSecret"] != "" {
				t.Fatal("import included broker credentials")
			}
		}
		observed.Finalizers = []string{controller.RealmFinalizerName}
		f.requireNoError(k8s.Update(ctx, observed))
		fixtureReconcile(f, ctx, observeRealm, observed)
		fixtureReconcile(f, ctx, observeRealm, observed)
		fixtureGet(f, ctx, k8s, observed)
		if len(observed.Finalizers) != 0 {
			t.Fatal("observed realm retained legacy destructive ownership")
		}
	}
	var importedApps hanko.HankoApplicationList
	f.requireNoError(k8s.List(ctx, &importedApps, client.InNamespace("inventory")))
	for i := range importedApps.Items {
		observed := &importedApps.Items[i]
		fixtureEqual(t, "application observe mode", observed.Spec.Mode, "Observe")
		fixtureReconcile(f, ctx, observeApp, observed)
		fixtureGet(f, ctx, k8s, observed)
		if observed.Status.ClientSecret != nil || len(observed.Finalizers) != 0 {
			t.Fatal("observed application acquired credential/destructive ownership")
		}
		// Applications can retain an old Manage finalizer until deletion. The
		// Observe deletion path must release it without touching the provider.
		observed.Finalizers = []string{controller.FinalizerName}
		f.requireNoError(k8s.Update(ctx, observed))
		f.requireNoError(k8s.Delete(ctx, observed))
		fixtureReconcile(f, ctx, observeApp, observed)
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(observed), &hanko.HankoApplication{}); !apierrors.IsNotFound(err) {
			t.Fatal("observed application deletion retained a legacy finalizer")
		}
	}
	var importedAccounts hanko.HankoServiceAccountList
	f.requireNoError(k8s.List(ctx, &importedAccounts, client.InNamespace("inventory")))
	for i := range importedAccounts.Items {
		observed := &importedAccounts.Items[i]
		observed.Finalizers = []string{controller.SAFinalizerName}
		f.requireNoError(k8s.Update(ctx, observed))
		fixtureReconcile(f, ctx, observeAccount, observed)
		fixtureReconcile(f, ctx, observeAccount, observed)
		fixtureGet(f, ctx, k8s, observed)
		if observed.Status.SecretRef != nil || observed.Status.LastRotated != nil || len(observed.Finalizers) != 0 {
			t.Fatal("observed service account acquired credentials/destructive ownership")
		}
	}
	var importedSecrets corev1.SecretList
	f.requireNoError(k8s.List(ctx, &importedSecrets, client.InNamespace("inventory")))
	fixtureEqual(t, "no imported credential Secrets", len(importedSecrets.Items), 0)
	fixtureEqual(t, "observe preserved realm", getRealm(), beforeObserveRealm)
	fixtureEqual(t, "observe preserved application", f.client("managed", "app-spa"), beforeObserveSPA)
	fixtureEqual(t, "observe preserved service account", f.client("managed", "worker"), beforeObserveWorker)
	again, err = f.kc.GetClientSecret(ctx, "managed", "worker")
	f.requireNoError(err)
	fixtureEqual(t, "observe did not rotate credentials", again, rotated)
	var afterEvents []map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/admin-events", nil, &afterEvents)
	fixtureEqual(t, "observe produced no Admin API write events", afterEvents, beforeEvents)

	t.Log("managed IDP removal only deletes its owned alias/mapper")
	fixtureGet(f, ctx, k8s, realm)
	realm.Spec.IdentityProviders = nil
	realm.Spec.DisplayName = "Updated realm"
	f.requireNoError(k8s.Update(ctx, realm))
	fixtureReconcile(f, ctx, rr, realm)
	fixtureEqual(t, "updated realm display name", getRealm()["displayName"], "Updated realm")
	fixtureEqual(t, "removed managed IDP", f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances/managed-oidc", nil, nil), http.StatusNotFound)
	fixtureEqual(t, "preserved unmanaged IDP", f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances/unowned-idp", nil, nil), http.StatusOK)

	t.Log("child finalizers, realm deletion guard and owned realm cleanup")
	// Explicit realm deletion must wait until managed applications and SAs are
	// deleted; unmanaged contents belong to the explicitly owned realm boundary.
	f.requireNoError(k8s.Delete(ctx, realm))
	_, err = rr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(realm)})
	if err == nil || !strings.Contains(err.Error(), "managed resource(s) still present") {
		t.Fatal("realm deletion did not fail closed while managed children remained")
	}
	if _, err := f.kc.GetRealm(ctx, "managed"); err != nil {
		f.requireNoError(err)
	}
	for _, app := range applications {
		fixtureGet(f, ctx, k8s, app)
		f.requireNoError(k8s.Delete(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		if exists, err := f.kc.ClientExists(ctx, "managed", app.Spec.ClientID); err != nil || exists {
			t.Fatal("application finalizer left provider client")
		}
	}
	fixtureGet(f, ctx, k8s, sa)
	f.requireNoError(k8s.Delete(ctx, sa))
	fixtureReconcile(f, ctx, sr, sa)
	if exists, err := f.kc.ClientExists(ctx, "managed", "worker"); err != nil || exists {
		t.Fatal("SA finalizer left provider client")
	}
	fixtureGet(f, ctx, k8s, role)
	f.requireNoError(k8s.Delete(ctx, role))
	fixtureReconcile(f, ctx, ror, role)
	if _, err := f.kc.GetRealmRole(ctx, "managed", "editor"); !keycloak.IsNotFound(err) {
		t.Fatal("role finalizer left owned role")
	}
	fixtureEqual(t, "child deletion preserved unowned client", f.client("managed", "unowned"), unowned)
	fixtureEqual(t, "child deletion preserved unowned role", f.admin(http.MethodGet, "/admin/realms/managed/roles/unowned-role", nil, nil), http.StatusOK)
	fixtureEqual(t, "child deletion preserved unowned IDP", f.admin(http.MethodGet, "/admin/realms/managed/identity-provider/instances/unowned-idp", nil, nil), http.StatusOK)
	fixtureReconcile(f, ctx, rr, realm)
	if _, err := f.kc.GetRealm(ctx, "managed"); !keycloak.IsNotFound(err) {
		t.Fatal("owned realm finalizer left realm")
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(realm), &hanko.HankoRealm{}); !apierrors.IsNotFound(err) {
		t.Fatal("realm finalizer did not finish deletion")
	}
	var proxies []map[string]any
	f.admin(http.MethodGet, "/admin/realms/master/clients?clientId=managed-realm", nil, &proxies)
	fixtureEqual(t, "owned management proxy deletion", len(proxies), 0)
	var masterAfter, unrelatedAfter map[string]any
	f.admin(http.MethodGet, "/admin/realms/master", nil, &masterAfter)
	f.admin(http.MethodGet, "/admin/realms/unrelated", nil, &unrelatedAfter)
	fixtureEqual(t, "protected master configuration preserved", masterAfter, masterBefore)
	fixtureEqual(t, "unrelated realm preserved", unrelatedAfter, unrelatedBefore)
	fixtureEqual(t, "operator credential client preserved by cleanup", f.client("master", "fixture-operator"), operatorBefore)
	fixtureEqual(t, "unprivileged client preserved by cleanup", f.client("master", "fixture-no-admin"), unprivilegedBefore)
}
