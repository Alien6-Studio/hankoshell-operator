package controller

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func realmCondition(realm *hankoshv1alpha1.HankoRealm, conditionType string) *metav1.Condition {
	for i := range realm.Status.Conditions {
		if realm.Status.Conditions[i].Type == conditionType {
			return &realm.Status.Conditions[i]
		}
	}
	return nil
}

func TestRealmWaitsForManagedTheme(t *testing.T) {
	theme := testTheme()
	theme.Status.Phase = "Building"
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{LoginTheme: theme.Name},
	}
	r := &HankoRealmReconciler{Client: newThemeClient(t, theme)}

	ready, _, err := r.reconcileThemeReadiness(context.Background(), realm)
	if err != nil {
		t.Fatalf("reconcileThemeReadiness: %v", err)
	}
	condition := realmCondition(realm, "ThemeReady")
	if ready || realm.Status.Phase != "Reconciling" || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "ThemeBuilding" {
		t.Fatalf("readiness: ready=%v phase=%q condition=%+v", ready, realm.Status.Phase, condition)
	}
}

func TestRealmAcceptsCurrentManagedTheme(t *testing.T) {
	theme := testTheme()
	theme.Status.Phase = "Ready"
	theme.Status.JarPath = "/opt/keycloak/providers/hanko-theme.jar"
	theme.Status.ObservedGeneration = theme.Generation
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{LoginTheme: theme.Name},
	}
	r := &HankoRealmReconciler{Client: newThemeClient(t, theme)}

	ready, _, err := r.reconcileThemeReadiness(context.Background(), realm)
	if err != nil {
		t.Fatalf("reconcileThemeReadiness: %v", err)
	}
	condition := realmCondition(realm, "ThemeReady")
	if !ready || condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "ManagedThemeReady" {
		t.Fatalf("readiness: ready=%v condition=%+v", ready, condition)
	}
}

func TestRealmAllowsExternalThemeDuringMigration(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{LoginTheme: "preinstalled"},
	}
	r := &HankoRealmReconciler{Client: newThemeClient(t)}

	ready, _, err := r.reconcileThemeReadiness(context.Background(), realm)
	if err != nil {
		t.Fatalf("reconcileThemeReadiness: %v", err)
	}
	condition := realmCondition(realm, "ThemeReady")
	if !ready || condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "ExternalTheme" {
		t.Fatalf("readiness: ready=%v condition=%+v", ready, condition)
	}
}

func TestRealmSpecMapsFrontendURL(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{
			FrontendURL: "https://auth.hanko.sh",
		},
	}

	got := realmSpec(realm)
	if got.FrontendURL != realm.Spec.FrontendURL {
		t.Fatalf("FrontendURL = %q, want %q", got.FrontendURL, realm.Spec.FrontendURL)
	}
}

func TestRealmSpecMapsExpandedSecurityProfile(t *testing.T) {
	enabled := true
	disabled := false
	passwordHistory := 5
	auditRetentionDays := 365
	clientSecretRotationDays := 30
	bruteForce := &hankoshv1alpha1.BruteForcePolicy{Enabled: true, MaxFailures: 7, WaitIncrements: "30m"}
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
			MFAPolicy:                 "required",
			PasswordMinLength:         14,
			PasswordExpiryDays:        60,
			PasswordHistory:           &passwordHistory,
			PasswordRequireUppercase:  &enabled,
			PasswordRequireLowercase:  &enabled,
			PasswordRequireDigit:      &enabled,
			PasswordRequireSpecial:    &enabled,
			PasswordDisallowUsername:  &enabled,
			PasswordDisallowEmail:     &enabled,
			BruteForce:                bruteForce,
			SessionLifetime:           "8h",
			SessionIdleTimeout:        "15m",
			OTPDigits:                 8,
			OTPPeriodSeconds:          45,
			EmailVerificationRequired: &enabled,
			RememberMeEnabled:         &disabled,
			UserRegistrationEnabled:   &disabled,
			UserEventsEnabled:         &enabled,
			AdminEventsEnabled:        &enabled,
			AuditRetentionDays:        &auditRetentionDays,
			AuditExportEnabled:        &enabled,
			ClientSecretRotationDays:  &clientSecretRotationDays,
			AdminConsoleExposure:      "restricted",
			IDPBrokerRequireSignature: &enabled,
			IDPBrokerTrustEmail:       &disabled,
		}},
	}

	got := realmSpec(realm)
	for _, policy := range []string{"length(14)", "upperCase(1)", "lowerCase(1)", "digits(1)", "specialChars(1)", "notUsername(undefined)", "notEmail(undefined)", "passwordHistory(5)", "forceExpiredPasswordChange(60)"} {
		if !strings.Contains(got.PasswordPolicy, policy) {
			t.Fatalf("PasswordPolicy %q missing %q", got.PasswordPolicy, policy)
		}
	}
	if got.SSOSessionMaxLifespan != 8*60*60 || got.SSOSessionIdleTimeout != 15*60 || got.OTPDigits != 8 || got.OTPPeriod != 45 {
		t.Fatalf("mapped security timings = %+v", got)
	}
	if got.MFAPolicy != "required" || !got.BruteForceProtected || got.FailureFactor != 7 || got.WaitIncrementSeconds != 30*60 {
		t.Fatalf("mapped MFA and brute-force profile = %+v", got)
	}
	if got.VerifyEmail == nil || !*got.VerifyEmail || got.RememberMe == nil || *got.RememberMe || got.EventsEnabled == nil || !*got.EventsEnabled {
		t.Fatalf("mapped security booleans = %+v", got)
	}
	if got.AuditRetentionDays == nil || *got.AuditRetentionDays != 365 || got.AuditExportEnabled == nil || !*got.AuditExportEnabled || got.AdminConsoleExposure != "restricted" || got.IDPBrokerRequireSignature == nil || !*got.IDPBrokerRequireSignature || got.IDPBrokerTrustEmail == nil || *got.IDPBrokerTrustEmail {
		t.Fatalf("mapped operational security controls = %+v", got)
	}
}

func TestRealmSpecPreservesLegacyPasswordDefaults(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy"},
		Spec: hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
			PasswordMinLength: 10,
		}},
	}
	policy := realmSpec(realm).PasswordPolicy
	for _, expected := range []string{"upperCase(1)", "lowerCase(1)", "digits(1)", "passwordHistory(3)"} {
		if !strings.Contains(policy, expected) {
			t.Fatalf("legacy PasswordPolicy %q missing %q", policy, expected)
		}
	}
}

func TestRealmSecretRotationDefaultAndChildOverride(t *testing.T) {
	days := 30
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoRealmSpec{SecurityProfile: &hankoshv1alpha1.RealmSecurityProfile{
			ClientSecretRotationDays: &days,
		}},
	}
	reader := newThemeClient(t, realm)
	policy, err := effectiveSecretRotationPolicy(context.Background(), reader, "default", "regulated", nil)
	if err != nil || policy == nil || !policy.Enabled || policy.IntervalDays != 30 {
		t.Fatalf("realm rotation policy = %+v, err=%v", policy, err)
	}
	explicit := &hankoshv1alpha1.SecretRotationPolicy{Enabled: true, IntervalDays: 60}
	policy, err = effectiveSecretRotationPolicy(context.Background(), reader, "default", "regulated", explicit)
	if err != nil || policy != explicit {
		t.Fatalf("explicit rotation policy = %+v, err=%v", policy, err)
	}
}

func TestRealmSecretRotationFallsBackToIAMProfile(t *testing.T) {
	days := 45
	profile := &hankoshv1alpha1.HankoIAMProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "enterprise", Namespace: "default"},
		Spec: hankoshv1alpha1.HankoIAMProfileSpec{Security: hankoshv1alpha1.RealmSecurityProfile{
			ClientSecretRotationDays: &days,
		}},
	}
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: profile.Name},
	}
	reader := newThemeClient(t, profile, realm)
	policy, err := effectiveSecretRotationPolicy(context.Background(), reader, "default", realm.Name, nil)
	if err != nil || policy == nil || !policy.Enabled || policy.IntervalDays != days {
		t.Fatalf("IAM profile rotation policy = %+v, err=%v", policy, err)
	}

	missing, err := effectiveSecretRotationPolicy(context.Background(), reader, "default", "missing", nil)
	if err != nil || missing != nil {
		t.Fatalf("missing realm policy = %+v, err=%v", missing, err)
	}

	legacy := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "default"}}
	legacyPolicy, err := effectiveSecretRotationPolicy(context.Background(), newThemeClient(t, legacy), "default", legacy.Name, nil)
	if err != nil || legacyPolicy != nil {
		t.Fatalf("legacy realm policy = %+v, err=%v", legacyPolicy, err)
	}
}

func TestRealmSecretRotationSurfacesIAMProfileResolutionFailure(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated", Namespace: "default"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: "missing"},
	}
	reader := newThemeClient(t, realm)
	if _, err := effectiveSecretRotationPolicy(context.Background(), reader, "default", realm.Name, nil); err == nil {
		t.Fatal("missing IAM profile was ignored")
	}
}
