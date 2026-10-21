package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func newIAMProfileClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&hankoshv1alpha1.HankoIAMProfile{}, &hankoshv1alpha1.HankoRealm{}).
		WithObjects(objects...).Build()
}

func TestIAMProfileReconcilePublishesStablePolicyHash(t *testing.T) {
	profile := &hankoshv1alpha1.HankoIAMProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "enterprise", Namespace: "auth", Generation: 3},
		Spec: hankoshv1alpha1.HankoIAMProfileSpec{Security: hankoshv1alpha1.RealmSecurityProfile{
			MFAPolicy: "required", SessionLifetime: "8h", SessionIdleTimeout: "30m",
		}},
	}
	k8sClient := newIAMProfileClient(t, profile)
	reconciler := &HankoIAMProfileReconciler{Client: k8sClient}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(profile)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	var actual hankoshv1alpha1.HankoIAMProfile
	if err := k8sClient.Get(context.Background(), request.NamespacedName, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.ObservedGeneration != 3 || actual.Status.LastValidated == nil {
		t.Fatalf("status = %+v", actual.Status)
	}
	wantHash := hashIAMSecurityProfile(&profile.Spec.Security)
	if actual.Status.PolicyHash != wantHash || wantHash == "" {
		t.Fatalf("policy hash = %q, want %q", actual.Status.PolicyHash, wantHash)
	}
}

func TestIAMProfileRejectsInvalidSessionPolicy(t *testing.T) {
	profile := &hankoshv1alpha1.HankoIAMProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "auth", Generation: 1},
		Spec: hankoshv1alpha1.HankoIAMProfileSpec{Security: hankoshv1alpha1.RealmSecurityProfile{
			SessionLifetime: "30m", SessionIdleTimeout: "2h",
		}},
	}
	k8sClient := newIAMProfileClient(t, profile)
	reconciler := &HankoIAMProfileReconciler{Client: k8sClient}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(profile)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	var actual hankoshv1alpha1.HankoIAMProfile
	if err := k8sClient.Get(context.Background(), request.NamespacedName, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Error" || actual.Status.PolicyHash != "" {
		t.Fatalf("status = %+v", actual.Status)
	}
	condition := findCondition(actual.Status.Conditions, "Valid")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "InvalidPolicy" {
		t.Fatalf("valid condition = %+v", condition)
	}
}

func TestRealmResolvesReusableIAMProfile(t *testing.T) {
	profile := &hankoshv1alpha1.HankoIAMProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "enterprise", Namespace: "auth"},
		Spec: hankoshv1alpha1.HankoIAMProfileSpec{Security: hankoshv1alpha1.RealmSecurityProfile{
			MFAPolicy: "required", SessionLifetime: "8h",
		}},
	}
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: profile.Name},
	}
	effective, err := resolveRealmIAMProfile(context.Background(), newIAMProfileClient(t, profile, realm), realm)
	if err != nil {
		t.Fatal(err)
	}
	if effective.Name != profile.Name || effective.Hash == "" || effective.Security == nil || effective.Security.MFAPolicy != "required" {
		t.Fatalf("effective profile = %+v", effective)
	}
	if got := realmSpecWithSecurity(realm, effective.Security); got.MFAPolicy != "required" || got.SSOSessionMaxLifespan != 8*60*60 {
		t.Fatalf("realm spec = %+v", got)
	}
}

func TestRealmIAMProfileResolutionFailsClosed(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"},
		Spec:       hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: "missing"},
	}
	if _, err := resolveRealmIAMProfile(context.Background(), newIAMProfileClient(t, realm), realm); err == nil {
		t.Fatal("missing profile must fail resolution")
	}
	realm.Spec.SecurityProfile = &hankoshv1alpha1.RealmSecurityProfile{MFAPolicy: "optional"}
	if _, err := resolveRealmIAMProfile(context.Background(), newIAMProfileClient(t, realm), realm); err == nil {
		t.Fatal("profile reference and inline policy must be rejected")
	}
}

func TestRealmProfileChangeEnqueuesEveryConsumer(t *testing.T) {
	profile := &hankoshv1alpha1.HankoIAMProfile{ObjectMeta: metav1.ObjectMeta{Name: "enterprise", Namespace: "auth"}}
	realms := []client.Object{
		&hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"}, Spec: hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: profile.Name}},
		&hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "auth"}, Spec: hankoshv1alpha1.HankoRealmSpec{IAMProfileRef: "other"}},
	}
	reconciler := &HankoRealmReconciler{Client: newIAMProfileClient(t, realms...)}
	requests := reconciler.realmRequestsForIAMProfile(context.Background(), profile)
	if len(requests) != 1 || requests[0].NamespacedName != (types.NamespacedName{Name: "acme", Namespace: "auth"}) {
		t.Fatalf("requests = %+v", requests)
	}
}

func TestMFAPolicyStrengtheningRequiresSessionRevocation(t *testing.T) {
	for _, test := range []struct {
		previous string
		desired  string
		want     bool
	}{
		{previous: "", desired: "required", want: false},
		{previous: "none", desired: "optional", want: true},
		{previous: "optional", desired: "required", want: true},
		{previous: "required", desired: "optional", want: false},
		{previous: "required", desired: "required", want: false},
	} {
		if got := mfaPolicyStrengthened(test.previous, test.desired); got != test.want {
			t.Errorf("mfaPolicyStrengthened(%q, %q) = %v, want %v", test.previous, test.desired, got, test.want)
		}
	}
}

func TestNamedIAMProfileSecurityAppliesToIdentityProvider(t *testing.T) {
	requireSignature := true
	trustEmail := false
	reconciler := &HankoRealmReconciler{}
	realm := &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "auth"}}
	security := &hankoshv1alpha1.RealmSecurityProfile{
		IDPBrokerRequireSignature: &requireSignature,
		IDPBrokerTrustEmail:       &trustEmail,
	}

	provider, err := reconciler.identityProviderForRealmWithSecurity(context.Background(), realm, security, hankoshv1alpha1.RealmIdentityProvider{
		Alias: "entra", ProviderID: "oidc", TrustEmail: boolPointer(true), Config: map[string]string{"validateSignature": "false"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.TrustEmail {
		t.Fatal("named IAM profile did not override broker trustEmail")
	}
	if provider.Config["validateSignature"] != "true" {
		t.Fatalf("validateSignature=%q", provider.Config["validateSignature"])
	}
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}
