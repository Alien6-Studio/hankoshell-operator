package applicationbinding

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type fixture struct {
	app      *api.HankoApplication
	proof    Proof
	kube     client.WithWatch
	delivery *Delivery
}

func runtimeFixture(t *testing.T, credentials bool) fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}}
	if credentials {
		b.Credentials = &api.ApplicationRuntimeCredentialTarget{SecretRef: "identity"}
	}
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "auth", UID: "app-uid", Generation: 3}, Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "worker", Type: "m2m", RuntimeBindings: []api.ApplicationRuntimeBinding{b}}}
	hash := string(iamcontract.Hash(iamcontract.Version, "fixture", "plan", []byte("public contract")))
	proof := Proof{ApplicationUID: string(app.UID), Generation: 3, ContractVersion: string(iamcontract.Version), IntentHash: hash, AppliedPlanHash: hash, Protocol: "oidc", Pattern: "m2m", ClientID: "worker", OIDC: &api.OIDCEndpoints{Issuer: "https://idp.test/realms/realm", Authorization: "https://idp.test/realms/realm/protocol/openid-connect/auth", Token: "https://idp.test/realms/realm/protocol/openid-connect/token", JWKS: "https://idp.test/realms/realm/protocol/openid-connect/certs"}}
	app.Status = api.HankoApplicationStatus{EvaluatedGeneration: 3, AppliedGeneration: 3, ObservationGeneration: 3, ContractVersion: proof.ContractVersion, IntentHash: hash, EvaluatedPlanHash: hash, AppliedPlanHash: hash, ObservationPlanHash: hash, ObservationComplete: true, DriftState: "InSync"}
	annotations := Authorization(app, b, "sa-uid")
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "identity", UID: "cm-uid", Labels: map[string]string{TargetLabel: "metadata"}, Annotations: annotations}, Data: map[string]string{"unrelated": "preserved"}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "worker", UID: "sa-uid"}}
	yes := true
	source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "hanko-app-worker", UID: "source-uid", ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{{APIVersion: "hanko.sh/v1alpha1", Kind: "HankoApplication", Name: app.Name, UID: app.UID, Controller: &yes}}}, Data: map[string][]byte{CredentialKey: []byte("fixture-credential-first")}}
	target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "identity", UID: "target-uid", Labels: map[string]string{TargetLabel: "credentials"}, Annotations: Authorization(app, b, "sa-uid")}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"unrelated": []byte("preserved")}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.HankoApplication{}).WithObjects(app, cm, sa, source, target).Build()
	return fixture{app, proof, kube, &Delivery{Client: kube, Reader: kube, Verify: func(context.Context) error { return nil }}}
}
func read[T client.Object](t *testing.T, c client.Reader, key client.ObjectKey, target T) T {
	t.Helper()
	if err := c.Get(context.Background(), key, target); err != nil {
		t.Fatal(err)
	}
	return target
}
func requireDelivery(t *testing.T, f fixture) []api.ApplicationRuntimeBindingStatus {
	t.Helper()
	statuses, err := f.delivery.Deliver(context.Background(), f.app, f.proof)
	if err != nil || len(statuses) != 1 || !meta.IsStatusConditionTrue(statuses[0].Conditions, "Ready") {
		t.Fatalf("delivery not ready: %v, %+v", err, statuses)
	}
	return statuses
}

func TestRuntimeSchemaDeterminismAndCredentialMetadataRevision(t *testing.T) {
	f := runtimeFixture(t, true)
	b := f.app.Spec.RuntimeBindings[0]
	doc := runtimeDocument(f.app, b, "sa-uid", f.proof)
	first, hash, rev, err := Encode(doc, CredentialVersion{"source", "1"}, "cm", "secret")
	if err != nil {
		t.Fatal(err)
	}
	again, h2, r2, _ := Encode(doc, CredentialVersion{"source", "1"}, "cm", "secret")
	if string(first) != string(again) || hash != h2 || rev != r2 {
		t.Fatal("equivalent inputs are nondeterministic")
	}
	_, _, rotated, _ := Encode(doc, CredentialVersion{"source", "2"}, "cm", "secret")
	if rotated == rev {
		t.Fatal("credential resource version did not change revision")
	}
	doc.ClientID = "new-client"
	_, changed, _, _ := Encode(doc, CredentialVersion{"source", "1"}, "cm", "secret")
	if changed == hash {
		t.Fatal("semantic metadata change hidden")
	}
	if strings.Contains(string(first), "fixture-credential") || strings.Contains(string(first), "source-uid") {
		t.Fatal("private credential source entered public document")
	}
	var actual Document
	if json.Unmarshal(first, &actual) != nil || actual.SchemaVersion != Schema || actual.Credentials.Key != CredentialKey || actual.SAML != nil {
		t.Fatal("invalid versioned OIDC schema")
	}
	doc.ClientID = strings.Repeat("x", MaxDocumentBytes)
	if _, _, _, err := Encode(doc, CredentialVersion{}, "cm", ""); Reason(err) != "OutputTooLarge" {
		t.Fatal("unbounded runtime document")
	}
}

func TestRuntimeDeliveryDriftRotationAndCleanup(t *testing.T) {
	f := runtimeFixture(t, true)
	ctx := context.Background()
	first := requireDelivery(t, f)[0]
	cm := read(t, f.kube, metadataKey(f.app.Spec.RuntimeBindings[0]), &corev1.ConfigMap{})
	secret := read(t, f.kube, credentialKey(f.app.Spec.RuntimeBindings[0]), &corev1.Secret{})
	if cm.Data["unrelated"] != "preserved" || string(secret.Data["unrelated"]) != "preserved" || secret.Annotations[RevisionAnnotation] != first.BindingRevision {
		t.Fatal("unrelated fields lost or revisions inconsistent")
	}
	cm.Data[MetadataKey] = "drift"
	_ = f.kube.Update(ctx, cm)
	secret.Data[CredentialKey] = []byte("drift")
	_ = f.kube.Update(ctx, secret)
	if requireDelivery(t, f)[0].BindingRevision != first.BindingRevision {
		t.Fatal("output drift changed intended revision")
	}
	source := read(t, f.kube, sourceKey(f.app), &corev1.Secret{})
	source.Data[CredentialKey] = []byte("fixture-credential-second")
	_ = f.kube.Update(ctx, source)
	second := requireDelivery(t, f)[0]
	if first.BindingRevision == second.BindingRevision {
		t.Fatal("rotation did not change revision")
	}
	secret = read(t, f.kube, credentialKey(f.app.Spec.RuntimeBindings[0]), &corev1.Secret{})
	if string(secret.Data[CredentialKey]) != "fixture-credential-second" {
		t.Fatal("rotation not delivered")
	}
	current := read(t, f.kube, client.ObjectKeyFromObject(f.app), &api.HankoApplication{})
	current.Spec.RuntimeBindings = nil
	_ = f.kube.Update(ctx, current)
	if _, err := f.delivery.Deliver(ctx, current, f.proof); err != nil {
		t.Fatal(err)
	}
	cm = read(t, f.kube, client.ObjectKey{Namespace: "payments", Name: "identity"}, &corev1.ConfigMap{})
	secret = read(t, f.kube, client.ObjectKeyFromObject(secret), &corev1.Secret{})
	if _, exists := cm.Data[MetadataKey]; exists {
		t.Fatal("metadata key survived cleanup")
	}
	if _, exists := secret.Data[CredentialKey]; exists {
		t.Fatal("credential survived cleanup")
	}
	if cm.Data["unrelated"] != "preserved" || string(secret.Data["unrelated"]) != "preserved" || cm.Annotations[RevisionAnnotation] != "" || cm.Annotations[ApplicationUID] != string(f.app.UID) {
		t.Fatal("cleanup removed owner data/authorization or retained managed annotations")
	}
}

func TestRuntimeAuthorizationAndFreshSourceFailClosed(t *testing.T) {
	for _, attack := range []string{"empty-app-uid", "foreign-app", "workload-uid", "service-account-replaced", "target-replaced", "secret-type", "status-forged", "stale-source", "provider-unproven", "missing-verifier", "source-unowned", "wrong-target-kind"} {
		t.Run(attack, func(t *testing.T) {
			f := runtimeFixture(t, true)
			ctx := context.Background()
			b := f.app.Spec.RuntimeBindings[0]
			cm := read(t, f.kube, metadataKey(b), &corev1.ConfigMap{})
			switch attack {
			case "empty-app-uid":
				cm.Annotations[ApplicationUID] = ""
			case "foreign-app":
				cm.Annotations[ApplicationUID] = "foreign"
			case "workload-uid":
				cm.Annotations[ServiceAccountUID] = ""
			case "wrong-target-kind":
				cm.Labels[TargetLabel] = "credentials"
			case "service-account-replaced":
				sa := read(t, f.kube, client.ObjectKey{Namespace: "payments", Name: "worker"}, &corev1.ServiceAccount{})
				_ = f.kube.Delete(ctx, sa)
				sa.ResourceVersion = ""
				sa.UID = "replacement-sa"
				_ = f.kube.Create(ctx, sa)
			case "target-replaced":
				_ = f.kube.Delete(ctx, cm)
				cm.ResourceVersion = ""
				cm.UID = "replacement-cm"
				cm.Annotations = nil
				_ = f.kube.Create(ctx, cm)
			case "secret-type":
				s := read(t, f.kube, credentialKey(b), &corev1.Secret{})
				s.Type = corev1.SecretTypeTLS
				_ = f.kube.Update(ctx, s)
			case "status-forged":
				app := read(t, f.kube, client.ObjectKeyFromObject(f.app), &api.HankoApplication{})
				app.Status.RuntimeBindings = []api.ApplicationRuntimeBindingStatus{{Name: b.Name, ServiceAccountUID: "sa-uid", BindingRevision: f.proof.AppliedPlanHash}}
				_ = f.kube.Status().Update(ctx, app)
				cm.Annotations[ApplicationUID] = "foreign"
			case "stale-source":
				app := read(t, f.kube, client.ObjectKeyFromObject(f.app), &api.HankoApplication{})
				app.Generation++
				_ = f.kube.Update(ctx, app)
			case "provider-unproven":
				f.delivery.Verify = func(context.Context) error { return errors.New("provider unavailable") }
			case "missing-verifier":
				f.delivery.Verify = nil
			case "source-unowned":
				s := read(t, f.kube, sourceKey(f.app), &corev1.Secret{})
				s.OwnerReferences = nil
				_ = f.kube.Update(ctx, s)
			}
			if attack != "target-replaced" {
				_ = f.kube.Update(ctx, cm)
			}
			if _, err := f.delivery.Deliver(ctx, f.app, f.proof); err == nil {
				t.Fatal("unauthorized delivery accepted")
			}
			cm = read(t, f.kube, metadataKey(b), &corev1.ConfigMap{})
			s := read(t, f.kube, credentialKey(b), &corev1.Secret{})
			if cm.Data[MetadataKey] != "" || len(s.Data[CredentialKey]) != 0 {
				t.Fatal("prevalidation failure mutated outputs")
			}
		})
	}
}

func TestPartialWriteLostAcknowledgementAndStatusLossRetry(t *testing.T) {
	for _, lostAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-secret", true: "lost-secret-ack"}[lostAck], func(t *testing.T) {
			f := runtimeFixture(t, true)
			ctx := context.Background()
			fail := true
			writes := 0
			f.delivery.Client = interceptor.NewClient(f.kube, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					writes++
					if fail {
						if lostAck {
							if err := c.Patch(ctx, obj, patch, opts...); err != nil {
								return err
							}
						}
						return errors.New("fixture lost acknowledgement")
					}
				}
				return c.Patch(ctx, obj, patch, opts...)
			}})
			status, err := f.delivery.Deliver(ctx, f.app, f.proof)
			if err == nil || meta.IsStatusConditionTrue(status[0].Conditions, "Ready") {
				t.Fatal("partial delivery certified Ready")
			}
			cm := read(t, f.kube, metadataKey(f.app.Spec.RuntimeBindings[0]), &corev1.ConfigMap{})
			firstRevision := cm.Annotations[RevisionAnnotation]
			if firstRevision == "" {
				t.Fatal("partial metadata write missing")
			}
			fail = false
			statuses := requireDelivery(t, f)
			if statuses[0].BindingRevision != firstRevision {
				t.Fatal("retry changed intended revision")
			}
			// Drop the returned status entirely, as if its patch failed. The journal
			// and actual target state recover readiness with zero output writes.
			before := writes
			again := requireDelivery(t, f)
			if writes != before || again[0].BindingRevision != statuses[0].BindingRevision || again[0].MetadataHash != statuses[0].MetadataHash {
				t.Fatal("status-loss retry rewrote outputs or changed proof")
			}
			if lostAck && writes != 1 {
				t.Fatal("lost acknowledgement caused duplicate Secret write")
			}
		})
	}
}

func TestRuntimeCleanupRevocationAndSAReauthorization(t *testing.T) {
	f := runtimeFixture(t, true)
	ctx := context.Background()
	before := requireDelivery(t, f)[0]
	b := f.app.Spec.RuntimeBindings[0]
	sa := read(t, f.kube, client.ObjectKey{Namespace: "payments", Name: "worker"}, &corev1.ServiceAccount{})
	_ = f.kube.Delete(ctx, sa)
	sa.UID = "replacement-sa"
	sa.ResourceVersion = ""
	_ = f.kube.Create(ctx, sa)
	if _, err := f.delivery.Deliver(ctx, f.app, f.proof); Reason(err) != "WorkloadChanged" {
		t.Fatalf("replacement workload accepted: %v", err)
	}
	for _, target := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}} {
		read(t, f.kube, client.ObjectKey{Namespace: "payments", Name: "identity"}, target)
		target.GetAnnotations()[ServiceAccountUID] = string(sa.UID)
		_ = f.kube.Update(ctx, target)
	}
	if requireDelivery(t, f)[0].BindingRevision == before.BindingRevision {
		t.Fatal("explicitly reauthorized UID did not change revision")
	}
	cm := read(t, f.kube, metadataKey(b), &corev1.ConfigMap{})
	delete(cm.Annotations, ApplicationUID)
	_ = f.kube.Update(ctx, cm)
	current := read(t, f.kube, client.ObjectKeyFromObject(f.app), &api.HankoApplication{})
	current.Spec.RuntimeBindings = nil
	_ = f.kube.Update(ctx, current)
	if _, err := f.delivery.Deliver(ctx, current, f.proof); Reason(err) != "CleanupConflict" {
		t.Fatalf("revoked cleanup accepted: %v", err)
	}
	actual := read(t, f.kube, metadataKey(b), &corev1.ConfigMap{})
	if actual.Data[MetadataKey] != cm.Data[MetadataKey] {
		t.Fatal("revoked target cleared")
	}
}

func TestRuntimeProtocolAndDuplicateWriterValidation(t *testing.T) {
	f := runtimeFixture(t, false)
	f.app.Spec.Type = "spa"
	if err := f.kube.Update(context.Background(), f.app); err != nil {
		t.Fatal(err)
	}
	requireDelivery(t, f)
	f.app.Spec.Mode = "Observe"
	if Reason(Validate(f.app)) != "ManageRequired" {
		t.Fatal("Observe delivery accepted")
	}
	f.app.Spec.Mode = ""
	f.app.Spec.RuntimeBindings[0].Credentials = &api.ApplicationRuntimeCredentialTarget{SecretRef: "identity"}
	if Reason(Validate(f.app)) != "InvalidCredentials" {
		t.Fatal("SPA credential accepted")
	}
	f.app.Spec.Type = "m2m"
	f.app.Spec.ClientSecretProjections = []api.ApplicationSecretProjection{{Namespace: "payments", Name: "identity"}}
	if Reason(Validate(f.app)) != "DuplicateWriter" {
		t.Fatal("legacy duplicate writer accepted")
	}
	f.app.Spec.ClientSecretProjections = nil
	f.app.Spec.Protocol = "saml"
	if Reason(Validate(f.app)) != "InvalidCredentials" {
		t.Fatal("SAML credential accepted")
	}
	f.app.Spec.RuntimeBindings[0].Credentials = nil
	doc := runtimeDocument(f.app, f.app.Spec.RuntimeBindings[0], "sa-uid", Proof{Protocol: "saml", ClientID: "https://sp.test", SAML: &api.SAMLEndpoints{Issuer: "https://idp.test", SSO: "https://idp.test/saml", Metadata: "https://idp.test/descriptor"}, NameIDFormat: "persistent"})
	data, _, _, err := Encode(doc, CredentialVersion{}, "cm", "")
	if err != nil || !strings.Contains(string(data), `"saml":`) || strings.Contains(string(data), `"credentials":`) {
		t.Fatal("invalid SAML runtime schema")
	}
}

func TestAllBindingsPrevalidatedAndSchemaBounds(t *testing.T) {
	f := runtimeFixture(t, true)
	second := f.app.Spec.RuntimeBindings[0]
	second.Name = "unavailable"
	second.PublicMetadata.ConfigMapRef = "missing"
	f.app.Spec.RuntimeBindings = append(f.app.Spec.RuntimeBindings, second)
	if err := f.kube.Update(context.Background(), f.app); err != nil {
		t.Fatal(err)
	}
	if _, err := f.delivery.Deliver(context.Background(), f.app, f.proof); err == nil {
		t.Fatal("missing second target accepted")
	}
	cm := read(t, f.kube, client.ObjectKey{Namespace: "payments", Name: "identity"}, &corev1.ConfigMap{})
	if cm.Data[MetadataKey] != "" {
		t.Fatal("first output mutated before validating second binding")
	}
	f.app.Spec.RuntimeBindings = make([]api.ApplicationRuntimeBinding, 33)
	if Reason(Validate(f.app)) != "InvalidBindings" {
		t.Fatal("unbounded bindings accepted")
	}
	f = runtimeFixture(t, false)
	doc := runtimeDocument(f.app, f.app.Spec.RuntimeBindings[0], "sa-uid", f.proof)
	first, hash, rev, err := Encode(doc, CredentialVersion{}, "cm", "")
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Document
	if err := json.Unmarshal(first, &roundtrip); err != nil {
		t.Fatal(err)
	}
	again, h2, r2, _ := Encode(roundtrip, CredentialVersion{}, "cm", "")
	if string(first) != string(again) || hash != h2 || rev != r2 {
		t.Fatal("omitted optional fields/revision roundtrip changed canonical metadata")
	}
	// Fixed schema field order is independent of map or input insertion order.
	if !strings.HasPrefix(string(first), `{"schemaVersion":"hanko.sh/application-runtime/v1alpha1","protocol":"oidc","clientID":`) {
		t.Fatal("canonical field order changed")
	}
}
