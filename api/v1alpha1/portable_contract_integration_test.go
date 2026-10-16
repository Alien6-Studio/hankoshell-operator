//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkPortableCorpusAdmission(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	corpus, err := iamconformance.ReadPortableCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Fixtures {
		t.Run("portable-admission-"+fixture.Name, func(t *testing.T) {
			data, _ := json.Marshal(fixture.Manifest)
			obj := &unstructured.Unstructured{}
			if json.Unmarshal(data, &obj.Object) != nil {
				t.Fatal("invalid fixture document")
			}
			obj.SetName("portable-fixture-" + fixture.Name)
			obj.SetNamespace("auth")
			if err := kube.Create(ctx, obj, client.DryRunAll, client.FieldValidation("Strict")); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("partial-provider-capability-status", func(t *testing.T) {
		app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "portable-partial-capabilities", Namespace: "auth"}, Spec: api.HankoApplicationSpec{RealmRef: "portable", ClientID: "partial-capabilities", Type: "spa", RedirectURIs: []string{"https://app.example/callback"}}}
		if err := kube.Create(ctx, app); err != nil {
			t.Fatal(err)
		}
		app.Status.Phase = "Ready"
		app.Status.Capabilities = api.ApplicationCapabilitySnapshot{OIDC: true, PublicClient: true, ConfidentialClient: true}
		if err := kube.Status().Update(ctx, app); err != nil {
			t.Fatal("partial capability snapshot must retain required false values", err)
		}
		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(api.GroupVersion.WithKind("HankoApplication"))
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), stored); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"saml", "samlACS", "samlAssertionSigning", "samlResponseSigning", "samlMetadata", "clientRoles", "protocolMappers"} {
			value, found, err := unstructured.NestedBool(stored.Object, "status", "capabilities", key)
			if err != nil || !found || value {
				t.Fatal("unsupported capability was omitted or promoted", key)
			}
		}
		stale := app.DeepCopy()
		app.Spec.RedirectURIs = []string{"https://app.example/changed"}
		if err := kube.Update(ctx, app); err != nil {
			t.Fatal(err)
		}
		if err := kube.Status().Update(ctx, stale); !apierrors.IsConflict(err) {
			t.Fatal("stale complete status overwrote a new source generation", err)
		}
	})
}
