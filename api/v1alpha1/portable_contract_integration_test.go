//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
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
}
