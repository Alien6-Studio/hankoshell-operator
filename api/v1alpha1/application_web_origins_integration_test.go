//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkApplicationWebOrigins(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	for n, origins := range [][]string{{}, {"https://portal.test", "http://localhost:3000"}, {"+"}, {"https://portal.test/callback", "https://portal.test/login/*"}} {
		app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("explicit-origins-%d", n), Namespace: "auth"}, Spec: api.HankoApplicationSpec{RealmRef: "example", ClientID: "origins", Type: "spa", WebOrigins: &origins}}
		if err := kube.Create(ctx, app); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), app); err != nil {
			t.Fatal(err)
		}
		if app.Spec.WebOrigins == nil || !slices.Equal(*app.Spec.WebOrigins, origins) {
			t.Fatal("Kubernetes defaulting or pruning changed an explicit CORS set")
		}
	}
	tooMany := make([]any, 65)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("https://portal-%d.test", i)
	}
	for n, origins := range [][]any{{"*"}, {"https://*.portal.test"}, {"https://portal.test?token=private"}, {"https://user:password@portal.test"}, {"https://portal.test", "https://portal.test"}, tooMany} {
		bad := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": map[string]any{"name": fmt.Sprintf("invalid-origins-%d", n), "namespace": "auth"}, "spec": map[string]any{"realmRef": "example", "clientID": "origins", "type": "spa", "webOrigins": origins}}}
		if err := kube.Create(ctx, bad); !apierrors.IsInvalid(err) {
			t.Fatalf("unqualified CORS policy %d was admitted: %v", n, err)
		}
	}
}
