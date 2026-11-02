package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestServiceAccountScopeIntentRoundTrip(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {"basic", "registry:oci:artifacts:read"}} {
		original := HankoServiceAccount{Spec: HankoServiceAccountSpec{RealmRef: "example", ClientID: "reader", Scopes: scopes}}
		unstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&original)
		if err != nil {
			t.Fatal(err)
		}
		var restored HankoServiceAccount
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured, &restored); err != nil || !reflect.DeepEqual(original.Spec, restored.Spec) {
			t.Fatal("unstructured conversion lost scope intent", err)
		}
		for range 2 {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var restored HankoServiceAccount
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(original.Spec, restored.Spec) {
				t.Fatalf("typed update lost scope intent: %s", raw)
			}
			original = restored
		}
	}
}
