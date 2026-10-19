package v1beta1_test

import (
	"encoding/json"
	"reflect"
	"testing"

	alpha "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	beta "github.com/Alien6-Studio/hankoshell-operator/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func conversionScheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := alpha.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := beta.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestVersionsPreserveAllFieldsAndDoNotShareAuthorityState(t *testing.T) {
	scheme := conversionScheme(t)
	for _, kind := range []string{"HankoApplication", "HankoRole", "HankoResourceServer"} {
		t.Run(kind, func(t *testing.T) {
			old, err := scheme.New(alpha.GroupVersion.WithKind(kind))
			if err != nil {
				t.Fatal(err)
			}
			wire := `{"apiVersion":"hanko.sh/v1alpha1","kind":"` + kind + `","metadata":{"name":"current","namespace":"auth","uid":"resource-uid","generation":7,"resourceVersion":"123","annotations":{"hanko.sh/adoption-contract":"hanko.sh/adoption-contract/v1alpha1","hanko.sh/adoption-candidate":"reviewed-approval","hanko.sh/runtime-bindings-journal":"preserve-opaque-recovery"},"finalizers":["hanko.sh/owned"],"ownerReferences":[{"apiVersion":"hanko.sh/v1alpha1","kind":"HankoRealm","name":"realm","uid":"parent-uid"}]},"spec":{"realmRef":"realm","mode":"Observe"},"status":{"phase":"Ready","observedGeneration":7,"appliedGeneration":7,"appliedPlanHash":"opaque-plan","conditions":[{"type":"Synced","status":"True","reason":"Recorded","lastTransitionTime":"2026-01-01T00:00:00Z"}]}}`
			if err := json.Unmarshal([]byte(wire), old); err != nil {
				t.Fatal(err)
			}
			next, _ := scheme.New(beta.GroupVersion.WithKind(kind))
			if err := scheme.Convert(old, next, nil); err != nil {
				t.Fatal(err)
			}
			back, _ := scheme.New(alpha.GroupVersion.WithKind(kind))
			if err := scheme.Convert(next, back, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(old, back) {
				t.Fatal("version conversion changed metadata, spec, status or recovery authority")
			}
			next.(metav1.Object).GetAnnotations()["hanko.sh/adoption-candidate"] = "changed-in-beta"
			next.(metav1.Object).SetUID(types.UID("different"))
			if old.(metav1.Object).GetAnnotations()["hanko.sh/adoption-candidate"] != "reviewed-approval" || old.(metav1.Object).GetUID() != "resource-uid" {
				t.Fatal("converted version shares mutable source authority")
			}
		})
	}
}

func TestApplicationNestedSpecAndStatusAreIndependent(t *testing.T) {
	old := &alpha.HankoApplication{Spec: alpha.HankoApplicationSpec{RealmRoleScopes: []string{"reader"}, Attributes: map[string]string{"locale": "fr"}}, Status: alpha.HankoApplicationStatus{AdoptionReceipt: &alpha.AdoptionReceiptStatus{State: "Verified"}}}
	next := beta.ApplicationFromHub(old)
	next.Spec.RealmRoleScopes[0], next.Spec.Attributes["locale"], next.Status.AdoptionReceipt.State = "admin", "en", "Changed"
	if old.Spec.RealmRoleScopes[0] != "reader" || old.Spec.Attributes["locale"] != "fr" || old.Status.AdoptionReceipt.State != "Verified" {
		t.Fatal("conversion aliased mutable spec/status")
	}
	if beta.ApplicationFromHub(nil) != nil || (*beta.HankoApplication)(nil).ToHub() != nil || beta.RoleFromHub(nil) != nil || (*beta.HankoRole)(nil).ToHub() != nil || beta.ResourceServerFromHub(nil) != nil || (*beta.HankoResourceServer)(nil).ToHub() != nil {
		t.Fatal("nil conversion changed shape")
	}
}

// Populate every mutable exported field, including future additions. A new
// field omitted by either converter must fail without needing a fuzz mutation
// to guess that field's JSON name.
func populated(value reflect.Value, depth int) {
	if depth > 12 || !value.CanSet() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		value.Set(reflect.New(value.Type().Elem()))
		populated(value.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			populated(value.Field(i), depth+1)
		}
	case reflect.Slice:
		value.Set(reflect.MakeSlice(value.Type(), 1, 1))
		populated(value.Index(0), depth+1)
	case reflect.Map:
		value.Set(reflect.MakeMap(value.Type()))
		key := reflect.New(value.Type().Key()).Elem()
		item := reflect.New(value.Type().Elem()).Elem()
		populated(key, depth+1)
		populated(item, depth+1)
		value.SetMapIndex(key, item)
	case reflect.String:
		value.SetString("field-preserved")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(int64(depth + 1))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(7)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(1.25)
	}
}

func TestEveryExportedFieldAndListSurvivesBothDirections(t *testing.T) {
	scheme := conversionScheme(t)
	for _, kind := range []string{"HankoApplication", "HankoRole", "HankoResourceServer", "HankoApplicationList", "HankoRoleList", "HankoResourceServerList"} {
		t.Run(kind, func(t *testing.T) {
			source, _ := scheme.New(alpha.GroupVersion.WithKind(kind))
			populated(reflect.ValueOf(source).Elem(), 0)
			source.GetObjectKind().SetGroupVersionKind(alpha.GroupVersion.WithKind(kind))
			// List items have their own root wire metadata.
			items := reflect.ValueOf(source).Elem().FieldByName("Items")
			if items.IsValid() {
				for i := 0; i < items.Len(); i++ {
					items.Index(i).Addr().Interface().(runtime.Object).GetObjectKind().SetGroupVersionKind(alpha.GroupVersion.WithKind(kind[:len(kind)-4]))
				}
			}
			next, _ := scheme.New(beta.GroupVersion.WithKind(kind))
			back, _ := scheme.New(alpha.GroupVersion.WithKind(kind))
			if err := scheme.Convert(source, next, nil); err != nil {
				t.Fatal(err)
			}
			if err := scheme.Convert(next, back, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(source, back) {
				t.Fatal("conversion lost an exported field or list identity")
			}
		})
	}
}

func FuzzAPIVersionRoundTrip(f *testing.F) {
	for _, kind := range []string{"HankoApplication", "HankoRole", "HankoResourceServer"} {
		f.Add(kind, []byte(`{"metadata":{"name":"seed","annotations":{"hanko.sh/adoption-contract":"preserved"}},"spec":{"realmRef":"seed"},"status":{"phase":"Ready"}}`))
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		if kind != "HankoApplication" && kind != "HankoRole" && kind != "HankoResourceServer" {
			return
		}
		scheme := conversionScheme(t)
		obj, _ := scheme.New(alpha.GroupVersion.WithKind(kind))
		if json.Unmarshal(data, obj) != nil {
			return
		}
		obj.GetObjectKind().SetGroupVersionKind(alpha.GroupVersion.WithKind(kind))
		next, _ := scheme.New(beta.GroupVersion.WithKind(kind))
		if err := scheme.Convert(obj, next, nil); err != nil {
			t.Fatal(err)
		}
		back, _ := scheme.New(alpha.GroupVersion.WithKind(kind))
		if err := scheme.Convert(next, back, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(obj, back) {
			t.Fatal("lossy API round trip")
		}
	})
}
