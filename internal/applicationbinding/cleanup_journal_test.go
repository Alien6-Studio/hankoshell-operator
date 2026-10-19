package applicationbinding

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestRuntimeCleanupRejectsAmbiguousJournalBeforeAnyOutputWrite(t *testing.T) {
	for _, scenario := range []string{"duplicate UID", "escaped duplicate", "unknown field", "case alias", "null", "noncanonical", "trailing", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			f := runtimeFixture(t, true)
			requireDelivery(t, f)
			ctx := context.Background()
			app := read(t, f.kube, client.ObjectKeyFromObject(f.app), &api.HankoApplication{})
			value := app.Annotations[JournalAnnotation]
			switch scenario {
			case "duplicate UID":
				value = strings.Replace(value, `"workloadUID":`, `"workloadUID":"foreign","workloadUID":`, 1)
			case "escaped duplicate":
				value = strings.Replace(value, `"workloadUID":`, `"workload\u0055ID":"foreign","workloadUID":`, 1)
			case "unknown field":
				value = strings.Replace(value, `"workloadUID":`, `"private":"withheld-sentinel","workloadUID":`, 1)
			case "case alias":
				value = strings.Replace(value, `"workloadUID":`, `"WorkloadUID":`, 1)
			case "null":
				value = "null"
			case "noncanonical":
				value = " " + value
			case "trailing":
				value += " {}"
			case "oversized":
				value = strings.Repeat(" ", 49153)
			}
			app.Annotations[JournalAnnotation] = value
			if err := f.kube.Update(ctx, app); err != nil {
				t.Fatal(err)
			}
			b := f.app.Spec.RuntimeBindings[0]
			beforeCM := read(t, f.kube, metadataKey(b), &corev1.ConfigMap{}).DeepCopy()
			beforeSecret := read(t, f.kube, credentialKey(b), &corev1.Secret{}).DeepCopy()
			writes := 0
			f.delivery.Client = interceptor.NewClient(f.kube, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
				writes++
				return c.Patch(ctx, obj, p, opts...)
			}})
			err := f.delivery.Cleanup(ctx, app, nil)
			if Reason(err) != "CleanupConflict" || writes != 0 {
				t.Fatalf("ambiguous journal reached cleanup: reason=%s writes=%d", Reason(err), writes)
			}
			if strings.Contains(err.Error(), "sentinel") {
				t.Fatal("untrusted journal content entered error")
			}
			if !reflect.DeepEqual(beforeCM, read(t, f.kube, metadataKey(b), &corev1.ConfigMap{})) || !reflect.DeepEqual(beforeSecret, read(t, f.kube, credentialKey(b), &corev1.Secret{})) {
				t.Fatal("refused cleanup changed an output")
			}
		})
	}
}

func TestRuntimeCleanupJournalRetainsExactRecordAndByteBounds(t *testing.T) {
	b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}}
	for _, count := range []int{0, MaxBindings, MaxBindings + 1} {
		values := make([]record, count)
		for i := range values {
			values[i] = record{Binding: b, WorkloadUID: "sa-uid", ConfigMapUID: "cm-uid"}
		}
		encoded, _ := json.Marshal(values)
		app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{JournalAnnotation: string(encoded)}}}
		parsed, err := records(app)
		if (err == nil) != (count <= MaxBindings) || err == nil && len(parsed) != count {
			t.Fatal("cleanup record cardinality boundary changed")
		}
	}
}

func FuzzRuntimeCleanupJournal(f *testing.F) {
	b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}, PublicMetadata: api.ApplicationRuntimeMetadataTarget{ConfigMapRef: "identity"}}
	seed, _ := json.Marshal([]record{{Binding: b, WorkloadUID: "sa-uid", ConfigMapUID: "cm-uid"}})
	for _, value := range []string{"", "[]", string(seed), "null", strings.Replace(string(seed), `"workloadUID":`, `"workloadUID":"foreign","workloadUID":`, 1), strings.Repeat(" ", 49153)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		app := &api.HankoApplication{}
		app.Annotations = map[string]string{JournalAnnotation: value}
		result, err := records(app)
		if err != nil || value == "" {
			return
		}
		encoded, _ := json.Marshal(result)
		if len(value) > 49152 || result == nil || len(result) > MaxBindings || string(encoded) != value {
			t.Fatal("accepted ambiguous or unbounded cleanup journal")
		}
		for _, r := range result {
			if !validBinding(r.Binding) || !validRecordUIDs(r) {
				t.Fatal("accepted unbound cleanup target")
			}
		}
		app.Annotations[JournalAnnotation] = value + " null"
		if _, err := records(app); err == nil {
			t.Fatal("accepted trailing cleanup document")
		}
	})
}

func FuzzRuntimeTargetAuthorization(f *testing.F) {
	f.Add("app-uid", "sa-uid", "cm-uid", "metadata", "worker", false)
	f.Add("foreign", "sa-uid", "cm-uid", "metadata", "worker", false)
	f.Fuzz(func(t *testing.T, owner, workloadUID, targetUID, kind, binding string, deleting bool) {
		app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "auth", UID: "app-uid"}}
		b := api.ApplicationRuntimeBinding{Name: "worker", Workload: api.ApplicationRuntimeWorkload{Namespace: "payments", ServiceAccountRef: "worker"}}
		annotations := Authorization(app, b, "sa-uid")
		annotations[ApplicationUID], annotations[ServiceAccountUID], annotations[BindingName] = owner, workloadUID, binding
		target := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{UID: types.UID(targetUID), Labels: map[string]string{TargetLabel: kind}, Annotations: annotations}}
		if deleting {
			target.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
		}
		err := authorized(target, app, b, "sa-uid", "metadata")
		want := owner == "app-uid" && workloadUID == "sa-uid" && targetUID != "" && kind == "metadata" && binding == "worker" && !deleting
		if (err == nil) != want {
			t.Fatal("runtime target authority crossed an identity or consent boundary")
		}
	})
}
