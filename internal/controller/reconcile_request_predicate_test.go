package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func TestGenerationOrReconcileRequestChanged(t *testing.T) {
	predicate := generationOrReconcileRequestChanged()
	tests := []struct {
		name string
		old  *hankoshv1alpha1.HankoRealm
		new  *hankoshv1alpha1.HankoRealm
		want bool
	}{
		{
			name: "spec generation changed",
			old:  &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 1}},
			new:  &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 2}},
			want: true,
		},
		{
			name: "reconcile request added",
			old:  &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 1}},
			new: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{
				Generation: 1, Annotations: map[string]string{reconcileRequestAnnotation: "request-1"},
			}},
			want: true,
		},
		{
			name: "reconcile request changed",
			old: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{
				Generation: 1, Annotations: map[string]string{reconcileRequestAnnotation: "request-1"},
			}},
			new: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{
				Generation: 1, Annotations: map[string]string{reconcileRequestAnnotation: "request-2"},
			}},
			want: true,
		},
		{
			name: "unrelated annotation changed",
			old: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{
				Generation: 1, Annotations: map[string]string{"example.test/value": "old"},
			}},
			new: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{
				Generation: 1, Annotations: map[string]string{"example.test/value": "new"},
			}},
			want: false,
		},
		{
			name: "status-only update",
			old:  &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 1}},
			new:  &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 1}, Status: hankoshv1alpha1.HankoRealmStatus{Phase: "Ready"}},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := predicate.Update(event.UpdateEvent{ObjectOld: test.old, ObjectNew: test.new})
			if got != test.want {
				t.Fatalf("Update() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAdoptionMetadataChangesEnqueueEachLeafWithoutGenerationChange(t *testing.T) {
	for _, object := range []client.Object{&hankoshv1alpha1.HankoApplication{}, &hankoshv1alpha1.HankoRole{}, &hankoshv1alpha1.HankoServiceAccount{}} {
		object.SetGeneration(8)
		for _, key := range []string{adoption.SourceAnnotation, adoption.ContractAnnotation, adoption.CandidateAnnotation, "hanko.sh/migrate-keycloak-client-uuid", "hanko.sh/migrate-keycloak-observation"} {
			for _, value := range []string{"", "reviewed"} {
				changed := object.DeepCopyObject().(client.Object)
				changed.SetAnnotations(map[string]string{key: value})
				p := generationOrReconcileRequestChanged()
				if !p.Update(event.UpdateEvent{ObjectOld: object, ObjectNew: changed}) || !p.Update(event.UpdateEvent{ObjectOld: changed, ObjectNew: object}) {
					t.Fatalf("metadata addition/removal was filtered for %T %s", object, key)
				}
			}
		}
	}
}

func TestReconcileRequestPredicateAppliesToHankoApplication(t *testing.T) {
	predicate := generationOrReconcileRequestChanged()
	oldApplication := &hankoshv1alpha1.HankoApplication{ObjectMeta: metav1.ObjectMeta{
		Generation: 8, Annotations: map[string]string{reconcileRequestAnnotation: "before"},
	}}
	newApplication := oldApplication.DeepCopy()
	newApplication.Annotations[reconcileRequestAnnotation] = "after"
	if !predicate.Update(event.UpdateEvent{ObjectOld: oldApplication, ObjectNew: newApplication}) {
		t.Fatal("HankoApplication reconcile-request annotation change was filtered")
	}
}
