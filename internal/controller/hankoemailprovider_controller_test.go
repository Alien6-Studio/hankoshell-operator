package controller

import (
	"context"
	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
	"time"
)

func TestLegacyEmailProviderRetiresReadinessWithoutCredentialsOrNetwork(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			stamp := metav1.NewTime(time.Now())
			provider := &hankoshv1alpha1.HankoEmailProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "platform-email", Namespace: "auth", Generation: 4},
				Spec:       hankoshv1alpha1.HankoEmailProviderSpec{Type: "office365", Enabled: enabled},
				Status: hankoshv1alpha1.HankoEmailProviderStatus{Phase: "Ready", ObservedGeneration: 4, LastPreflight: &stamp, CredentialVersion: "old-version",
					Conditions: []metav1.Condition{{Type: "DeliveryReady", Status: metav1.ConditionTrue, Reason: "PreflightPassed", LastTransitionTime: stamp}}},
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(provider).WithObjects(provider).Build()
			r := &HankoEmailProviderReconciler{Client: client}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: provider.Name, Namespace: provider.Namespace}}
			for i := 0; i < 2; i++ {
				result, err := r.Reconcile(context.Background(), req)
				if err != nil || result.RequeueAfter != 0 {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			}
			var got hankoshv1alpha1.HankoEmailProvider
			if err := client.Get(context.Background(), req.NamespacedName, &got); err != nil {
				t.Fatal(err)
			}
			phase := "Deprecated"
			if !enabled {
				phase = "Disabled"
			}
			condition := meta.FindStatusCondition(got.Status.Conditions, "DeliveryReady")
			if got.Status.Phase != phase || got.Status.LastPreflight != nil || got.Status.CredentialVersion != "" ||
				condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "DelegatedToAPI" || condition.ObservedGeneration != 4 {
				t.Fatalf("legacy status=%+v", got.Status)
			}
			if got.Spec.Type != "office365" || got.Spec.Enabled != enabled {
				t.Fatal("legacy configuration was modified")
			}
		})
	}
}
