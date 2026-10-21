package controller

import (
	"context"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestApplicationExecutionUsesFreshLocalAuthorityNotStatus(t *testing.T) {
	for _, change := range []string{"status", "generation", "mode", "identity", "approval", "realm", "theme"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: "application-uid", Generation: 1}, Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "portal", Type: "spa", Theme: "brand"}}
			realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "realm", Namespace: "auth", UID: "realm-uid", Generation: 1}}
			theme := &api.HankoTheme{ObjectMeta: metav1.ObjectMeta{Name: "brand", Namespace: "auth", UID: "theme-uid", Generation: 1}, Status: api.HankoThemeStatus{Phase: "Ready", JarPath: "/themes/brand.jar", ObservedGeneration: 1}}
			kube := controllerTestClient(controllerTestScheme(t), app, realm, theme)
			r := &HankoApplicationReconciler{Client: kube, OwnershipReader: kube}
			kc := keycloak.New("https://provider.test", "operator", "unused")
			r.Pool = keycloak.NewPool(kc)
			plan, err := r.compileApplicationPlan(ctx, app, kc)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "status":
				app.Status.AppliedPlanHash = "forged"
				app.Status.AppliedGeneration = 123
				if err := kube.Status().Update(ctx, app); err != nil {
					t.Fatal(err)
				}
			case "realm":
				realm.Generation++
				realm.Spec.FrontendURL = "https://public.test"
				if err := kube.Update(ctx, realm); err != nil {
					t.Fatal(err)
				}
			case "theme":
				theme.Status.Phase = "Error"
				if err := kube.Update(ctx, theme); err != nil {
					t.Fatal(err)
				}
			default:
				switch change {
				case "generation":
					app.Generation++
				case "mode":
					app.Spec.Mode = "Observe"
				case "identity":
					app.Spec.ClientID = "replacement"
				case "approval":
					app.Annotations = map[string]string{"hanko.sh/migrate-keycloak-client-uuid": "new-authority"}
				}
				if err := kube.Update(ctx, app); err != nil {
					t.Fatal(err)
				}
			}
			var current api.HankoApplication
			if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
				t.Fatal(err)
			}
			err = r.validateApplicationExecution(ctx, &current, kc, plan)
			if change == "status" {
				if err != nil {
					t.Fatal("status entered execution authority", err)
				}
			} else if !errors.Is(err, iamcontract.ErrStale) {
				t.Fatalf("changed %s accepted: %v", change, err)
			}
		})
	}
}
