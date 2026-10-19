package controller

import (
	"context"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func credentialFixture() (*api.HankoApplication, *corev1.Secret) {
	app := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "auth", UID: "application-uid"}, Spec: api.HankoApplicationSpec{ClientID: "portal", Type: "web"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName(app.Spec.ClientID), Namespace: app.Namespace, UID: "canonical-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(app, api.GroupVersion.WithKind("HankoApplication"))}}, Data: map[string][]byte{"client_secret": []byte("retained")}}
	return app, secret
}

func TestCanonicalCredentialRefusesForeignOwnershipBeforeProviderRead(t *testing.T) {
	for _, kind := range []string{"no-owner", "uid", "name", "kind", "api-version", "deleting"} {
		t.Run(kind, func(t *testing.T) {
			app, secret := credentialFixture()
			switch kind {
			case "no-owner":
				secret.OwnerReferences = nil
			case "uid":
				secret.OwnerReferences[0].UID = "foreign"
			case "name":
				secret.OwnerReferences[0].Name = "foreign"
			case "kind":
				secret.OwnerReferences[0].Kind = "HankoRealm"
			case "api-version":
				secret.OwnerReferences[0].APIVersion = "foreign/v1"
			case "deleting":
				now := metav1.Now()
				secret.DeletionTimestamp = &now
				secret.Finalizers = []string{"fixture"}
			}
			kube := controllerTestClient(controllerTestScheme(t), app, secret)
			r := &HankoApplicationReconciler{Client: kube, Scheme: controllerTestScheme(t)}
			// A nil provider makes any credential request a test failure.
			if err := r.ensureSecret(context.Background(), app, nil, nil); err == nil {
				t.Fatal("foreign Secret trusted")
			}
			if err := r.upsertSecret(context.Background(), app, "new", nil); err == nil {
				t.Fatal("foreign Secret overwritten")
			}
			var current corev1.Secret
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(secret), &current); err != nil {
				t.Fatal(err)
			}
			if string(current.Data["client_secret"]) != "retained" {
				t.Fatal("foreign data changed")
			}
		})
	}
}

func TestApplicationCredentialWritesRefuseConcurrentReplacementAndRevocation(t *testing.T) {
	for _, operation := range []string{"canonical", "projection", "cleanup"} {
		for _, change := range []string{"replace", "revoke"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				app, secret := credentialFixture()
				if operation != "canonical" {
					secret.OwnerReferences = nil
					secret.Namespace = "workload"
					secret.Labels = map[string]string{clientSecretProjectionLabel: "true"}
					secret.Annotations = secretProjectionAnnotations(app)
				}
				base := controllerTestClient(controllerTestScheme(t), app, secret)
				changed := false
				kube := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
					if !changed {
						changed = true
						var current corev1.Secret
						if err := c.Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
							return err
						}
						current.Data["client_secret"] = []byte("concurrent")
						if change == "replace" {
							if err := c.Delete(ctx, &current); err != nil {
								return err
							}
							current.UID = "replacement-uid"
							current.ResourceVersion = ""
							if err := c.Create(ctx, &current); err != nil {
								return err
							}
						} else {
							current.OwnerReferences, current.Annotations = nil, nil
							if err := c.Update(ctx, &current); err != nil {
								return err
							}
						}
					}
					return c.Patch(ctx, obj, p, opts...)
				}})
				r := &HankoApplicationReconciler{Client: kube, Scheme: controllerTestScheme(t)}
				var err error
				switch operation {
				case "canonical":
					err = r.upsertSecret(ctx, app, "new", nil)
				case "projection":
					err = r.upsertSecretProjection(ctx, app, client.ObjectKeyFromObject(secret), "new", nil)
				case "cleanup":
					err = r.clearSecretProjection(ctx, app, client.ObjectKeyFromObject(secret), nil)
				}
				if err == nil || !changed {
					t.Fatal("concurrent identity/authorization change was accepted")
				}
				var current corev1.Secret
				if err := base.Get(ctx, client.ObjectKeyFromObject(secret), &current); err != nil {
					t.Fatal(err)
				}
				if string(current.Data["client_secret"]) != "concurrent" {
					t.Fatal("stale mutation changed concurrent data")
				}
			})
		}
	}
}

func TestApplicationCredentialReadBackAndAuthorityFailuresStayPending(t *testing.T) {
	for _, failure := range []string{"read-back", "authority", "replacement"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			app, secret := credentialFixture()
			base := controllerTestClient(controllerTestScheme(t), app, secret)
			written := false
			kube := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
					if err := c.Patch(ctx, obj, p, opts...); err != nil {
						return err
					}
					written = true
					return nil
				},
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if written && failure == "read-back" {
						return errors.New("read-back unavailable")
					}
					if err := c.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if written && failure == "replacement" {
						obj.SetUID("replacement-uid")
					}
					return nil
				},
			})
			r := &HankoApplicationReconciler{Client: kube, Scheme: controllerTestScheme(t)}
			guard := func(context.Context) error {
				if written && failure == "authority" {
					return errors.New("stale execution")
				}
				return nil
			}
			if err := r.upsertSecret(ctx, app, "new", guard); err == nil || !written {
				t.Fatal("unproven credential output acknowledged")
			}
		})
	}
}
