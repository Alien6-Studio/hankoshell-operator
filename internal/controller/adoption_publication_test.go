package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestInventoryCandidateConcurrentStatusPublication(t *testing.T) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount", "HankoRole", "HankoResourceServer"} {
		for _, mutation := range []string{"status", "generation", "tenant", "import", "replacement", "unavailable", "conflicts"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				ctx := context.Background()
				metadata := metav1.ObjectMeta{Name: "target", Namespace: "auth", UID: "target-uid", Generation: 1, Labels: map[string]string{importedByLabel: "inventory"}}
				var object client.Object
				switch kind {
				case "HankoApplication":
					object = &api.HankoApplication{ObjectMeta: metadata}
				case "HankoServiceAccount":
					object = &api.HankoServiceAccount{ObjectMeta: metadata}
				case "HankoRole":
					object = &api.HankoRole{ObjectMeta: metadata}
				case "HankoResourceServer":
					object = &api.HankoResourceServer{ObjectMeta: metadata}
				}
				kube := controllerTestClient(controllerTestScheme(t), object)
				calls := 0
				outage := errors.New("fixture API unavailable")
				writer := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{
					SubResourcePatch: func(ctx context.Context, c client.Client, _ string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						calls++
						if mutation == "unavailable" {
							return outage
						}
						if calls == 1 || mutation == "conflicts" {
							fresh := object.DeepCopyObject().(client.Object)
							if err := c.Get(ctx, client.ObjectKeyFromObject(object), fresh); err != nil {
								t.Fatal(err)
							}
							if mutation == "status" {
								switch o := fresh.(type) {
								case *api.HankoApplication:
									o.Status.Phase = "Ready"
								case *api.HankoServiceAccount:
									o.Status.Phase = "Ready"
								case *api.HankoRole:
									o.Status.Phase = "Ready"
								case *api.HankoResourceServer:
									o.Status.Phase = "Ready"
								}
								if err := c.Status().Update(ctx, fresh); err != nil {
									t.Fatal(err)
								}
							} else {
								switch mutation {
								case "generation":
									fresh.SetGeneration(2)
								case "tenant":
									fresh.GetLabels()["hanko.sh/tenant"] = "changed"
								case "import":
									fresh.GetLabels()[importedByLabel] = "changed"
								case "replacement":
									if err := c.Delete(ctx, fresh); err != nil {
										t.Fatal(err)
									}
									fresh.SetUID("replacement-uid")
									fresh.SetResourceVersion("")
									if err := c.Create(ctx, fresh); err != nil {
										t.Fatal(err)
									}
								}
								if mutation != "replacement" {
									if err := c.Update(ctx, fresh); err != nil {
										t.Fatal(err)
									}
								}
							}
							return apierrors.NewConflict(schema.GroupResource{Group: "hanko.sh", Resource: kind}, obj.GetName(), fmt.Errorf("fixture status race"))
						}
						return c.Status().Patch(ctx, obj, patch, opts...)
					},
				})
				target := adoption.TargetIdentity{Kind: kind, Namespace: "auth", Name: "target", UID: "target-uid", Generation: 1, ImportRef: "inventory"}
				candidate := adoption.Build(target, adoption.ProviderIdentity{}, adoption.Observation{Complete: true}, nil)
				r := &HankoImportReconciler{Client: writer, APIReader: kube}
				published, err := r.patchInventoryCandidate(ctx, target, candidate)
				switch mutation {
				case "status":
					if !published || err != nil || calls != 2 {
						t.Fatalf("status race did not recover: %v %v %d", published, err, calls)
					}
					if err := kube.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
						t.Fatal(err)
					}
					var phase string
					switch o := object.(type) {
					case *api.HankoApplication:
						phase = o.Status.Phase
					case *api.HankoServiceAccount:
						phase = o.Status.Phase
					case *api.HankoRole:
						phase = o.Status.Phase
					case *api.HankoResourceServer:
						phase = o.Status.Phase
					}
					if phase != "Ready" {
						t.Fatal("candidate publication overwrote the concurrent leaf status")
					}
				case "unavailable", "conflicts":
					if published || err == nil || calls > 4 {
						t.Fatal("API failure swallowed or unbounded retries", published, err, calls)
					}
				default:
					if published || err != nil || calls != 1 {
						t.Fatal("changed identity accepted stale evidence", published, err, calls)
					}
				}
			})
		}
	}
}

func TestImportEvidencePublicationFailureRemainsRetryable(t *testing.T) {
	ctx := context.Background()
	object := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "auth", UID: "target-uid", Generation: 1}, Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "client"}}
	operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}}
	operation.Status.Coverage.Complete = true
	item := newInventoryItem("application", "realm", "provider-id", "client")
	inventory := &realmAdoptionInventory{complete: true, items: []*adoptionInventoryItem{item}, provider: adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "source-uid"}, Origin: "https://keycloak.example.test", RealmID: "realm-uuid", Trust: "public-ca", ObjectIDs: item.ids}}
	kube := controllerTestClient(controllerTestScheme(t), object)
	outage := errors.New("fixture API unavailable")
	writer := interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return outage
	}})
	r := &HankoImportReconciler{Client: writer, APIReader: kube}
	if err := r.updateImportEvidence(ctx, operation, []importedRealmData{{inventory: inventory}}, true); !errors.Is(err, outage) {
		t.Fatal("failed publication became terminal partial evidence", err)
	}
	// A fresh observation on the next reconcile must discard the previous
	// incomplete attempt, rather than accumulating its negative coverage.
	operation.Status.Coverage.Complete = true
	r.Client = kube
	if err := r.updateImportEvidence(ctx, operation, []importedRealmData{{inventory: inventory}}, true); err != nil || !operation.Status.Coverage.Complete {
		t.Fatal("publication did not recover", err)
	}
}

func TestImportPublicationOutageResumesAfterManagerRestart(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		for _, lostAck := range []bool{false, true} {
			t.Run(fmt.Sprintf("dry-run-%t/lost-ack-%t", dryRun, lostAck), func(t *testing.T) {
				f := newAcquisitionFixture(t, "HankoApplication", "oidc")
				ctx := context.Background()
				includeProviders := false
				op := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}, Spec: api.HankoImportSpec{SourceRef: "source", DryRun: dryRun, IncludeIdentityProviders: &includeProviders}}
				if err := f.kube.Create(ctx, op); err != nil {
					t.Fatal(err)
				}
				outage := errors.New("fixture status response lost")
				writer := interceptor.NewClient(f.kube.(client.WithWatch), interceptor.Funcs{
					SubResourcePatch: func(ctx context.Context, c client.Client, _ string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						if _, leaf := obj.(*api.HankoApplication); leaf {
							if lostAck {
								if err := c.Status().Patch(ctx, obj, patch, opts...); err != nil {
									return err
								}
							}
							return outage
						}
						return c.Status().Patch(ctx, obj, patch, opts...)
					},
				})
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(op)}
				r := &HankoImportReconciler{Client: writer, APIReader: f.kube, RequireHTTPS: true}
				if _, err := r.Reconcile(ctx, req); !errors.Is(err, outage) {
					t.Fatal("publication failure did not retry", err)
				}
				if err := f.kube.Get(ctx, req.NamespacedName, op); err != nil || op.Status.CompletedAt != nil || op.Status.Phase == "Done" || op.Status.Phase == "Failed" {
					t.Fatal("publication outage made the import terminal", err, op.Status.Phase)
				}
				// No in-memory retry state survives. The source is rediscovered,
				// and an acknowledged candidate becomes an ordinary semantic no-op.
				r = &HankoImportReconciler{Client: f.kube, APIReader: f.kube, RequireHTTPS: true}
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatal(err)
				}
				if err := f.kube.Get(ctx, req.NamespacedName, op); err != nil || op.Status.Phase != "Done" || !op.Status.Coverage.Complete {
					t.Fatal("fresh manager did not finish complete import", err, op.Status)
				}
				if f.puts != 0 || f.observerWrites != 0 || f.credentialCalls != 0 {
					t.Fatal("import recovery acquired provider write or credential authority")
				}
			})
		}
	}
}
