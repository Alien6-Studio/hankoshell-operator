package controller

import (
	"context"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func previewAlias(kind string) client.Object {
	meta := metav1.ObjectMeta{Name: "passive-import", Namespace: "auth", UID: "alias-uid"}
	if kind == "HankoServiceAccount" {
		return &api.HankoServiceAccount{ObjectMeta: meta, Spec: api.HankoServiceAccountSpec{Mode: ModeObserve, RealmRef: "realm", ClientID: "client"}}
	}
	return &api.HankoApplication{ObjectMeta: meta, Spec: api.HankoApplicationSpec{Mode: ModeObserve, RealmRef: "realm", ClientID: "client", Type: "spa"}}
}

func TestExplicitClientAcquisitionPreservesPassiveObserveAliases(t *testing.T) {
	for _, targetKind := range []string{"HankoApplication", "HankoServiceAccount"} {
		for _, aliasKind := range []string{"HankoApplication", "HankoServiceAccount"} {
			t.Run(targetKind+"/"+aliasKind, func(t *testing.T) {
				f := newAcquisitionFixture(t, targetKind, "oidc")
				alias := previewAlias(aliasKind)
				if err := f.kube.Create(context.Background(), alias); err != nil {
					t.Fatal(err)
				}
				original := alias.DeepCopyObject().(client.Object)
				f.approve()
				if err := f.run(); err != nil {
					t.Fatal(err)
				}
				receipt, _ := f.status()
				if receipt == nil || receipt.State != "Verified" || f.puts != 1 || f.observerWrites != 0 || f.credentialCalls != 0 {
					t.Fatal("explicit UID acquisition failed or exceeded ownership-only writes")
				}
				if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(alias), alias); err != nil || !acquisitionMetadataEqual(original, alias) || targetAdoptionMode(alias) != ModeObserve {
					t.Fatal("passive alias was changed by acquisition")
				}
			})
		}
	}
}

func TestExplicitClientAcquisitionHoldsCompetingManagerAndApproval(t *testing.T) {
	for _, kind := range []string{"HankoApplication", "HankoServiceAccount"} {
		for _, conflict := range []string{"manager", "approval", "malformed-approval"} {
			t.Run(kind+"/"+conflict, func(t *testing.T) {
				f := newAcquisitionFixture(t, "HankoApplication", "oidc")
				alias := previewAlias(kind)
				if err := f.kube.Create(context.Background(), alias); err != nil {
					t.Fatal(err)
				}
				f.approve()
				if conflict == "manager" {
					switch a := alias.(type) {
					case *api.HankoApplication:
						a.Spec.Mode = ModeManage
					case *api.HankoServiceAccount:
						a.Spec.Mode = ModeManage
					}
				} else {
					annotations := map[string]string{adoption.SourceAnnotation: "source", adoption.ContractAnnotation: string(adoption.Version), adoption.CandidateAnnotation: "sha256:" + strings.Repeat("a", 64)}
					if conflict == "malformed-approval" {
						annotations[adoption.ContractAnnotation] = "unknown"
					}
					alias.SetAnnotations(annotations)
				}
				if err := f.kube.Update(context.Background(), alias); err != nil {
					t.Fatal(err)
				}
				if err := f.run(); err != nil {
					t.Fatal(err)
				}
				receipt, _ := f.status()
				if receipt == nil || receipt.State != "Conflict" || f.puts != 0 || f.credentialCalls != 0 {
					t.Fatal("stale approval acquired against a competing local claim")
				}
			})
		}
	}
}

func TestCatalogDiscoveryStillRefusesAmbiguousClientTargets(t *testing.T) {
	f := newAcquisitionFixture(t, "HankoApplication", "oidc")
	alias := previewAlias("HankoApplication")
	if err := f.kube.Create(context.Background(), alias); err != nil {
		t.Fatal(err)
	}
	r := &HankoImportReconciler{Client: f.kube, APIReader: f.kube}
	item := newInventoryItem("application", "realm", "client-uuid", "client")
	target, _ := r.currentInventoryTarget(context.Background(), &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Namespace: "auth"}}, item)
	if target.UID != "" || f.puts != 0 {
		t.Fatal("catalog discovery chose a declaration without explicit target authority")
	}
}
