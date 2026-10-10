package controller

import (
	"context"
	"errors"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// refreshTargetCandidate resolves the current explicit source or import latch.
// It cannot acquire provider ownership and never uses the writer pool.
func refreshTargetCandidate(ctx context.Context, kube client.Client, reader client.Reader, object client.Object) *api.AdoptionCandidateStatus {
	return readTargetCandidate(ctx, kube, reader, object, false)
}

func readTargetCandidate(ctx context.Context, kube client.Client, reader client.Reader, object client.Object, normalizeAcquisition bool) *api.AdoptionCandidateStatus {
	if reader == nil {
		reader = kube
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	current, ok := object.DeepCopyObject().(client.Object)
	if !ok {
		return incompleteTargetCandidate(object)
	}
	if reader.Get(ctx, client.ObjectKeyFromObject(object), current) != nil || current.GetUID() != object.GetUID() {
		return incompleteTargetCandidate(object)
	}
	object = current
	source, err := resolveAdoptionSource(ctx, reader, object)
	if errors.Is(err, errNoAdoptionSource) {
		return nil
	}
	if err != nil {
		return incompleteTargetCandidate(object)
	}
	importName := object.GetLabels()[importedByLabel]

	target := adoption.TargetIdentity{Namespace: object.GetNamespace(), Name: object.GetName(), UID: string(object.GetUID()), Generation: object.GetGeneration(), ImportRef: importName, TenantRef: object.GetLabels()["hanko.sh/tenant"]}
	realmName, clientID, kind := "", "", ""
	switch o := object.(type) {
	case *api.HankoApplication:
		target.Kind = "HankoApplication"
		realmName = o.Spec.RealmRef
		clientID = o.Spec.ClientID
		kind = "application"
	case *api.HankoServiceAccount:
		target.Kind = "HankoServiceAccount"
		realmName = o.Spec.RealmRef
		clientID = o.Spec.ClientID
		kind = "service-account"
	case *api.HankoRole:
		target.Kind = "HankoRole"
		realmName = o.Spec.RealmRef
		clientID = o.Spec.Name
		kind = "role"
	case *api.HankoResourceServer:
		target.Kind = "HankoResourceServer"
		realmName = o.Spec.RealmRef
		var app api.HankoApplication
		if reader.Get(ctx, types.NamespacedName{Namespace: o.Namespace, Name: o.Spec.ApplicationRef}, &app) == nil && app.Spec.RealmRef == o.Spec.RealmRef {
			clientID = app.Spec.ClientID
		}
		kind = "resource-server"
	}
	failed := func() *api.AdoptionCandidateStatus {
		return candidateStatus(adoption.Build(target, adoption.ProviderIdentity{}, adoption.Observation{Complete: false, Findings: []adoption.Finding{{Code: "current_inventory_unreadable", Domain: kind, Message: "current target, sourceRef identity or bounded provider observation could not be verified", Blocking: true}}}, nil))
	}
	operation := api.HankoImport{}
	operation.Namespace = object.GetNamespace()
	operation.Name = importName

	kc, err := buildKCClientForInstance(ctx, reader, source, false)
	if err != nil {
		return failed()
	}
	kc.RestrictToInventory()
	realm, err := kc.GetRealm(ctx, realmName)
	if err != nil {
		return failed()
	}
	p, err := adoptionSourceIdentity(ctx, reader, source, kc, realm.ID)
	if err != nil {
		return failed()
	}
	reconciler := &HankoImportReconciler{Client: kube, APIReader: reader}
	inventory := &realmAdoptionInventory{provider: p, complete: true}
	switch kind {
	case "application", "service-account":
		got, err := kc.ReadClientOwnership(ctx, realmName, clientID)
		if err != nil || got == nil {
			return failed()
		}
		inventory.clients = []keycloak.InventoryClient{{Application: got.Application, UnqualifiedNative: !got.QualifiedLeaf()}}
		reconciler.discoverInventoryClients(ctx, kc, inventory, realmName)
	case "role":
		got, err := kc.GetRealmRole(ctx, realmName, clientID)
		if err != nil || got == nil {
			return failed()
		}
		inventory.roles = []keycloak.RealmRole{*got}
		reconciler.discoverInventoryRoles(ctx, kc, inventory, realmName)
	case "resource-server":
		got, err := kc.GetApplication(ctx, realmName, clientID)
		if err != nil || got == nil {
			return failed()
		}
		reconciler.discoverInventoryAuthorization(ctx, kc, inventory, realmName, keycloak.InventoryClient{Application: *got})
	}
	reconciler.verifyInventoryIdentity(ctx, inventory, source, kc, *realm)
	for _, item := range inventory.items {
		if item.kind != kind {
			continue
		}
		if normalizeAcquisition {
			item.ownerID = ""
		}
		current, desired := reconciler.currentInventoryTarget(ctx, &operation, item)
		if current.UID != target.UID || current.ImportRef != importName {
			return failed()
		}
		if normalizeAcquisition {
			for i, f := range item.observation.Facts {
				if f.Identity == item.id && f.Field == "owner" {
					item.observation.Facts[i].Value = textValue("unmarked")
					item.observation.Facts[i].Classification = adoption.Supported
				}
			}
		}
		p.ObjectIDs = item.ids
		item.observation.Complete = item.observation.Complete && inventory.complete
		item.observation.Findings = append(item.observation.Findings, inventory.findings...)
		return candidateStatus(adoption.Build(current, p, item.observation, desired))
	}
	return failed()
}
