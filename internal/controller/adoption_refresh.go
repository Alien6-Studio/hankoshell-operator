package controller

import (
	"context"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// refreshImportedCandidate resolves sourceRef from the current import latch,
// never a status-supplied endpoint/credential or the shared writer pool. A fresh
// UID/spec read is mandatory. The result cannot cause a provider write.
func refreshImportedCandidate(ctx context.Context, kube client.Client, reader client.Reader, object client.Object) *api.AdoptionCandidateStatus {
	importName := object.GetLabels()[importedByLabel]
	if importName == "" {
		return nil
	}
	if reader == nil {
		reader = kube
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
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
	var operation api.HankoImport
	if reader.Get(ctx, types.NamespacedName{Namespace: object.GetNamespace(), Name: importName}, &operation) != nil {
		return failed()
	}
	var source api.HankoKeycloakInstance
	if reader.Get(ctx, types.NamespacedName{Namespace: object.GetNamespace(), Name: operation.Spec.SourceRef}, &source) != nil {
		return failed()
	}
	kc, err := buildKCClientForInstance(ctx, reader, &source, false)
	if err != nil {
		return failed()
	}
	kc.RestrictToInventory()
	realm, err := kc.GetRealm(ctx, realmName)
	if err != nil {
		return failed()
	}
	p, err := adoptionSourceIdentity(ctx, reader, &source, kc, realm.ID)
	if err != nil {
		return failed()
	}
	reconciler := &HankoImportReconciler{Client: kube, APIReader: reader}
	inventory := &realmAdoptionInventory{provider: p, complete: true}
	switch kind {
	case "application", "service-account":
		got, err := kc.GetApplication(ctx, realmName, clientID)
		if err != nil || got == nil {
			return failed()
		}
		inventory.clients = []keycloak.InventoryClient{{Application: *got}}
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
	reconciler.verifyInventoryIdentity(ctx, inventory, &source, kc, *realm)
	for _, item := range inventory.items {
		if item.kind != kind {
			continue
		}
		current, desired := reconciler.currentInventoryTarget(ctx, &operation, item)
		if current.UID != target.UID || current.ImportRef != importName {
			return failed()
		}
		p.ObjectIDs = item.ids
		item.observation.Complete = item.observation.Complete && inventory.complete
		item.observation.Findings = append(item.observation.Findings, inventory.findings...)
		return candidateStatus(adoption.Build(current, p, item.observation, desired))
	}
	return failed()
}
