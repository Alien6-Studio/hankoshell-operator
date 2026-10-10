package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type resourceServerAdoptionState struct {
	model      keycloak.AuthorizationModel
	snapshot   *keycloak.AuthorizationAdoptionSnapshot
	references string
}

func readResourceServerAdoption(ctx context.Context, kube client.Client, reader client.Reader, kc *keycloak.Client, obj *api.HankoResourceServer) (*resourceServerAdoptionState, error) {
	var app api.HankoApplication
	if err := reader.Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.ApplicationRef}, &app); err != nil {
		return nil, err
	}
	if app.UID == "" || !app.DeletionTimestamp.IsZero() || app.Spec.RealmRef != obj.Spec.RealmRef {
		return nil, errAdoptionIdentity
	}
	references := &contractReferenceReader{Client: kube, Reader: reader}
	resolver := &HankoResourceServerReconciler{Client: references, APIReader: reader, Pool: keycloak.NewPool(kc)}
	resolver.organizationResolver = &organizationGrantResolver{reader: reader, provider: authorization.NewKeycloakDriver(kc), namespace: obj.Namespace, realm: obj.Spec.RealmRef}
	declaration := obj.DeepCopy()
	declaration.Spec.Mode = ModeObserve // Resolve references without granting realm authority.
	model, err := resolver.resolveAuthorizationModel(ctx, declaration)
	if err != nil {
		return nil, err
	}
	native := authorization.KeycloakAdoptionModel(model, string(obj.UID))
	snapshot, err := kc.ReadAuthorizationAdoption(ctx, native, string(app.UID))
	if err != nil {
		return nil, err
	}
	if !acquisitionCurrentTarget(ctx, reader, &app, false) {
		return nil, errAdoptionIdentity
	}
	return &resourceServerAdoptionState{native, snapshot, string(references.digest())}, nil
}

func resourceServerCandidate(obj *api.HankoResourceServer, provider adoption.ProviderIdentity, state *resourceServerAdoptionState) *api.AdoptionCandidateStatus {
	target := adoption.TargetIdentity{Kind: "HankoResourceServer", Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID), Generation: obj.Generation, ImportRef: obj.Labels[importedByLabel], TenantRef: obj.Labels["hanko.sh/tenant"]}
	observation := adoption.Observation{Complete: true}
	clientID := state.snapshot.Client.Application.ID
	add := func(domain, id, name, field string, value adoption.Value) {
		observation.Facts = append(observation.Facts, inventoryFact(domain, id, name, field, value))
		provider.ObjectIDs = append(provider.ObjectIDs, id)
	}
	add("resource-server", clientID, obj.Spec.Audience, "owner", textValue("unmarked"))
	add("resource-server", clientID, obj.Spec.Audience, "runtimeBindings", setValue([]string{state.references, "applicationUID/" + state.snapshot.ApplicationUID}))
	scopeNames, resourceNames, policyNames := map[string]string{}, map[string]string{}, map[string]string{}
	for _, scope := range state.snapshot.Graph.Scopes {
		scopeNames[scope.ID] = scope.Name
	}
	for _, resource := range state.snapshot.Graph.Resources {
		resourceNames[resource.ID] = resource.Name
	}
	for _, policy := range state.snapshot.Graph.Policies {
		policyNames[policy.ID] = policy.Name
	}
	for _, scope := range state.snapshot.Graph.Scopes {
		add("authorization-scope", scope.ID, scope.Name, "description", textValue(scope.DisplayName))
	}
	for _, resource := range state.snapshot.Graph.Resources {
		ids := []string{}
		for _, scope := range resource.Scopes {
			ids = append(ids, scope.ID)
		}
		add("authorization-resource", resource.ID, resource.Name, "name", textValue(resource.DisplayName))
		add("authorization-resource", resource.ID, resource.Name, "scopes", setValue(namedAuthorizationRefs(ids, scopeNames)))
		add("authorization-resource", resource.ID, resource.Name, "uris", setValue(resource.URIs))
		add("authorization-resource", resource.ID, resource.Name, "type", textValue(resource.Type))
	}
	for _, policy := range state.snapshot.Graph.Policies {
		principals := []string{}
		for _, role := range policy.Roles {
			principals = append(principals, "role/"+role.ID+"/required="+boolText(role.Required))
		}
		for _, id := range policy.Clients {
			principals = append(principals, "client/"+id)
		}
		for _, group := range policy.Groups {
			principals = append(principals, "group/"+group.ID+"/descendants="+boolText(group.ExtendChildren))
		}
		add("authorization-policy", policy.ID, policy.Name, "principals", setValue(principals))
		add("authorization-policy", policy.ID, policy.Name, "policies", setValue(policy.AssociatedPolicies))
		add("authorization-policy", policy.ID, policy.Name, "logic", textValue(policy.Logic))
		add("authorization-policy", policy.ID, policy.Name, "decisionStrategy", textValue(policy.DecisionStrategy))
		add("authorization-policy", policy.ID, policy.Name, "type", textValue(policy.Type))
	}
	for _, permission := range state.snapshot.Graph.Permissions {
		add("authorization-permission", permission.ID, permission.Name, "type", textValue(permission.Type))
		add("authorization-permission", permission.ID, permission.Name, "logic", textValue(permission.Logic))
		add("authorization-permission", permission.ID, permission.Name, "decisionStrategy", textValue(permission.DecisionStrategy))
		add("authorization-permission", permission.ID, permission.Name, "scopes", setValue(namedAuthorizationRefs(permission.Scopes, scopeNames)))
		add("authorization-permission", permission.ID, permission.Name, "resources", setValue(namedAuthorizationRefs(permission.Resources, resourceNames)))
		add("authorization-permission", permission.ID, permission.Name, "policies", setValue(namedAuthorizationRefs(permission.Policies, policyNames)))
	}
	desired := resourceServerDesiredFacts(obj, state)
	return candidateStatus(adoption.Build(target, provider, observation, desired))
}

func namedAuthorizationRefs(ids []string, names map[string]string) []string {
	values := []string{}
	for _, id := range ids {
		if name, ok := names[id]; ok {
			values = append(values, name)
		} else {
			values = append(values, "unresolved/"+id)
		}
	}
	return values
}

func resourceServerDesiredFacts(obj *api.HankoResourceServer, state *resourceServerAdoptionState) []adoption.Fact {
	id := state.snapshot.Client.Application.ID
	facts := []adoption.Fact{}
	add := func(domain, name, identity, field string, value adoption.Value) {
		if identity == "" {
			identity = id
		}
		facts = append(facts, inventoryFact(domain, identity, name, field, value))
	}
	add("resource-server", obj.Spec.Audience, id, "mode", textValue(obj.Spec.Mode))
	add("resource-server", obj.Spec.Audience, id, "importLatch", flagValue(isImported(obj.Labels)))
	add("resource-server", obj.Spec.Audience, id, "realmRef", textValue(obj.Spec.RealmRef))
	add("resource-server", obj.Spec.Audience, id, "name", textValue(obj.Spec.DisplayName))
	for _, scope := range state.model.Scopes {
		add("authorization-scope", scope.Name, authorizationRefID(state.snapshot.Selected.Scopes, scope.Name), "description", textValue(scope.Description))
	}
	for _, resource := range state.model.Resources {
		resourceID := authorizationRefID(state.snapshot.Selected.Resources, resource.Name)
		add("authorization-resource", resource.Name, resourceID, "name", textValue(resource.DisplayName))
		add("authorization-resource", resource.Name, resourceID, "scopes", setValue(resource.Scopes))
		add("authorization-resource", resource.Name, resourceID, "uris", setValue(resource.URIs))
		add("authorization-resource", resource.Name, resourceID, "type", textValue(resource.Type))
	}
	for _, permission := range state.model.Permissions {
		permissionID := authorizationRefID(state.snapshot.Selected.Permissions, permission.Name)
		add("authorization-permission", permission.Name, permissionID, "type", textValue("scope"))
		add("authorization-permission", permission.Name, permissionID, "logic", textValue("POSITIVE"))
		add("authorization-permission", permission.Name, permissionID, "decisionStrategy", textValue("AFFIRMATIVE"))
		add("authorization-permission", permission.Name, permissionID, "scopes", setValue(permission.Scopes))
		add("authorization-permission", permission.Name, permissionID, "resources", setValue(permission.Resources))
		principals := []string{}
		for _, p := range permission.Principals {
			principals = append(principals, p.Kind+"/"+p.Ref)
			for _, g := range p.Groups {
				principals = append(principals, "group/"+g.ID+"/descendants="+boolText(g.ExtendChildren))
			}
		}
		add("authorization-permission", permission.Name, permissionID, "principals", setValue(principals))
	}
	for _, policy := range state.snapshot.DesiredPolicies {
		principals := []string{}
		for _, role := range policy.Roles {
			principals = append(principals, "role/"+role.ID+"/required="+boolText(role.Required))
		}
		for _, id := range policy.Clients {
			principals = append(principals, "client/"+id)
		}
		for _, group := range policy.Groups {
			principals = append(principals, "group/"+group.ID+"/descendants="+boolText(group.ExtendChildren))
		}
		add("authorization-desired-policy", policy.Name, id, "principals", setValue(principals))
		add("authorization-desired-policy", policy.Name, id, "type", textValue(policy.Type))
		add("authorization-desired-policy", policy.Name, id, "logic", textValue(policy.Logic))
		add("authorization-desired-policy", policy.Name, id, "decisionStrategy", textValue(policy.DecisionStrategy))
	}
	return facts
}

func authorizationRefID(refs []keycloak.AuthorizationManagedReference, name string) string {
	for _, ref := range refs {
		if ref.Name == name {
			return ref.ID
		}
	}
	return ""
}

func (r *HankoResourceServerReconciler) reconcileResourceServerAcquisition(ctx context.Context, cached *api.HankoResourceServer, writer *keycloak.Client) (bool, ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	reader := r.authorityReader()
	current := &api.HankoResourceServer{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(cached), current); err != nil {
		return true, ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if current.UID != cached.UID || !acquisitionMetadataEqual(current, cached) {
		return true, ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if !current.DeletionTimestamp.IsZero() {
		return false, ctrl.Result{}, nil
	}
	approval, err := adoption.ParseApproval(current.Annotations)
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionApprovalRequired")
	}
	if targetAdoptionMode(current) == ModeManage {
		return r.resourceServerManageGate(ctx, current, writer, approval)
	}
	if !approval.Requested {
		return false, ctrl.Result{}, nil
	}
	source, err := resolveAdoptionSource(ctx, reader, current)
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionIdentityChanged")
	}
	observer, err := buildKCClientForInstance(ctx, reader, source, false)
	if err != nil || writer == nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionIncomplete")
	}
	observer.RestrictToInventory()
	before, err := readResourceServerAdoption(ctx, r.Client, reader, observer, current)
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionUnsupported")
	}
	proof := adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoResourceServer", TargetUID: string(current.UID), CandidateHash: approval.CandidateHash}
	existing, objects, err := observer.AuthorizationAdoptionReceipt(ctx, current.Spec.RealmRef, before.snapshot.Client.Application.ID, string(current.UID))
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	if existing == nil && objects.ResourceServerID != "" {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Verified", "AlreadyOwned")
	}
	if existing != nil && !reflect.DeepEqual(*existing, proof) {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	candidate := readTargetCandidate(ctx, r.Client, reader, current, true)
	if reason := adoptionCandidateFailure(candidate, approval); reason != "" {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", reason)
	}
	if existing != nil {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Verified", "AdoptionVerified")
	}
	fresh, err := readResourceServerAdoption(ctx, r.Client, reader, writer, current)
	origin, originErr := adoptionEndpointOrigin(writer.BaseURL())
	if err != nil || originErr != nil || origin != candidate.ProviderIdentity.Origin || !before.snapshot.SameSemantics(fresh.snapshot) || before.references != fresh.references || !acquisitionTargetUnchanged(ctx, reader, current) {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", "AdoptionIdentityChanged")
	}
	candidate = readTargetCandidate(ctx, r.Client, reader, current, true)
	if reason := adoptionCandidateFailure(candidate, approval); reason != "" {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", reason)
	}
	_ = writer.MarkAuthorizationAdoption(ctx, fresh.model, fresh.snapshot, proof)
	after, err := readResourceServerAdoption(ctx, r.Client, reader, observer, current)
	if err != nil || !before.snapshot.SameSemantics(after.snapshot) || before.references != after.references || !acquisitionTargetUnchanged(ctx, reader, current) {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Partial", "AdoptionPartial")
	}
	existing, objects, err = observer.AuthorizationAdoptionReceipt(ctx, current.Spec.RealmRef, after.snapshot.Client.Application.ID, string(current.UID))
	if err != nil || existing == nil || !reflect.DeepEqual(*existing, proof) || !sameSelectedAuthorization(objects, after.snapshot.Selected) {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Partial", "AdoptionPartial")
	}
	verified := readTargetCandidate(ctx, r.Client, reader, current, true)
	if reason := adoptionCandidateFailure(verified, approval); reason != "" {
		return adoptionResult(ctx, r.Client, current, verified, approval, "Partial", "AdoptionPartial")
	}
	return adoptionResult(ctx, r.Client, current, verified, approval, "Verified", "AdoptionVerified")
}

func sameSelectedAuthorization(a, b keycloak.AuthorizationManagedObjects) bool {
	canonical := func(objects keycloak.AuthorizationManagedObjects) keycloak.AuthorizationManagedObjects {
		for _, refs := range []*[]keycloak.AuthorizationManagedReference{&objects.Scopes, &objects.Resources, &objects.Policies, &objects.Permissions} {
			*refs = slices.Clone(*refs)
			slices.SortFunc(*refs, func(a, b keycloak.AuthorizationManagedReference) int { return strings.Compare(a.Name, b.Name) })
		}
		return objects
	}
	a, b = canonical(a), canonical(b)
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func (r *HankoResourceServerReconciler) resourceServerManageGate(ctx context.Context, obj *api.HankoResourceServer, kc *keycloak.Client, approval adoption.Approval) (bool, ctrl.Result, error) {
	if kc == nil {
		return false, ctrl.Result{}, nil
	}
	var app api.HankoApplication
	if err := r.authorityReader().Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.ApplicationRef}, &app); err != nil {
		return true, ctrl.Result{}, err
	}
	native, err := kc.GetApplication(ctx, obj.Spec.RealmRef, app.Spec.ClientID)
	if err != nil {
		return true, ctrl.Result{}, err
	}
	if native == nil {
		if approval.Requested {
			return adoptionResult(ctx, r.Client, obj, nil, approval, "Conflict", "AdoptionIncomplete")
		}
		return false, ctrl.Result{}, nil
	}
	proof, _, err := kc.AuthorizationAdoptionReceipt(ctx, obj.Spec.RealmRef, native.ID, string(obj.UID))
	if err != nil {
		return adoptionResult(ctx, r.Client, obj, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	if proof == nil {
		return false, ctrl.Result{}, nil
	}
	if obj.Spec.Mode != ModeManage || isImported(obj.Labels) {
		return adoptionResult(ctx, r.Client, obj, nil, approval, "Conflict", "ExplicitManageRequired")
	}
	if !keycloak.ApplicationOwned(native, string(app.UID)) || !acquisitionTargetUnchanged(ctx, r.authorityReader(), obj) {
		return adoptionResult(ctx, r.Client, obj, nil, approval, "Conflict", "AdoptionIdentityChanged")
	}
	if _, err := readResourceServerAdoption(ctx, r.Client, r.authorityReader(), kc, obj); err != nil {
		return adoptionResult(ctx, r.Client, obj, nil, approval, "Conflict", "ManagePreservationUnqualified")
	}
	return false, ctrl.Result{}, nil
}
