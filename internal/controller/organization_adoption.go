package controller

import (
	"context"
	"errors"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *HankoOrganizationReconciler) organizationReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// Resolve the hierarchy from current declarations and exact provider reads;
// parent status UUIDs are never ownership or adoption authority.
func organizationAdoptionPath(ctx context.Context, reader client.Reader, kc *keycloak.Client, org *api.HankoOrganization) (string, string, []string, error) {
	return organizationLifecyclePath(ctx, reader, kc, org, false)
}

func organizationLifecyclePath(ctx context.Context, reader client.Reader, kc *keycloak.Client, org *api.HankoOrganization, deleting bool) (string, string, []string, error) {
	names := []string{org.Spec.Name}
	bindings := []string{}
	seen := map[string]bool{org.Name: true}
	parentRef := org.Spec.ParentRef
	for parentRef != "" {
		if seen[parentRef] || len(names) > adoption.MaxDepth {
			return "", "", nil, errAdoptionIdentity
		}
		seen[parentRef] = true
		var parent api.HankoOrganization
		if reader.Get(ctx, client.ObjectKey{Namespace: org.Namespace, Name: parentRef}, &parent) != nil || parent.UID == "" || !deleting && !parent.DeletionTimestamp.IsZero() || parent.Spec.RealmRef != org.Spec.RealmRef {
			return "", "", nil, errAdoptionIdentity
		}
		bindings = append(bindings, string(parent.UID)+"/"+parent.Name)
		names = append(names, parent.Spec.Name)
		parentRef = parent.Spec.ParentRef
	}
	path := ""
	for i := len(names) - 1; i >= 0; i-- {
		if names[i] == "" || strings.ContainsAny(names[i], "/\x00\r\n") {
			return "", "", nil, errAdoptionIdentity
		}
		path += "/" + names[i]
	}
	parentID := ""
	if org.Spec.ParentRef != "" {
		parent, err := kc.GetGroupByPath(ctx, org.Spec.RealmRef, strings.TrimSuffix(path, "/"+org.Spec.Name))
		if err != nil || parent.ID == "" {
			return "", "", nil, errAdoptionIdentity
		}
		parentID = parent.ID
	}
	return path, parentID, bindings, nil
}

func (r *HankoOrganizationReconciler) reconcileOrganizationObserve(ctx context.Context, org *api.HankoOrganization) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		controllerutil.RemoveFinalizer(org, orgFinalizerName)
		if err := r.Update(ctx, org); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if !org.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	patch := client.MergeFrom(org.DeepCopy())
	org.Status.AdoptionCandidate = refreshTargetCandidate(ctx, r.Client, r.organizationReader(), org)
	org.Status.ObservedGeneration = org.Generation
	setCondition(&org.Status.Conditions, "Projection", metav1.ConditionUnknown, "ObserveOnly", "Observe does not call the platform projection")
	kc := kcForObject(r.Pool, org.Namespace, org.Labels)
	path, _, _, err := organizationAdoptionPath(ctx, r.organizationReader(), kc, org)
	if err == nil {
		var group *keycloak.Group
		group, err = kc.GetGroupByPath(ctx, org.Spec.RealmRef, path)
		if err == nil {
			org.Status.GroupID, org.Status.GroupPath = group.ID, group.Path
		}
	}
	reason, condition := "Observed", metav1.ConditionTrue
	org.Status.Phase = "Ready"
	if err != nil {
		reason, condition, org.Status.Phase = "ObserveFailed", metav1.ConditionFalse, "Error"
	}
	if org.Spec.ParentRef == "" && err == nil {
		var native *keycloak.Organization
		native, err = kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(org))
		if err == nil && native != nil {
			org.Status.OrgID = native.ID
		}
		if err != nil {
			reason, condition, org.Status.Phase = "ObserveFailed", metav1.ConditionFalse, "Error"
		}
	}
	now := metav1.Now()
	org.Status.LastReconciled = &now
	iamCondition(&org.Status.Conditions, org.Generation, "Synced", condition, reason, "Observe reads provider configuration without semantic writes, credentials or membership inventory")
	if err := r.Status().Patch(ctx, org, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func readOrganizationCandidate(ctx context.Context, reader client.Reader, kc *keycloak.Client, org *api.HankoOrganization, provider adoption.ProviderIdentity, normalize bool) *api.AdoptionCandidateStatus {
	target := adoption.TargetIdentity{Kind: "HankoOrganization", Namespace: org.Namespace, Name: org.Name, UID: string(org.UID), Generation: org.Generation, ImportRef: org.Labels[importedByLabel], TenantRef: org.Labels["hanko.sh/tenant"]}
	path, parentID, bindings, err := organizationAdoptionPath(ctx, reader, kc, org)
	if err != nil {
		return incompleteTargetCandidate(org)
	}
	alias := ""
	if org.Spec.ParentRef == "" {
		alias = orgSlug(org)
		enabled, err := kc.InventoryOrganizationsEnabled(ctx, org.Spec.RealmRef)
		if err != nil || !enabled {
			return candidateStatus(adoption.Build(target, provider, adoption.Observation{Complete: false, Findings: []adoption.Finding{{Code: "organizations_not_enabled", Domain: "organization", Message: "native Organizations must already be enabled on the external realm", Blocking: true}}}, nil))
		}
	}
	s, err := kc.ReadOrganizationOwnership(ctx, org.Spec.RealmRef, path, alias)
	if err != nil {
		return incompleteTargetCandidate(org)
	}
	item := newInventoryItem("group", org.Spec.RealmRef, s.Group.ID, s.Group.Name)
	item.fact("name", textValue(s.Group.Name))
	item.fact("path", textValue(s.Group.Path))
	item.fact("parent", textValue(s.ParentID))
	item.fact("runtimeBindings", setValue(bindings))
	if s.ParentID != parentID || !s.QualifiedRoots() {
		item.finding("hierarchy_or_native_root_unqualified", "hierarchy and complete native root representation must be qualified", true)
	}
	organizationCandidateOwner(item, "group", s.Group.ID, s.Group.Name, s.Group.Attributes, org, normalize)
	for _, child := range s.Children {
		item.ids = append(item.ids, child.ID)
		item.observation.Facts = append(item.observation.Facts, inventoryFact("group-child", child.ID, child.Name, "path", textValue(child.Path)))
	}
	for _, role := range s.Roles {
		item.ids = append(item.ids, role.ID)
		item.observation.Facts = append(item.observation.Facts, inventoryFact("group-role", role.ID, role.Name, "container", textValue(role.ContainerID)))
	}
	desired := []adoption.Fact{inventoryFact("group", s.Group.ID, s.Group.Name, "name", textValue(org.Spec.Name)), inventoryFact("group", s.Group.ID, s.Group.Name, "path", textValue(path)), inventoryFact("group", s.Group.ID, s.Group.Name, "parent", textValue(parentID)), inventoryFact("group", s.Group.ID, s.Group.Name, "realmRoles", setValue(org.Spec.Roles)), inventoryFact("group", s.Group.ID, s.Group.Name, "mode", textValue(org.Spec.Mode)), inventoryFact("group", s.Group.ID, s.Group.Name, "importLatch", flagValue(isImported(org.Labels)))}
	clientRoles := []string{}
	for _, mapping := range org.Spec.ClientRoles {
		for _, role := range mapping.Roles {
			clientRoles = append(clientRoles, mapping.Client+"/"+role)
		}
	}
	desired = append(desired, inventoryFact("group", s.Group.ID, s.Group.Name, "clientRoles", setValue(clientRoles)), inventoryFact("group", s.Group.ID, s.Group.Name, "brokerEndpoints", setValue([]string{org.Spec.IdentityProvider})))
	if s.Organization != nil {
		native := s.Organization
		item.ids = append(item.ids, native.ID)
		organizationCandidateOwner(item, "organization", native.ID, native.Name, native.Attributes, org, normalize)
		item.observation.Facts = append(item.observation.Facts, inventoryFact("organization", native.ID, native.Name, "name", textValue(native.Name)), inventoryFact("organization", native.ID, native.Name, "alias", textValue(native.Alias)), inventoryFact("organization", native.ID, native.Name, "enabled", flagValue(native.Enabled)), inventoryFact("organization", native.ID, native.Name, "brokerEndpoints", setValue(s.Links)))
		domains := []string{}
		for _, domain := range native.Domains {
			domains = append(domains, domain.Name+"/verified="+boolText(domain.Verified))
		}
		item.observation.Facts = append(item.observation.Facts, inventoryFact("organization", native.ID, native.Name, "domains", setValue(domains)))
		desired = append(desired, inventoryFact("organization", native.ID, native.Name, "alias", textValue(alias)), inventoryFact("organization", native.ID, native.Name, "name", textValue(org.Spec.Name)), inventoryFact("organization", native.ID, native.Name, "domains", setValue(org.Spec.Domains)))
	}
	provider.ObjectIDs = item.ids
	if parentID != "" {
		provider.ObjectIDs = append(provider.ObjectIDs, parentID)
	}
	return candidateStatus(adoption.Build(target, provider, item.observation, desired))
}

func organizationCandidateOwner(item *adoptionInventoryItem, domain, id, name string, attrs map[string][]string, org *api.HankoOrganization, normalize bool) {
	owner, class := "unmarked", adoption.Supported
	if !keycloak.OrganizationUnmarked(attrs) {
		receipt := attrs[adoption.ReceiptKey]
		if len(receipt) == 1 && keycloak.OrganizationExactReceipt(attrs, org.Name, org.Namespace, string(org.UID), receipt[0]) {
			// Existing exact target ownership and unmarked state are both safe
			// acquisition preconditions. Canonicalize only this target's envelope
			// so partial checkpoint recovery keeps the same reviewed hash.
			owner = "unmarked"
		} else if keycloak.OrganizationOwned(attrs, org.Name, org.Namespace, string(org.UID)) && len(receipt) == 0 {
			owner = "unmarked"
		} else {
			owner, class = "foreign", adoption.Conflicting
		}
	}
	f := inventoryFact(domain, id, name, "owner", textValue(owner))
	f.Classification = class
	item.observation.Facts = append(item.observation.Facts, f)
	for key, values := range attrs {
		if adoption.ReservedAttribute(key) {
			continue
		}
		if key == "trunx_slug" && len(values) == 1 && values[0] == orgSlug(org) {
			item.observation.Facts = append(item.observation.Facts, inventoryFact(domain, id, name, "attributes", setValue([]string{key + "=" + values[0]})))
		} else if keycloak.QualifiedOrganizationPublicAttribute(key, values) {
			fact := inventoryFact(domain, id, name, "nativeLocale", textValue(values[0]))
			fact.Classification = adoption.Preserved
			fact.RoundTrip = adoption.PreservedNative
			item.observation.Facts = append(item.observation.Facts, fact)
		} else {
			item.native("nativePresence", "unqualified provider attributes are excluded from canonical evidence", true)
		}
	}
}

var errOrganizationCleanupConflict = errors.New("organization cleanup would destroy foreign state")
