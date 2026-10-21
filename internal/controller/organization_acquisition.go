package controller

import (
	"context"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func organizationCheckpoint(attrs map[string][]string, org *api.HankoOrganization, receipt string) (acquired, safe bool) {
	if keycloak.OrganizationExactReceipt(attrs, org.Name, org.Namespace, string(org.UID), receipt) {
		return true, true
	}
	_, hasReceipt := attrs[adoption.ReceiptKey]
	return false, keycloak.OrganizationUnmarked(attrs) || !hasReceipt && keycloak.OrganizationOwned(attrs, org.Name, org.Namespace, string(org.UID))
}

func readOrganizationAcquisition(ctx context.Context, reader client.Reader, kc *keycloak.Client, org *api.HankoOrganization) (*keycloak.OrganizationOwnershipSnapshot, error) {
	path, _, _, err := organizationAdoptionPath(ctx, reader, kc, org)
	if err != nil {
		return nil, err
	}
	alias := ""
	if org.Spec.ParentRef == "" {
		alias = orgSlug(org)
	}
	return kc.ReadOrganizationOwnership(ctx, org.Spec.RealmRef, path, alias)
}

func (r *HankoOrganizationReconciler) reconcileOrganizationAcquisition(ctx context.Context, cached *api.HankoOrganization, writer *keycloak.Client) (bool, ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	reader := r.organizationReader()
	current := &api.HankoOrganization{}
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
	if effectiveOrganizationMode(current) == ModeManage {
		return r.organizationManageGate(ctx, current, writer, approval)
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
	before, err := readOrganizationAcquisition(ctx, reader, observer, current)
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionIncomplete")
	}
	receipt, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoOrganization", TargetUID: string(current.UID), CandidateHash: approval.CandidateHash}).Canonical()
	if err != nil {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionApprovalRequired")
	}
	groupAcquired, safe := organizationCheckpoint(before.Group.Attributes, current, receipt)
	nativeAcquired := before.Organization == nil
	if safe && before.Organization != nil {
		nativeAcquired, safe = organizationCheckpoint(before.Organization.Attributes, current, receipt)
	}
	if !safe {
		return adoptionResult(ctx, r.Client, current, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	candidate := readTargetCandidate(ctx, r.Client, reader, current, true)
	if reason := adoptionCandidateFailure(candidate, approval); reason != "" {
		state := "Conflict"
		if groupAcquired || before.Organization != nil && nativeAcquired {
			state, reason = "Partial", "AdoptionPartial"
		}
		return adoptionResult(ctx, r.Client, current, candidate, approval, state, reason)
	}
	if groupAcquired && nativeAcquired {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Verified", "AdoptionVerified")
	}
	origin, err := adoptionEndpointOrigin(writer.BaseURL())
	realm, realmErr := writer.GetRealm(ctx, current.Spec.RealmRef)
	if err != nil || realmErr != nil || origin != candidate.ProviderIdentity.Origin || realm.ID != candidate.ProviderIdentity.RealmID {
		return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", "AdoptionIdentityChanged")
	}
	for _, native := range []bool{false, true} {
		if !native && groupAcquired || native && nativeAcquired {
			continue
		}
		// Every remaining checkpoint has independent fresh writer/read-only
		// observations, target checks and canonical candidate recomputation.
		candidate = readTargetCandidate(ctx, r.Client, reader, current, true)
		fresh, err := readOrganizationAcquisition(ctx, reader, writer, current)
		if err != nil || !before.SameSemantics(fresh) || adoptionCandidateFailure(candidate, approval) != "" || !acquisitionTargetUnchanged(ctx, reader, current) {
			return adoptionResult(ctx, r.Client, current, candidate, approval, "Partial", "AdoptionPartial")
		}
		if validateOrganizationAuthorityRoles(current, r.ProtectedRealm) != nil || validateOrganizationEffectiveAuthorityRoles(ctx, current, r.ProtectedRealm, writer) != nil || validateExistingOrganizationGroupAuthority(ctx, current, r.ProtectedRealm, writer, &fresh.Group) != nil {
			return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", "AdoptionOwnershipConflict")
		}
		attrs := fresh.Group.Attributes
		if native {
			attrs = fresh.Organization.Attributes
		}
		acquired, safe := organizationCheckpoint(attrs, current, receipt)
		if !safe {
			return adoptionResult(ctx, r.Client, current, candidate, approval, "Conflict", "AdoptionOwnershipConflict")
		}
		if !acquired {
			_ = writer.MarkOrganizationMemberAdoption(ctx, current.Spec.RealmRef, fresh, native, current.Name, current.Namespace, string(current.UID), receipt)
		}
		after, err := readOrganizationAcquisition(ctx, reader, observer, current)
		if err != nil || !before.SameSemantics(after) || !acquisitionTargetUnchanged(ctx, reader, current) {
			return adoptionResult(ctx, r.Client, current, candidate, approval, "Partial", "AdoptionPartial")
		}
		attrs = after.Group.Attributes
		if native {
			attrs = after.Organization.Attributes
		}
		acquired, safe = organizationCheckpoint(attrs, current, receipt)
		if !acquired || !safe {
			return adoptionResult(ctx, r.Client, current, candidate, approval, "Partial", "AdoptionPartial")
		}
		before = after
	}
	verified := readTargetCandidate(ctx, r.Client, reader, current, true)
	if adoptionCandidateFailure(verified, approval) != "" {
		return adoptionResult(ctx, r.Client, current, verified, approval, "Partial", "AdoptionPartial")
	}
	return adoptionResult(ctx, r.Client, current, verified, approval, "Verified", "AdoptionVerified")
}

// The native root is checked before group lookup, preserving the existing
// collision boundary in the protected realm. Read failures hold reconciliation.
func (r *HankoOrganizationReconciler) organizationManageGate(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client, approval adoption.Approval) (bool, ctrl.Result, error) {
	fail := func(err error) (bool, ctrl.Result, error) {
		result, failure := r.recordOrganizationProviderSecurityError(ctx, org, client.MergeFrom(org.DeepCopy()), err)
		return true, result, failure
	}
	if org.Spec.ParentRef == "" {
		native, err := kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(org))
		if err != nil {
			// Ordinary Hanko-created realms may initialize the optional feature.
			// External realms and receipt-backed groups still fail before writes.
			var realm api.HankoRealm
			realmErr := r.organizationReader().Get(ctx, client.ObjectKey{Namespace: org.Namespace, Name: org.Spec.RealmRef}, &realm)
			if !keycloak.IsNotFound(err) || realmErr != nil && client.IgnoreNotFound(realmErr) != nil || realmErr == nil && isImported(realm.Labels) {
				return fail(err)
			}
		}
		if native != nil && len(native.Attributes[adoption.ReceiptKey]) != 0 {
			return r.authorizeAdoptedOrganizationManage(ctx, org, kc, approval)
		}
		if native != nil && !keycloak.OrganizationOwned(native.Attributes, org.Name, org.Namespace, string(org.UID)) {
			return fail(errRootOrganizationOwnership)
		}
	}
	path, _, _, err := organizationAdoptionPath(ctx, r.organizationReader(), kc, org)
	if err != nil {
		return fail(err)
	}
	group, err := kc.GetGroupByPath(ctx, org.Spec.RealmRef, path)
	if err != nil && !keycloak.IsNotFound(err) {
		return fail(err)
	}
	if group != nil && len(group.Attributes[adoption.ReceiptKey]) != 0 {
		return r.authorizeAdoptedOrganizationManage(ctx, org, kc, approval)
	}
	if approval.Requested {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "AdoptionUnsupported")
	}
	return false, ctrl.Result{}, nil
}

func (r *HankoOrganizationReconciler) authorizeAdoptedOrganizationManage(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client, approval adoption.Approval) (bool, ctrl.Result, error) {
	if org.Spec.Mode != ModeManage || isImported(org.Labels) {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "ExplicitManageRequired")
	}
	s, err := readOrganizationAcquisition(ctx, r.organizationReader(), kc, org)
	if err != nil {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "AdoptionIncomplete")
	}
	values := s.Group.Attributes[adoption.ReceiptKey]
	if len(values) != 1 {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Partial", "AdoptionPartial")
	}
	proof, err := adoption.ParseReceipt(values[0])
	if err != nil || proof.TargetKind != "HankoOrganization" || proof.TargetUID != string(org.UID) || !keycloak.OrganizationExactReceipt(s.Group.Attributes, org.Name, org.Namespace, string(org.UID), values[0]) || s.Organization != nil && !keycloak.OrganizationExactReceipt(s.Organization.Attributes, org.Name, org.Namespace, string(org.UID), values[0]) {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	if !s.QualifiedRoots() || !keycloak.OrganizationAttributesQualified(s.Group.Attributes) || s.Organization != nil && !keycloak.OrganizationAttributesQualified(s.Organization.Attributes) {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "ManagePreservationUnqualified")
	}
	_, parentID, _, err := organizationAdoptionPath(ctx, r.organizationReader(), kc, org)
	if err != nil || parentID != s.ParentID || !acquisitionTargetUnchanged(ctx, r.organizationReader(), org) {
		return adoptionResult(ctx, r.Client, org, nil, approval, "Conflict", "AdoptionIdentityChanged")
	}
	return false, ctrl.Result{}, nil
}
