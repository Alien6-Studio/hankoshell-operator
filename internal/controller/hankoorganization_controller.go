package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const (
	orgFinalizerName           = "hanko.sh/organization-cleanup"
	orgOwnerNameAttribute      = "hanko.sh/organization-name"
	orgOwnerNamespaceAttribute = "hanko.sh/organization-namespace"
	orgOwnerUIDAttribute       = "hanko.sh/organization-uid"
)

var (
	errOrganizationGroupOwnership = errors.New("organization group ownership conflict")
	errRootOrganizationOwnership  = errors.New("root organization ownership conflict")
	errProjectorUnavailable       = errors.New("hanko organization API projector is not configured")
)

// HankoOrganizationReconciler reconciles HankoOrganization objects into
// Keycloak groups whose realm-role mappings become the members' effective
// roles, exposed to Trunx via claims (HKX-09).
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoorganizations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoorganizations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoorganizations/finalizers,verbs=update
type HankoOrganizationReconciler struct {
	client.Client
	ProtectedRealm string
	Scheme         *runtime.Scheme
	Pool           *keycloak.Pool
	Recorder       events.EventRecorder
	// Positions projects the reconciled Keycloak group into the hankoShell API model
	// consumed by hankoShell and product-side ADK clients.
	Positions interface {
		EnsurePosition(context.Context, string, hankoapi.PositionSpec) (string, error)
		DeletePosition(context.Context, string, string) error
	}
}

func (r *HankoOrganizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var org hankoshv1alpha1.HankoOrganization
	if err := r.Get(ctx, req.NamespacedName, &org); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err := validateOrganizationAuthorityRoles(&org, r.ProtectedRealm); err != nil {
		if !org.DeletionTimestamp.IsZero() {
			return r.releaseInvalidOrganization(ctx, &org, err.Error())
		}
		patch := client.MergeFrom(org.DeepCopy())
		org.Status.Phase = "Error"
		org.Status.ObservedGeneration = org.Generation
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ReservedAuthorityRole", err.Error())
		if patchErr := r.Status().Patch(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}

	kc := kcForObject(r.Pool, org.Namespace, org.Labels)
	if err := validateOrganizationEffectiveAuthorityRoles(ctx, &org, r.ProtectedRealm, kc); err != nil {
		if !org.DeletionTimestamp.IsZero() {
			if isReservedAuthorityRoleViolation(err) {
				return r.releaseInvalidOrganization(ctx, &org, err.Error())
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify organization authority roles before deletion: %w", err)
		}
		patch := client.MergeFrom(org.DeepCopy())
		org.Status.Phase = "Error"
		org.Status.ObservedGeneration = org.Generation
		reason := "AuthorityRoleLookupFailed"
		if isReservedAuthorityRoleViolation(err) {
			reason = "ReservedAuthorityRole"
		}
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
		if patchErr := r.Status().Patch(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		if isReservedAuthorityRoleViolation(err) {
			return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify organization authority roles: %w", err)
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !org.DeletionTimestamp.IsZero() {
		if err := r.validateOrganizationResourcesBeforeDeletion(ctx, &org, kc); err != nil {
			if isOrganizationProviderSecurityViolation(err) {
				return r.releaseInvalidOrganization(ctx, &org, err.Error())
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify organization group before deletion: %w", err)
		}
		return r.reconcileOrgDeletion(ctx, &org, kc)
	}

	// ── Ensure finalizer ──────────────────────────────────────────────────────
	if err := r.ensureOrgFinalizer(ctx, &org); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(org.DeepCopy())
	now := metav1.Now()

	// ── Reject domains on internal nodes ──────────────────────────────────────
	// Isolation (alias + domains) is a property of the root alone; an internal
	// node declaring domains is a modelling error that must stay visible instead
	// of being silently dropped.
	if org.Spec.ParentRef != "" && (len(org.Spec.Domains) > 0 || org.Spec.IdentityProvider != "") {
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "InvalidSpec", "domains and identityProvider are only valid on a root organization (empty parentRef)")
		_ = r.Status().Patch(ctx, &org, patch)
		return ctrl.Result{}, nil
	}

	// ── Resolve parent group (multi-level hierarchy) ──────────────────────────
	parentID, parentPath, parentPositionID, err := r.resolveParent(ctx, &org)
	if err != nil {
		org.Status.Phase = "Pending"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ParentPending", err.Error())
		_ = r.Status().Patch(ctx, &org, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}

	// ── Ensure the Keycloak group ─────────────────────────────────────────────
	ownershipAttributes := organizationGroupOwnershipAttributes(&org)
	attributes := map[string][]string{"trunx_slug": {orgSlug(&org)}}
	for key, value := range ownershipAttributes {
		attributes[key] = value
	}
	protectedGroup := strings.TrimSpace(r.ProtectedRealm) != "" && strings.TrimSpace(org.Spec.RealmRef) == strings.TrimSpace(r.ProtectedRealm)
	spec := keycloak.GroupSpec{
		Name:                org.Spec.Name,
		ParentID:            parentID,
		ParentPath:          parentPath,
		Attributes:          attributes,
		OwnershipAttributes: ownershipAttributes,
		LegacyOwnedID:       org.Status.GroupID,
		RequireOwnership:    protectedGroup,
	}
	if protectedGroup {
		if org.Spec.ParentRef == "" {
			existingOrganization, lookupErr := kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(&org))
			if lookupErr != nil {
				return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("look up root organization before adoption: %w", lookupErr))
			}
			if existingOrganization != nil && !keycloak.OrganizationMatchesOwnership(existingOrganization, ownershipAttributes, org.Status.OrgID) {
				return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("%w: Keycloak organization alias %q in fleet authority realm %q is not owned by HankoOrganization %s/%s", errRootOrganizationOwnership, orgSlug(&org), org.Spec.RealmRef, org.Namespace, org.Name))
			}
		}
		existing, lookupErr := kc.GetGroupByPath(ctx, org.Spec.RealmRef, organizationGroupPath(parentPath, org.Spec.Name))
		if lookupErr == nil {
			if err := validateExistingOrganizationGroupAuthority(ctx, &org, r.ProtectedRealm, kc, existing); err != nil {
				return r.recordOrganizationProviderSecurityError(ctx, &org, patch, err)
			}
		} else if !keycloak.IsNotFound(lookupErr) {
			return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("look up organization group before adoption: %w", lookupErr))
		}
	}
	groupID, err := kc.EnsureGroup(ctx, org.Spec.RealmRef, spec)
	if err != nil {
		if errors.Is(err, keycloak.ErrGroupOwnershipConflict) {
			return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("%w: %v", errOrganizationGroupOwnership, err))
		}
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "GroupFailed", err.Error())
		_ = r.Status().Patch(ctx, &org, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("ensure group %q: %w", org.Spec.Name, err)
	}

	// ── Map realm roles onto the group ────────────────────────────────────────
	if err := kc.AssignRealmRolesToGroup(ctx, org.Spec.RealmRef, groupID, org.Spec.Roles); err != nil {
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "RolesFailed", err.Error())
		_ = r.Status().Patch(ctx, &org, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("map roles to group %q: %w", org.Spec.Name, err)
	}

	// ── Map client roles onto the group (permissions per application) ─────────
	for _, cr := range org.Spec.ClientRoles {
		if err := kc.AssignClientRolesToGroup(ctx, org.Spec.RealmRef, groupID, cr.Client, cr.Roles); err != nil {
			org.Status.Phase = "Error"
			setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ClientRolesFailed", err.Error())
			_ = r.Status().Patch(ctx, &org, patch)
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("map client roles of %q to group %q: %w", cr.Client, org.Spec.Name, err)
		}
	}

	// ── Reconcile the tenant root as a Keycloak Organization ──────────────────
	// The root alone carries isolation: a KC Organization holds the stable
	// alias and owned domains (and later the org-scoped IdP), while the group
	// tree keeps expressing structure. Internal nodes skip this entirely.
	orgID := org.Status.OrgID
	if org.Spec.ParentRef == "" {
		orgID, err = r.reconcileRootOrganization(ctx, &org, kc)
		if err != nil {
			if errors.Is(err, keycloak.ErrOrganizationOwnershipConflict) {
				return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("%w: %v", errRootOrganizationOwnership, err))
			}
			org.Status.Phase = "Error"
			setCondition(&org.Status.Conditions, "Organization", metav1.ConditionFalse, "OrganizationFailed", err.Error())
			_ = r.Status().Patch(ctx, &org, patch)
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("reconcile root organization %q: %w", org.Spec.Name, err)
		}
		setCondition(&org.Status.Conditions, "Organization", metav1.ConditionTrue, "Reconciled", "tenant root present as Keycloak organization")
	}

	// ── Project the same node into Hanko's organization API ───────────────────
	// hankoShell reads positions, not Keycloak groups. Treating the group-only
	// state as Ready caused a split-brain where the CRD was green but the UI was
	// empty. A missing projector now fails closed and remains observable.
	if r.Positions == nil {
		org.Status.Phase = "Error"
		// Keycloak reconciliation already succeeded above; rewrite Synced so a
		// failure message from an earlier incident cannot survive as stale
		// evidence next to the real cause carried by Projection.
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "organization group present in Keycloak")
		setCondition(&org.Status.Conditions, "Projection", metav1.ConditionFalse, "ProjectorUnavailable", "Hanko organization API projector is not configured")
		_ = r.Status().Patch(ctx, &org, patch)
		log.FromContext(ctx).Error(errProjectorUnavailable, "organization projection failing closed", "org", org.Spec.Name, "realm", org.Spec.RealmRef)
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}
	positionID, err := r.Positions.EnsurePosition(ctx, org.Spec.RealmRef, hankoapi.PositionSpec{
		Title: org.Spec.Name, ParentID: parentPositionID, GroupID: groupID, RoleIDs: org.Spec.Roles,
	})
	if err != nil {
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Projection", metav1.ConditionFalse, "ProjectionFailed", err.Error())
		_ = r.Status().Patch(ctx, &org, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("project organization position %q: %w", org.Spec.Name, err)
	}

	org.Status.Phase = "Ready"
	org.Status.OrgID = orgID
	org.Status.GroupID = groupID
	org.Status.GroupPath = organizationGroupPath(spec.ParentPath, org.Spec.Name)
	org.Status.PositionID = positionID
	org.Status.ObservedGeneration = org.Generation
	org.Status.LastReconciled = &now
	setCondition(&org.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "organization group present in Keycloak")
	setCondition(&org.Status.Conditions, "Projection", metav1.ConditionTrue, "Reconciled", "organization position present in hankoShell API")

	if err := r.Status().Patch(ctx, &org, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoOrganization synced", "org", org.Spec.Name, "realm", org.Spec.RealmRef, "group", groupID)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoOrganizationReconciler) releaseInvalidOrganization(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, message string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		return ctrl.Result{}, nil
	}
	controllerutil.RemoveFinalizer(org, orgFinalizerName)
	if err := r.Update(ctx, org); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove invalid organization finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released unsafe organization without mutating providers", "organization", org.Name, "reason", message)
	return ctrl.Result{}, nil
}

func organizationGroupOwnershipAttributes(org *hankoshv1alpha1.HankoOrganization) map[string][]string {
	attributes := map[string][]string{
		orgOwnerNameAttribute:      {org.Name},
		orgOwnerNamespaceAttribute: {org.Namespace},
	}
	if org.UID != "" {
		attributes[orgOwnerUIDAttribute] = []string{string(org.UID)}
	}
	return attributes
}

func organizationGroupPath(parentPath, name string) string {
	if strings.TrimSpace(parentPath) == "" {
		return "/" + name
	}
	return strings.TrimRight(parentPath, "/") + "/" + name
}

func isOrganizationProviderSecurityViolation(err error) bool {
	return isReservedAuthorityRoleViolation(err) ||
		errors.Is(err, errOrganizationGroupOwnership) || errors.Is(err, keycloak.ErrGroupOwnershipConflict) ||
		errors.Is(err, errRootOrganizationOwnership) || errors.Is(err, keycloak.ErrOrganizationOwnershipConflict)
}

func validateExistingOrganizationGroupAuthority(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, protectedRealm string, kc *keycloak.Client, group *keycloak.Group) error {
	if strings.TrimSpace(protectedRealm) == "" || strings.TrimSpace(org.Spec.RealmRef) != strings.TrimSpace(protectedRealm) {
		return nil
	}
	if !keycloak.GroupMatchesOwnership(group, organizationGroupOwnershipAttributes(org), org.Status.GroupID) {
		return fmt.Errorf("%w: Keycloak group %q in fleet authority realm %q is not owned by HankoOrganization %s/%s", errOrganizationGroupOwnership, group.Path, org.Spec.RealmRef, org.Namespace, org.Name)
	}
	roles, err := kc.GetGroupEffectiveRoleClosure(ctx, org.Spec.RealmRef, group.ID)
	if err != nil {
		return fmt.Errorf("inspect effective roles of existing organization group %q: %w", group.ID, err)
	}
	for _, role := range roles {
		if isReservedAuthorityRole(role.Name) {
			return reservedAuthorityRoleError(protectedRealm, org.Spec.RealmRef,
				fmt.Sprintf("existing group %q adopted by HankoOrganization %q", group.Path, org.Name), role.Name)
		}
	}
	return nil
}

func (r *HankoOrganizationReconciler) validateOrganizationResourcesBeforeDeletion(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, kc *keycloak.Client) error {
	if strings.TrimSpace(r.ProtectedRealm) == "" || strings.TrimSpace(org.Spec.RealmRef) != strings.TrimSpace(r.ProtectedRealm) {
		return nil
	}
	if org.Status.GroupID != "" {
		group, err := kc.GetGroup(ctx, org.Spec.RealmRef, org.Status.GroupID)
		if err != nil {
			if !keycloak.IsNotFound(err) {
				return err
			}
		} else if err := validateExistingOrganizationGroupAuthority(ctx, org, r.ProtectedRealm, kc, group); err != nil {
			return err
		}
	}
	if org.Status.OrgID != "" {
		organization, err := kc.GetOrganization(ctx, org.Spec.RealmRef, org.Status.OrgID)
		if err != nil {
			if keycloak.IsNotFound(err) {
				return nil
			}
			return err
		}
		if !keycloak.OrganizationMatchesOwnership(organization, organizationGroupOwnershipAttributes(org), org.Status.OrgID) {
			return fmt.Errorf("%w: Keycloak organization %q in fleet authority realm %q is not owned by HankoOrganization %s/%s", errRootOrganizationOwnership, organization.ID, org.Spec.RealmRef, org.Namespace, org.Name)
		}
	}
	return nil
}

func (r *HankoOrganizationReconciler) recordOrganizationProviderSecurityError(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, patch client.Patch, err error) (ctrl.Result, error) {
	org.Status.Phase = "Error"
	org.Status.ObservedGeneration = org.Generation
	reason := "GroupAuthorityLookupFailed"
	if errors.Is(err, errOrganizationGroupOwnership) || errors.Is(err, keycloak.ErrGroupOwnershipConflict) {
		reason = "GroupOwnershipConflict"
	} else if errors.Is(err, errRootOrganizationOwnership) || errors.Is(err, keycloak.ErrOrganizationOwnershipConflict) {
		reason = "OrganizationOwnershipConflict"
	} else if isReservedAuthorityRoleViolation(err) {
		reason = "ReservedAuthorityRole"
	}
	setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, reason, err.Error())
	if patchErr := r.Status().Patch(ctx, org, patch); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if isOrganizationProviderSecurityViolation(err) {
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, err
}

// reconcileRootOrganization ensures the realm accepts organizations and that a
// Keycloak Organization exists for this tenant root, returning its UUID. The
// alias is the node's slug so the token "organization" claim key stays stable
// even when the display name changes.
func (r *HankoOrganizationReconciler) reconcileRootOrganization(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, kc *keycloak.Client) (string, error) {
	if err := kc.EnsureOrganizationsEnabled(ctx, org.Spec.RealmRef); err != nil {
		return "", err
	}
	orgID, err := kc.EnsureOrganization(ctx, org.Spec.RealmRef, keycloak.OrganizationSpec{
		Alias:               orgSlug(org),
		Name:                org.Spec.Name,
		Domains:             org.Spec.Domains,
		Attributes:          organizationGroupOwnershipAttributes(org),
		OwnershipAttributes: organizationGroupOwnershipAttributes(org),
		LegacyOwnedID:       org.Status.OrgID,
		RequireOwnership:    strings.TrimSpace(r.ProtectedRealm) != "" && strings.TrimSpace(org.Spec.RealmRef) == strings.TrimSpace(r.ProtectedRealm),
	})
	if err != nil {
		return "", err
	}
	if err := kc.EnsureOrganizationIdentityProvider(ctx, org.Spec.RealmRef, orgID, org.Spec.IdentityProvider); err != nil {
		return "", fmt.Errorf("link identity provider %q: %w", org.Spec.IdentityProvider, err)
	}
	return orgID, nil
}

// resolveParent returns the Keycloak group ID and path of the parent
// organization. For a top-level organization it returns empty strings. An
// error signals the parent is not yet reconciled and the caller should requeue.
func (r *HankoOrganizationReconciler) resolveParent(ctx context.Context, org *hankoshv1alpha1.HankoOrganization) (string, string, string, error) {
	if org.Spec.ParentRef == "" {
		return "", "", "", nil
	}
	var parent hankoshv1alpha1.HankoOrganization
	key := types.NamespacedName{Namespace: org.Namespace, Name: org.Spec.ParentRef}
	if err := r.Get(ctx, key, &parent); err != nil {
		return "", "", "", fmt.Errorf("parent organization %q not found: %w", org.Spec.ParentRef, err)
	}
	if parent.Status.GroupID == "" || parent.Status.GroupPath == "" || parent.Status.PositionID == "" {
		return "", "", "", fmt.Errorf("parent organization %q not ready", org.Spec.ParentRef)
	}
	return parent.Status.GroupID, parent.Status.GroupPath, parent.Status.PositionID, nil
}

func (r *HankoOrganizationReconciler) reconcileOrgDeletion(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, kc *keycloak.Client) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		return ctrl.Result{}, nil
	}
	if r.Positions != nil && org.Status.PositionID != "" {
		if err := r.Positions.DeletePosition(ctx, org.Spec.RealmRef, org.Status.PositionID); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete organization position %q: %w", org.Spec.Name, err)
		}
	}
	if org.Status.GroupID != "" {
		if err := kc.DeleteGroup(ctx, org.Spec.RealmRef, org.Status.GroupID); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete group %q: %w", org.Spec.Name, err)
		}
	}
	if org.Status.OrgID != "" {
		if err := kc.DeleteOrganization(ctx, org.Spec.RealmRef, org.Status.OrgID); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("delete organization %q: %w", org.Spec.Name, err)
		}
	}
	controllerutil.RemoveFinalizer(org, orgFinalizerName)
	if err := r.Update(ctx, org); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove organization finalizer: %w", err)
	}
	log.FromContext(ctx).Info("organization group deleted", "org", org.Spec.Name)
	return ctrl.Result{}, nil
}

func (r *HankoOrganizationReconciler) ensureOrgFinalizer(ctx context.Context, org *hankoshv1alpha1.HankoOrganization) error {
	if controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		return nil
	}
	controllerutil.AddFinalizer(org, orgFinalizerName)
	if err := r.Update(ctx, org); err != nil {
		return fmt.Errorf("add organization finalizer: %w", err)
	}
	return nil
}

func (r *HankoOrganizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoOrganization{}).
		Complete(r)
}

// orgSlug returns the organization's slug, deriving it from the name when the
// spec leaves it empty.
func orgSlug(org *hankoshv1alpha1.HankoOrganization) string {
	if org.Spec.Slug != "" {
		return org.Spec.Slug
	}
	return deriveSlug(org.Spec.Name)
}

// deriveSlug lowercases a name and replaces runs of non-alphanumeric characters
// with single hyphens, trimming leading and trailing hyphens.
func deriveSlug(name string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastHyphen = false
		default:
			if !lastHyphen && b.Len() > 0 {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
