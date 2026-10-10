package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
)

const (
	orgFinalizerName           = "hanko.sh/organization-cleanup"
	orgOwnerNameAttribute      = organization.OwnerName
	orgOwnerNamespaceAttribute = organization.OwnerNamespace
	orgOwnerUIDAttribute       = organization.OwnerUID
)

var (
	errOrganizationGroupOwnership = errors.New("organization group ownership conflict")
	errRootOrganizationOwnership  = errors.New("root organization ownership conflict")
	errProjectorUnavailable       = hankoapi.ErrProjectorUnavailable
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
	APIReader      client.Reader
	ProtectedRealm string
	Scheme         *runtime.Scheme
	Pool           *keycloak.Pool
	Recorder       events.EventRecorder
	// Positions projects the reconciled Keycloak group into the hankoShell API model
	// consumed by hankoShell and product-side ADK clients.
	ProjectionMode hankoapi.ProjectionMode
	Positions      interface {
		EnsurePosition(context.Context, string, hankoapi.PositionSpec) (string, error)
		DeletePosition(context.Context, string, string) error
	}
}

func (r *HankoOrganizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var org hankoshv1alpha1.HankoOrganization
	if err := r.Get(ctx, req.NamespacedName, &org); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	kc := kcForObject(r.Pool, org.Namespace, org.Labels)
	if handled, result, err := r.reconcileOrganizationAcquisition(ctx, &org, kc); handled {
		return result, err
	}
	if effectiveOrganizationMode(&org) == ModeObserve {
		return r.reconcileOrganizationObserve(ctx, &org)
	}
	if err := validateOrganizationAuthorityRoles(&org, r.ProtectedRealm); err != nil {
		if !org.DeletionTimestamp.IsZero() {
			return r.releaseInvalidOrganization(ctx, &org, err.Error())
		}
		patch := client.MergeFrom(org.DeepCopy())
		org.Status.Phase = "Error"
		org.Status.ObservedGeneration = org.Generation
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ReservedAuthorityRole", err.Error())
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}

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
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		if isReservedAuthorityRoleViolation(err) {
			return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("verify organization authority roles: %w", err)
	}

	// ── Deletion path ─────────────────────────────────────────────────────────
	if !org.DeletionTimestamp.IsZero() {
		if err := r.discoverOrganizationDeletionReferences(ctx, &org, kc); err != nil {
			if isOrganizationProviderSecurityViolation(err) {
				return r.releaseInvalidOrganization(ctx, &org, "provider ownership conflict")
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
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
	org.Status.ObservedGeneration = org.Generation
	r.initializeProjectionCondition(&org)

	// ── Reject domains on internal nodes ──────────────────────────────────────
	// Isolation (alias + domains) is a property of the root alone; an internal
	// node declaring domains is a modelling error that must stay visible instead
	// of being silently dropped.
	if org.Spec.ParentRef != "" && (len(org.Spec.Domains) > 0 || org.Spec.IdentityProvider != "") {
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "InvalidSpec", "domains and identityProvider are only valid on a root organization (empty parentRef)")
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, nil
	}

	// ── Resolve parent group (multi-level hierarchy) ──────────────────────────
	parentID, parentPath, err := r.resolveProviderParent(ctx, &org)
	if err != nil {
		org.Status.Phase = "Pending"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ParentPending", err.Error())
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
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
		RequireOwnership:    true,
		PreserveAdopted:     true,
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
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("ensure group %q: %w", org.Spec.Name, err)
	}

	org.Status.GroupID = groupID
	org.Status.GroupPath = organizationGroupPath(spec.ParentPath, org.Spec.Name)

	// ── Map realm roles onto the group ────────────────────────────────────────
	if err := kc.AssignRealmRolesToGroup(ctx, org.Spec.RealmRef, groupID, org.Spec.Roles); err != nil {
		org.Status.Phase = "Error"
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "RolesFailed", err.Error())
		if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("map roles to group %q: %w", org.Spec.Name, err)
	}

	// ── Map client roles onto the group (permissions per application) ─────────
	for _, cr := range org.Spec.ClientRoles {
		if err := kc.AssignClientRolesToGroup(ctx, org.Spec.RealmRef, groupID, cr.Client, cr.Roles); err != nil {
			org.Status.Phase = "Error"
			setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "ClientRolesFailed", err.Error())
			if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
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
		org.Status.OrgID = orgID
		if err != nil {
			if errors.Is(err, keycloak.ErrOrganizationOwnershipConflict) {
				return r.recordOrganizationProviderSecurityError(ctx, &org, patch, fmt.Errorf("%w: %v", errRootOrganizationOwnership, err))
			}
			org.Status.Phase = "Error"
			setCondition(&org.Status.Conditions, "Organization", metav1.ConditionFalse, "OrganizationFailed", "Keycloak organization reconciliation failed")
			setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "OrganizationFailed", "Keycloak organization reconciliation failed")
			if patchErr := r.patchOrganizationStatus(ctx, &org, patch); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("reconcile root organization %q: %w", org.Spec.Name, err)
		}
		setCondition(&org.Status.Conditions, "Organization", metav1.ConditionTrue, "Reconciled", "tenant root present as Keycloak organization")
	}

	// Provider success is recorded independently of the optional API call.
	org.Status.OrgID = orgID
	org.Status.LastReconciled = &now
	setCondition(&org.Status.Conditions, "Synced", metav1.ConditionTrue, "Reconciled", "organization provider state reconciled")
	if r.ProjectionMode == hankoapi.ProjectionDisabled {
		org.Status.Phase = "Ready"
		return r.finishOrganization(ctx, &org, patch, requeueWithJitter())
	}
	if r.ProjectionMode != hankoapi.ProjectionEnabled || r.Positions == nil {
		return r.projectionFailure(ctx, &org, patch, "ProjectorUnavailable")
	}
	parentPositionID, err := r.resolveProjectionParent(ctx, &org)
	if err != nil {
		org.Status.Phase = "Pending"
		setCondition(&org.Status.Conditions, "Projection", metav1.ConditionFalse, "ParentProjectionPending", "parent platform projection is not ready")
		return r.finishOrganization(ctx, &org, patch, requeueOnError)
	}
	positionID, err := r.Positions.EnsurePosition(ctx, org.Spec.RealmRef, hankoapi.PositionSpec{
		Title: org.Spec.Name, ParentID: parentPositionID, GroupID: groupID, RoleIDs: org.Spec.Roles,
	})
	if err != nil {
		reason := "ProjectionFailed"
		if errors.Is(err, errProjectorUnavailable) {
			reason = "ProjectorUnavailable"
		}
		return r.projectionFailure(ctx, &org, patch, reason)
	}
	if positionID == "" {
		return r.projectionFailure(ctx, &org, patch, "ProjectionFailed")
	}
	org.Status.PositionID = positionID
	org.Status.Phase = "Ready"
	setCondition(&org.Status.Conditions, "Projection", metav1.ConditionTrue, "Reconciled", "organization platform projection reconciled")
	return r.finishOrganization(ctx, &org, patch, requeueWithJitter())
}

func (r *HankoOrganizationReconciler) releaseInvalidOrganization(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, _ string) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		return ctrl.Result{}, nil
	}
	// A provider ownership conflict cannot be turned into completed cleanup
	// by losing Kubernetes status. Only explicit Observe releases lifecycle
	// consent without provider deletion.
	patch := client.MergeFrom(org.DeepCopy())
	org.Status.Phase = "Error"
	setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, "CleanupConflict", "current aggregate ownership does not authorize cleanup")
	return ctrl.Result{RequeueAfter: requeueOnError}, r.patchOrganizationStatus(ctx, org, patch)
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
	if org.Status.GroupID != "" {
		group, err := kc.GetGroup(ctx, org.Spec.RealmRef, org.Status.GroupID)
		if err != nil {
			if !keycloak.IsNotFound(err) {
				return err
			}
		} else {
			if !keycloak.GroupMatchesOwnership(group, organizationGroupOwnershipAttributes(org), "") {
				return errOrganizationGroupOwnership
			}
			if err := validateExistingOrganizationGroupAuthority(ctx, org, r.ProtectedRealm, kc, group); err != nil {
				return err
			}
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
		if !keycloak.OrganizationMatchesOwnership(organization, organizationGroupOwnershipAttributes(org), "") {
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
	if patchErr := r.patchOrganizationStatus(ctx, org, patch); patchErr != nil {
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
	var realm hankoshv1alpha1.HankoRealm
	realmErr := r.organizationReader().Get(ctx, client.ObjectKey{Namespace: org.Namespace, Name: org.Spec.RealmRef}, &realm)
	if realmErr != nil && client.IgnoreNotFound(realmErr) != nil {
		return "", realmErr
	}
	external := realmErr == nil && isImported(realm.Labels)
	native, err := kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(org))
	if err != nil && (external || !keycloak.IsNotFound(err)) {
		return "", err
	}
	adopted := native != nil && len(native.Attributes["hanko.sh/adoption-receipt"]) != 0
	if external || adopted {
		enabled, err := kc.InventoryOrganizationsEnabled(ctx, org.Spec.RealmRef)
		if err != nil || !enabled {
			return "", errors.New("organizations must already be enabled on an external or adopted realm")
		}
	} else if err := kc.EnsureOrganizationsEnabled(ctx, org.Spec.RealmRef); err != nil {
		return "", err
	}
	orgID, err := kc.EnsureOrganization(ctx, org.Spec.RealmRef, keycloak.OrganizationSpec{
		Alias:               orgSlug(org),
		Name:                org.Spec.Name,
		Domains:             org.Spec.Domains,
		Attributes:          organizationGroupOwnershipAttributes(org),
		OwnershipAttributes: organizationGroupOwnershipAttributes(org),
		RequireOwnership:    true,
		PreserveAdopted:     true,
	})
	if err != nil {
		return "", err
	}
	link := kc.EnsureOrganizationIdentityProvider
	if adopted {
		link = kc.EnsureOrganizationIdentityProviderAdditive
	}
	if err := link(ctx, org.Spec.RealmRef, orgID, org.Spec.IdentityProvider); err != nil {
		return orgID, fmt.Errorf("link identity provider %q: %w", org.Spec.IdentityProvider, err)
	}
	return orgID, nil
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
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
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
