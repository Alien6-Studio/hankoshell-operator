package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func organizationCleanupReceipt(org *api.HankoOrganization, attrs map[string][]string) (string, error) {
	values, present := attrs[adoption.ReceiptKey]
	if !present {
		return "", nil
	}
	if len(values) != 1 {
		return "", errOrganizationCleanupConflict
	}
	proof, err := adoption.ParseReceipt(values[0])
	if err != nil || proof.TargetKind != "HankoOrganization" || proof.TargetUID != string(org.UID) || !keycloak.OrganizationExactReceipt(attrs, org.Name, org.Namespace, string(org.UID), values[0]) {
		return "", errOrganizationCleanupConflict
	}
	return values[0], nil
}

func (r *HankoOrganizationReconciler) validateAdoptedOrganizationCleanup(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client) error {
	if !acquisitionCurrentTarget(ctx, r.organizationReader(), org, true) {
		return errOrganizationCleanupConflict
	}
	if err := r.refreshOrganizationCleanupIdentities(ctx, org, kc); err != nil {
		return err
	}
	groupReceipt := ""
	if org.Status.GroupID != "" {
		group, err := kc.GetGroup(ctx, org.Spec.RealmRef, org.Status.GroupID)
		if err != nil && !keycloak.IsNotFound(err) {
			return err
		}
		if err == nil {
			groupReceipt, err = organizationCleanupReceipt(org, group.Attributes)
			if err != nil {
				return err
			}
			if groupReceipt != "" {
				if err := kc.CheckAdoptedOrganizationRepresentation(ctx, org.Spec.RealmRef, group.ID, false, organizationGroupOwnershipAttributes(org)); err != nil {
					return errOrganizationCleanupConflict
				}
				if err := r.validateAdoptedGroupCleanup(ctx, org, kc, group); err != nil {
					return err
				}
			}
		}
	}
	if org.Status.OrgID != "" {
		native, err := kc.GetOrganization(ctx, org.Spec.RealmRef, org.Status.OrgID)
		if err != nil && !keycloak.IsNotFound(err) {
			return err
		}
		if err == nil {
			receipt, err := organizationCleanupReceipt(org, native.Attributes)
			if err != nil {
				return err
			}
			if groupReceipt != "" && receipt == "" || receipt != "" && org.Status.GroupID != "" && groupReceipt == "" {
				return errOrganizationCleanupConflict
			}
			if receipt != "" {
				if err := kc.CheckAdoptedOrganizationRepresentation(ctx, org.Spec.RealmRef, native.ID, true, organizationGroupOwnershipAttributes(org)); err != nil {
					return errOrganizationCleanupConflict
				}
				if groupReceipt != "" && receipt != groupReceipt || native.Alias != orgSlug(org) {
					return errOrganizationCleanupConflict
				}
				members, err := kc.HasOrganizationMembers(ctx, org.Spec.RealmRef, native.ID)
				if err != nil {
					return err
				}
				links, err := kc.OrganizationIdentityProviderAliases(ctx, org.Spec.RealmRef, native.ID)
				if err != nil {
					return err
				}
				if members {
					return errOrganizationCleanupConflict
				}
				for _, alias := range links {
					if alias != org.Spec.IdentityProvider {
						return errOrganizationCleanupConflict
					}
				}
			}
		}
	}
	return nil
}

func (r *HankoOrganizationReconciler) validateAdoptedGroupCleanup(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client, group *keycloak.Group) error {
	path, _, _, err := organizationLifecyclePath(ctx, r.organizationReader(), kc, org, true)
	if err != nil || group.Path != path {
		return errOrganizationCleanupConflict
	}
	children, err := kc.HasGroupChildren(ctx, org.Spec.RealmRef, group.ID)
	if err != nil {
		return err
	}
	if children {
		return errOrganizationCleanupConflict
	}
	members, err := kc.HasGroupMembers(ctx, org.Spec.RealmRef, group.ID)
	if err != nil {
		return err
	}
	if members {
		return errOrganizationCleanupConflict
	}
	clientRoles := map[string][]string{}
	for _, mapping := range org.Spec.ClientRoles {
		clientRoles[mapping.Client] = append(clientRoles[mapping.Client], mapping.Roles...)
	}
	within, err := kc.GroupRoleMappingsWithin(ctx, org.Spec.RealmRef, group.ID, org.Spec.Roles, clientRoles)
	if err != nil {
		return err
	}
	if !within {
		return errOrganizationCleanupConflict
	}
	return nil
}

// Status UUIDs are lookup history. Resolve the current lifecycle boundary even
// when status was lost or forged, including partially completed cleanup.
func (r *HankoOrganizationReconciler) refreshOrganizationCleanupIdentities(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client) error {
	path, _, _, err := organizationLifecyclePath(ctx, r.organizationReader(), kc, org, true)
	if err != nil {
		return errOrganizationCleanupConflict
	}
	group, err := kc.GetGroupByPath(ctx, org.Spec.RealmRef, path)
	if err != nil && !keycloak.IsNotFound(err) {
		return err
	}
	org.Status.GroupID = ""
	if err == nil && group != nil {
		org.Status.GroupID, org.Status.GroupPath = group.ID, group.Path
	}
	if org.Spec.ParentRef != "" {
		org.Status.OrgID = ""
		return nil
	}
	native, err := kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(org))
	if err != nil {
		return err
	}
	org.Status.OrgID = ""
	if native != nil {
		org.Status.OrgID = native.ID
	}
	return nil
}
