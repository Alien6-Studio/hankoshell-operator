package controller

import (
	"context"
	"errors"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *HankoOrganizationReconciler) initializeProjectionCondition(org *api.HankoOrganization) {
	reason, message := "ProviderPending", "provider reconciliation precedes platform projection"
	if r.ProjectionMode == hankoapi.ProjectionDisabled {
		reason, message = "Disabled", "organization platform projection is disabled"
	}
	setCondition(&org.Status.Conditions, "Projection", metav1.ConditionUnknown, reason, message)
}

func (r *HankoOrganizationReconciler) patchOrganizationStatus(ctx context.Context, org *api.HankoOrganization, patch client.Patch) error {
	org.Status.ObservedGeneration = org.Generation
	synced := false
	for _, condition := range org.Status.Conditions {
		if condition.Type == "Synced" && condition.Status == metav1.ConditionTrue {
			synced = true
		}
	}
	if !synced {
		r.initializeProjectionCondition(org)
	}
	for i := range org.Status.Conditions {
		org.Status.Conditions[i].ObservedGeneration = org.Generation
	}
	return r.Status().Patch(ctx, org, patch)
}

func (r *HankoOrganizationReconciler) finishOrganization(ctx context.Context, org *api.HankoOrganization, patch client.Patch, retry time.Duration) (ctrl.Result, error) {
	if err := r.patchOrganizationStatus(ctx, org, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: retry}, nil
}

func (r *HankoOrganizationReconciler) projectionFailure(ctx context.Context, org *api.HankoOrganization, patch client.Patch, reason string) (ctrl.Result, error) {
	org.Status.Phase = "Error"
	// Never publish a remote error, response body, endpoint or credential.
	setCondition(&org.Status.Conditions, "Projection", metav1.ConditionFalse, reason, "configured organization platform projection did not complete")
	return r.finishOrganization(ctx, org, patch, requeueOnError)
}

func organizationConditionCurrent(org *api.HankoOrganization, kind string, status metav1.ConditionStatus) bool {
	for _, c := range org.Status.Conditions {
		if c.Type == kind && c.Status == status && c.ObservedGeneration == org.Generation {
			return true
		}
	}
	return false
}

func (r *HankoOrganizationReconciler) organizationParent(ctx context.Context, org *api.HankoOrganization) (*api.HankoOrganization, error) {
	parent := &api.HankoOrganization{}
	if org.Spec.ParentRef == org.Name {
		return nil, errors.New("organization cannot be its own parent")
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: org.Namespace, Name: org.Spec.ParentRef}, parent); err != nil {
		return nil, errors.New("parent organization is unavailable")
	}
	if !parent.DeletionTimestamp.IsZero() || parent.Spec.RealmRef != org.Spec.RealmRef {
		return nil, errors.New("parent organization is deleting or belongs to another realm")
	}
	return parent, nil
}

func (r *HankoOrganizationReconciler) resolveProviderParent(ctx context.Context, org *api.HankoOrganization) (string, string, error) {
	if org.Spec.ParentRef == "" {
		return "", "", nil
	}
	parent, err := r.organizationParent(ctx, org)
	if err != nil {
		return "", "", err
	}
	if parent.Status.GroupID == "" || parent.Status.GroupPath == "" || !organizationConditionCurrent(parent, "Synced", metav1.ConditionTrue) {
		return "", "", errors.New("parent provider state is not synchronized")
	}
	kc := kcForObject(r.Pool, org.Namespace, org.Labels)
	path, parentID, _, err := organizationAdoptionPath(ctx, r.organizationReader(), kc, org)
	if err != nil {
		return "", "", err
	}
	return parentID, strings.TrimSuffix(path, "/"+org.Spec.Name), nil
}

func (r *HankoOrganizationReconciler) resolveProjectionParent(ctx context.Context, org *api.HankoOrganization) (string, error) {
	if org.Spec.ParentRef == "" {
		return "", nil
	}
	parent, err := r.organizationParent(ctx, org)
	if err != nil {
		return "", err
	}
	if parent.Status.PositionID == "" || !organizationConditionCurrent(parent, "Projection", metav1.ConditionTrue) {
		return "", errors.New("parent platform projection is not synchronized")
	}
	return parent.Status.PositionID, nil
}

func (r *HankoOrganizationReconciler) discoverOrganizationDeletionReferences(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client) error {
	owner := organizationGroupOwnershipAttributes(org)
	if org.Status.GroupID == "" {
		_, path, err := r.resolveProviderParent(ctx, org)
		if err != nil {
			return err
		}
		group, err := kc.GetGroupByPath(ctx, org.Spec.RealmRef, organizationGroupPath(path, org.Spec.Name))
		if err != nil && !keycloak.IsNotFound(err) {
			return err
		}
		if err == nil {
			if !keycloak.GroupMatchesOwnership(group, owner, "") {
				return errOrganizationGroupOwnership
			}
			org.Status.GroupID, org.Status.GroupPath = group.ID, group.Path
		}
	}
	if org.Spec.ParentRef == "" && org.Status.OrgID == "" {
		native, err := kc.GetOrganizationByAlias(ctx, org.Spec.RealmRef, orgSlug(org))
		if err != nil {
			return err
		}
		if native != nil {
			if !keycloak.OrganizationMatchesOwnership(native, owner, "") {
				return errRootOrganizationOwnership
			}
			org.Status.OrgID = native.ID
		}
	}
	return nil
}

func (r *HankoOrganizationReconciler) reconcileOrgDeletion(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(org, orgFinalizerName) {
		return ctrl.Result{}, nil
	}
	patch := client.MergeFrom(org.DeepCopy())
	if err := r.deleteOrganizationProvider(ctx, org, kc); err != nil {
		org.Status.Phase = "Error"
		reason := "CleanupFailed"
		if errors.Is(err, errOrganizationCleanupConflict) {
			reason = "CleanupConflict"
		}
		setCondition(&org.Status.Conditions, "Synced", metav1.ConditionFalse, reason, "owned provider cleanup is not proven")
		return r.finishOrganization(ctx, org, patch, requeueOnError)
	}
	setCondition(&org.Status.Conditions, "Synced", metav1.ConditionTrue, "Deleted", "owned Keycloak resources are absent")
	r.initializeProjectionCondition(org)
	if r.ProjectionMode == hankoapi.ProjectionDisabled {
		if org.Status.PositionID != "" {
			log.FromContext(ctx).Info("organization projection disabled; external cleanup requires administrator review", "organization", org.Name)
			if r.Recorder != nil {
				r.Recorder.Eventf(org, nil, corev1.EventTypeWarning, "ProjectionCleanupSkipped", "Finalize", "Projection is disabled; external position cleanup requires administrator review")
			}
		}
	} else {
		if r.ProjectionMode != hankoapi.ProjectionEnabled || r.Positions == nil {
			return r.projectionFailure(ctx, org, patch, "ProjectorUnavailable")
		}
		if org.Status.PositionID != "" {
			if err := r.Positions.DeletePosition(ctx, org.Spec.RealmRef, org.Status.PositionID); err != nil {
				return r.projectionFailure(ctx, org, patch, "ProjectionFailed")
			}
			org.Status.PositionID = ""
		}
		setCondition(&org.Status.Conditions, "Projection", metav1.ConditionTrue, "Deleted", "configured platform projection cleanup completed")
	}
	org.Status.Phase = "Pending"
	if err := r.patchOrganizationStatus(ctx, org, patch); err != nil {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(org, orgFinalizerName)
	if err := r.Update(ctx, org); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *HankoOrganizationReconciler) deleteOrganizationProvider(ctx context.Context, org *api.HankoOrganization, kc *keycloak.Client) error {
	if err := r.validateAdoptedOrganizationCleanup(ctx, org, kc); err != nil {
		return err
	}
	owner := organizationGroupOwnershipAttributes(org)
	if org.Status.GroupID != "" {
		group, err := kc.GetGroup(ctx, org.Spec.RealmRef, org.Status.GroupID)
		if err != nil && !keycloak.IsNotFound(err) {
			return err
		}
		if err == nil {
			if !keycloak.GroupMatchesOwnership(group, owner, "") {
				return errOrganizationGroupOwnership
			}
			children, err := kc.HasGroupChildren(ctx, org.Spec.RealmRef, group.ID)
			if err != nil {
				return err
			}
			if children {
				return errors.New("child groups must be cleaned before organization deletion")
			}
			if err := r.validateAdoptedOrganizationCleanup(ctx, org, kc); err != nil {
				return err
			}
			if err := kc.DeleteGroup(ctx, org.Spec.RealmRef, group.ID); err != nil {
				return err
			}
			if _, err := kc.GetGroup(ctx, org.Spec.RealmRef, group.ID); !keycloak.IsNotFound(err) {
				return errors.New("group deletion read-back did not prove absence")
			}
		}
	}
	if org.Status.OrgID != "" {
		native, err := kc.GetOrganization(ctx, org.Spec.RealmRef, org.Status.OrgID)
		if err != nil && !keycloak.IsNotFound(err) {
			return err
		}
		if err == nil {
			if !keycloak.OrganizationMatchesOwnership(native, owner, "") {
				return errRootOrganizationOwnership
			}
			if err := r.validateAdoptedOrganizationCleanup(ctx, org, kc); err != nil {
				return err
			}
			if err := kc.DeleteOrganization(ctx, org.Spec.RealmRef, native.ID); err != nil {
				return err
			}
			if _, err := kc.GetOrganization(ctx, org.Spec.RealmRef, native.ID); !keycloak.IsNotFound(err) {
				return errors.New("organization deletion read-back did not prove absence")
			}
		}
	}
	return nil
}
