package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	kubejson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A separate manager cannot prune local approvals/finalizers formerly written
// by the legacy general-purpose manager. Field conflicts require local review.
const bundleFieldManager = "hanko-hub-bundle"

type bundleRefusal struct {
	reason string
	detail string
}

func (e *bundleRefusal) Error() string { return e.detail }

func refuseBundle(reason, detail string) error {
	return &bundleRefusal{reason: reason, detail: detail}
}

func bundleApplyReason(err error) string {
	var refusal *bundleRefusal
	if errors.As(err, &refusal) {
		return refusal.reason
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		return "BundleObjectConflict"
	}
	return "BundleApplyFailed"
}

type bundleObject struct {
	desired *unstructured.Unstructured
	current *unstructured.Unstructured
	count   string
	exists  bool
}

// applyBundle validates the entire bundle and reads current ownership before
// writing any object. Each write is conditional; this is not a transaction
// across objects, and a later concurrent conflict can leave a partial apply.
func (r *HankoTenantReconciler) applyBundle(ctx context.Context, tenant *api.HankoTenant, bundle *hub.Bundle) (map[string]int, error) {
	counts := map[string]int{"iamProfiles": 0, "realms": 0, "apps": 0, "themes": 0, "serviceAccounts": 0}
	objects, err := r.prepareBundle(ctx, tenant, bundle)
	if err != nil {
		return counts, err
	}
	for _, object := range objects {
		if !object.exists {
			// SSA would upsert an object created by somebody else after our read.
			object.current = object.desired.DeepCopy()
			err = r.Create(ctx, object.current, client.FieldOwner(bundleFieldManager))
			if err != nil {
				return counts, fmt.Errorf("create bundle %s %q: %w", object.desired.GetKind(), object.desired.GetName(), err)
			}
		}
		err = r.applyBundleObject(ctx, object)
		if err != nil {
			return counts, fmt.Errorf("write bundle %s %q: %w", object.desired.GetKind(), object.desired.GetName(), err)
		}
		counts[object.count]++
	}
	return counts, nil
}

func (r *HankoTenantReconciler) prepareBundle(ctx context.Context, tenant *api.HankoTenant, bundle *hub.Bundle) ([]bundleObject, error) {
	groups := []struct {
		count string
		kind  string
		raw   []json.RawMessage
	}{
		{"iamProfiles", "HankoIAMProfile", bundle.IAMProfiles},
		{"realms", "HankoRealm", bundle.Realms},
		{"apps", "HankoApplication", bundle.Apps},
		{"themes", "HankoTheme", bundle.Themes},
		{"serviceAccounts", "HankoServiceAccount", bundle.ServiceAccounts},
	}
	var objects []bundleObject
	seen := make(map[string]bool)
	for _, group := range groups {
		for _, raw := range group.raw {
			desired, err := r.decodeBundleObject(raw, group.kind, tenant)
			if err != nil {
				return nil, err
			}
			key := group.kind + "/" + desired.GetName()
			if seen[key] {
				return nil, refuseBundle("BundleObjectInvalid", "duplicate bundle object "+key)
			}
			seen[key] = true
			current, err := r.bindBundleObject(ctx, desired, tenant.Name)
			if err != nil {
				return nil, err
			}
			objects = append(objects, bundleObject{desired: desired, current: current, count: group.count, exists: current != nil})
		}
	}
	return objects, nil
}

func (r *HankoTenantReconciler) decodeBundleObject(raw json.RawMessage, kind string, tenant *api.HankoTenant) (*unstructured.Unstructured, error) {
	gvk := api.GroupVersion.WithKind(kind)
	object, err := r.Client.Scheme().New(gvk)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle kind: %w", err)
	}
	if err := json.Unmarshal(raw, object); err != nil {
		return nil, refuseBundle("BundleObjectInvalid", "invalid bundle object field types")
	}
	// Preserve explicitly supplied false/zero values, which typed omitempty
	// serialization would discard. Only the permitted metadata reaches storage.
	var desired unstructured.Unstructured
	if err := kubejson.Unmarshal(raw, &desired.Object); err != nil || desired.Object == nil {
		return nil, refuseBundle("BundleObjectInvalid", "invalid bundle object JSON")
	}
	for field := range desired.Object {
		switch field {
		case "apiVersion", "kind", "metadata", "spec":
		default:
			return nil, refuseBundle("BundleObjectInvalid", "unsupported bundle object field")
		}
	}
	if (desired.GetAPIVersion() != "" && desired.GetAPIVersion() != gvk.GroupVersion().String()) ||
		(desired.GetKind() != "" && desired.GetKind() != kind) {
		return nil, refuseBundle("BundleObjectInvalid", "unexpected bundle API version or kind")
	}
	if err := validateBundleMetadata(&desired, tenant); err != nil {
		return nil, err
	}
	desired.SetGroupVersionKind(gvk)
	desired.SetNamespace(tenant.Namespace)
	labels := desired.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["hanko.sh/tenant"] = tenant.Name
	desired.SetLabels(labels)
	return &desired, nil
}

func validateBundleMetadata(desired *unstructured.Unstructured, tenant *api.HankoTenant) error {
	metadata, found, err := unstructured.NestedMap(desired.Object, "metadata")
	if err != nil || !found || len(validation.IsDNS1123Subdomain(desired.GetName())) != 0 {
		return refuseBundle("BundleObjectInvalid", "bundle object requires a valid explicit name")
	}
	for field := range metadata {
		switch field {
		case "name", "namespace", "labels", "annotations":
		default:
			return refuseBundle("BundleMetadataInvalid", "bundle contains server or locally controlled metadata")
		}
	}
	if desired.GetNamespace() != "" && desired.GetNamespace() != tenant.Namespace {
		return refuseBundle("BundleTenantConflict", "bundle object targets another namespace")
	}
	for key, value := range desired.GetLabels() {
		if key == "hanko.sh/tenant" {
			if value != tenant.Name {
				return refuseBundle("BundleTenantConflict", "bundle object declares another tenant")
			}
		} else if reservedBundleMetadata(key) {
			return refuseBundle("BundleMetadataInvalid", "bundle contains locally controlled labels")
		}
	}
	for key := range desired.GetAnnotations() {
		if reservedBundleMetadata(key) {
			return refuseBundle("BundleMetadataInvalid", "bundle contains locally controlled annotations")
		}
	}
	return nil
}

func reservedBundleMetadata(key string) bool {
	return strings.HasPrefix(key, "hanko.sh/") || strings.HasPrefix(key, "hanko.io/") || strings.HasPrefix(key, "mesh.hanko.io/")
}

func (r *HankoTenantReconciler) bindBundleObject(ctx context.Context, desired *unstructured.Unstructured, tenant string) (*unstructured.Unstructured, error) {
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(desired.GroupVersionKind())
	if err := r.tenantReader().Get(ctx, client.ObjectKeyFromObject(desired), current); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read current bundle target: %w", err)
	}
	if current.GetLabels()["hanko.sh/tenant"] != tenant {
		return nil, refuseBundle("BundleTenantConflict", fmt.Sprintf("existing %s %q is not assigned to this tenant", desired.GetKind(), desired.GetName()))
	}
	if !current.GetDeletionTimestamp().IsZero() || current.GetUID() == "" || current.GetResourceVersion() == "" {
		return nil, refuseBundle("BundleObjectConflict", "bundle target is deleting or has no current identity")
	}
	// Kubernetes checks these inside the write. A cached read, an ownership
	// transfer, deletion/recreation or concurrent edit cannot authorize an upsert.
	desired.SetUID(current.GetUID())
	desired.SetResourceVersion(current.GetResourceVersion())
	return current, nil
}

func (r *HankoTenantReconciler) applyBundleObject(ctx context.Context, object bundleObject) error {
	// Create records Update ownership. Transfer only this dedicated manager's
	// entry to Apply; otherwise the first changed bundle conflicts with our own
	// creation. Never clear managedFields or transfer another manager's fields.
	current := object.current
	fields := current.GetManagedFields()
	changed, applied := false, false
	for i := range fields {
		if fields[i].Manager != bundleFieldManager || fields[i].Subresource != "" {
			continue
		}
		switch fields[i].Operation {
		case metav1.ManagedFieldsOperationApply:
			applied = true
		case metav1.ManagedFieldsOperationUpdate:
			fields[i].Operation = metav1.ManagedFieldsOperationApply
			changed = true
		}
	}
	if changed {
		if applied {
			return refuseBundle("BundleObjectConflict", "bundle target has ambiguous field manager ownership")
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{
			"uid": current.GetUID(), "resourceVersion": current.GetResourceVersion(), "managedFields": fields,
		}})
		if err != nil {
			return fmt.Errorf("encode bundle field manager transition: %w", err)
		}
		if err := r.Patch(ctx, current, client.RawPatch(types.MergePatchType, patch), client.FieldOwner(bundleFieldManager)); err != nil {
			return fmt.Errorf("transition bundle creation ownership: %w", err)
		}
	}
	object.desired.SetUID(current.GetUID())
	object.desired.SetResourceVersion(current.GetResourceVersion())
	return r.Apply(ctx, client.ApplyConfigurationFromUnstructured(object.desired), client.FieldOwner(bundleFieldManager))
}
