package applicationbinding

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type record struct {
	Binding      api.ApplicationRuntimeBinding `json:"binding"`
	WorkloadUID  string                        `json:"workloadUID"`
	ConfigMapUID string                        `json:"configMapUID"`
	SecretUID    string                        `json:"secretUID,omitempty"`
}

func records(app *api.HankoApplication) ([]record, error) {
	value := app.Annotations[JournalAnnotation]
	if value == "" {
		return nil, nil
	}
	var result []record
	if len(value) > 49152 || json.Unmarshal([]byte(value), &result) != nil || len(result) > MaxBindings {
		return nil, failure("CleanupConflict")
	}
	for _, r := range result {
		if !validBinding(r.Binding) || !validRecordUIDs(r) || (r.Binding.Credentials != nil && (len(r.Binding.Credentials.SecretRef) > 253 || !dnsName.MatchString(r.Binding.Credentials.SecretRef))) {
			return nil, failure("CleanupConflict")
		}
	}
	return result, nil
}
func validRecordUIDs(r record) bool {
	return r.WorkloadUID != "" && len(r.WorkloadUID) <= 128 && r.ConfigMapUID != "" && len(r.ConfigMapUID) <= 128 && (r.Binding.Credentials == nil || (r.SecretUID != "" && len(r.SecretUID) <= 128))
}
func (d *Delivery) saveJournal(ctx context.Context, app *api.HankoApplication, values []record) error {
	current, err := d.current(ctx, app, nil)
	if err != nil {
		return err
	}
	slices.SortFunc(values, func(a, b record) int { return cmpName(a.Binding.Name, b.Binding.Name) })
	data, err := json.Marshal(values)
	if err != nil || len(data) > 49152 || len(values) > MaxBindings {
		return failure("InvalidBindings")
	}
	value := string(data)
	if len(values) == 0 {
		value = ""
	}
	if current.Annotations[JournalAnnotation] == value {
		return nil
	}
	patch := client.MergeFromWithOptions(current.DeepCopy(), client.MergeFromWithOptimisticLock{})
	current.Annotations = maps.Clone(current.Annotations)
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	if value == "" {
		delete(current.Annotations, JournalAnnotation)
	} else {
		current.Annotations[JournalAnnotation] = value
	}
	if err := d.Client.Patch(ctx, current, patch); err != nil {
		return failure("OutputFailed")
	}
	return nil
}

// Cleanup uses journal references only as lookup hints. Fresh target consent,
// target UID, delivered application UID and workload UID independently authorize
// removal of our keys. Revoked authority leaves outputs intact for owner review.
func (d *Delivery) Cleanup(ctx context.Context, app *api.HankoApplication, desired []record) error {
	current, err := d.current(ctx, app, nil)
	if err != nil {
		return err
	}
	previous, err := records(current)
	if err != nil {
		return err
	}
	keep := desiredTargets(desired)
	for _, old := range previous {
		if !keep[targetIdentity("metadata", old.Binding.Workload.Namespace, old.Binding.PublicMetadata.ConfigMapRef)] {
			if err := d.cleanupMetadata(ctx, app, old); err != nil {
				return err
			}
		}
		if old.Binding.Credentials != nil && !keep[targetIdentity("credentials", old.Binding.Workload.Namespace, old.Binding.Credentials.SecretRef)] {
			if err := d.cleanupCredential(ctx, app, old); err != nil {
				return err
			}
		}
	}
	return d.saveJournal(ctx, app, desired)
}
func desiredTargets(desired []record) map[string]bool {
	result := map[string]bool{}
	for _, r := range desired {
		result[targetIdentity("metadata", r.Binding.Workload.Namespace, r.Binding.PublicMetadata.ConfigMapRef)] = true
		if r.Binding.Credentials != nil {
			result[targetIdentity("credentials", r.Binding.Workload.Namespace, r.Binding.Credentials.SecretRef)] = true
		}
	}
	return result
}
func (d *Delivery) cleanupAuthority(ctx context.Context, app *api.HankoApplication, r record, target client.Object, uid, kind string) error {
	if _, err := d.current(ctx, app, nil); err != nil {
		return err
	}
	sa, err := workload(ctx, d.Client, r.Binding)
	if err != nil || string(sa.UID) != r.WorkloadUID {
		return failure("CleanupConflict")
	}
	if string(target.GetUID()) != uid || target.GetAnnotations()["hanko.sh/runtime-source-uid"] != string(app.UID) || target.GetAnnotations()["hanko.sh/runtime-delivered-binding"] != r.Binding.Name {
		return failure("CleanupConflict")
	}
	if err := authorized(target, app, r.Binding, r.WorkloadUID, kind); err != nil {
		return failure("CleanupConflict")
	}
	return nil
}
func (d *Delivery) cleanupMetadata(ctx context.Context, app *api.HankoApplication, r record) error {
	var target corev1.ConfigMap
	if err := d.Client.Get(ctx, metadataKey(r.Binding), &target); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return failure("CleanupConflict")
	}
	if _, exists := target.Data[MetadataKey]; !exists && target.Annotations["hanko.sh/runtime-source-uid"] == "" {
		return nil
	}
	if err := d.cleanupAuthority(ctx, app, r, &target, r.ConfigMapUID, "metadata"); err != nil {
		return err
	}
	patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
	delete(target.Data, MetadataKey)
	clearDeliveredAnnotations(&target)
	if err := d.Client.Patch(ctx, &target, patch); err != nil {
		return failure("CleanupConflict")
	}
	return nil
}
func (d *Delivery) cleanupCredential(ctx context.Context, app *api.HankoApplication, r record) error {
	var target corev1.Secret
	if err := d.Client.Get(ctx, credentialKey(r.Binding), &target); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return failure("CleanupConflict")
	}
	if _, exists := target.Data[CredentialKey]; !exists && target.Annotations["hanko.sh/runtime-source-uid"] == "" {
		return nil
	}
	if err := d.cleanupAuthority(ctx, app, r, &target, r.SecretUID, "credentials"); err != nil {
		return err
	}
	patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
	delete(target.Data, CredentialKey)
	clearDeliveredAnnotations(&target)
	if err := d.Client.Patch(ctx, &target, patch); err != nil {
		return failure("CleanupConflict")
	}
	return nil
}
func clearDeliveredAnnotations(target client.Object) {
	annotations := target.GetAnnotations()
	for _, key := range []string{"hanko.sh/runtime-schema", "hanko.sh/runtime-source-uid", "hanko.sh/runtime-delivered-binding", "hanko.sh/runtime-source-generation", "hanko.sh/runtime-applied-plan-hash", RevisionAnnotation, "hanko.sh/runtime-metadata-hash"} {
		delete(annotations, key)
	}
	target.SetAnnotations(annotations)
}
