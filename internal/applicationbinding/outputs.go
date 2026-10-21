package applicationbinding

import (
	"bytes"
	"context"
	"maps"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func equalCredential(a, b []byte) bool { return bytes.Equal(a, b) }
func (d *Delivery) prewrite(ctx context.Context, app *api.HankoApplication, proof Proof, p outputPlan) error {
	if _, err := d.current(ctx, app, &proof); err != nil {
		return err
	}
	sa, err := workload(ctx, d.Client, p.record.Binding)
	if err != nil {
		return err
	}
	if string(sa.UID) != p.record.WorkloadUID {
		return failure("WorkloadChanged")
	}
	if p.record.Binding.Credentials != nil {
		var source corev1.Secret
		if err := d.Reader.Get(ctx, sourceKey(app), &source); err != nil {
			return failure("CredentialUnavailable")
		}
		if !controllerOwned(&source, app) || (CredentialVersion{string(source.UID), source.ResourceVersion}) != p.version {
			return failure("StaleSource")
		}
	}
	return nil
}
func (d *Delivery) write(ctx context.Context, app *api.HankoApplication, proof Proof, p outputPlan) error {
	if err := d.writeMetadata(ctx, app, proof, p); err != nil {
		return err
	}
	if p.record.Binding.Credentials != nil {
		if err := d.writeCredential(ctx, app, proof, p); err != nil {
			return err
		}
	}
	if err := d.prewrite(ctx, app, proof, p); err != nil {
		return err
	}
	return d.acknowledge(ctx, app, proof, p)
}
func (d *Delivery) writeMetadata(ctx context.Context, app *api.HankoApplication, proof Proof, p outputPlan) error {
	if err := d.prewrite(ctx, app, proof, p); err != nil {
		return err
	}
	var target corev1.ConfigMap
	if err := d.Client.Get(ctx, metadataKey(p.record.Binding), &target); err != nil {
		return failure("TargetUnavailable")
	}
	if string(target.UID) != p.record.ConfigMapUID {
		return failure("TargetChanged")
	}
	if err := authorized(&target, app, p.record.Binding, p.record.WorkloadUID, "metadata"); err != nil {
		return err
	}
	annotations := outputAnnotations(app, p.record.Binding.Name, p.hash, p.revision, proof)
	if target.Data[MetadataKey] == string(p.metadata) && containsAnnotations(target.Annotations, annotations) {
		return nil
	}
	patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
	target.Data = maps.Clone(target.Data)
	if target.Data == nil {
		target.Data = map[string]string{}
	}
	target.Data[MetadataKey] = string(p.metadata)
	target.Annotations = mergeAnnotations(target.Annotations, annotations)
	if err := d.Client.Patch(ctx, &target, patch); err != nil {
		return failure("OutputFailed")
	}
	return nil
}
func (d *Delivery) writeCredential(ctx context.Context, app *api.HankoApplication, proof Proof, p outputPlan) error {
	if err := d.prewrite(ctx, app, proof, p); err != nil {
		return err
	}
	var target corev1.Secret
	if err := d.Client.Get(ctx, credentialKey(p.record.Binding), &target); err != nil {
		return failure("TargetUnavailable")
	}
	if string(target.UID) != p.record.SecretUID {
		return failure("TargetChanged")
	}
	if err := authorized(&target, app, p.record.Binding, p.record.WorkloadUID, "credentials"); err != nil {
		return err
	}
	annotations := outputAnnotations(app, p.record.Binding.Name, p.hash, p.revision, proof)
	if equalCredential(target.Data[CredentialKey], p.credential) && containsAnnotations(target.Annotations, annotations) {
		return nil
	}
	patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
	target.Data = maps.Clone(target.Data)
	if target.Data == nil {
		target.Data = map[string][]byte{}
	}
	target.Data[CredentialKey] = append([]byte(nil), p.credential...)
	target.Annotations = mergeAnnotations(target.Annotations, annotations)
	if err := d.Client.Patch(ctx, &target, patch); err != nil {
		return failure("OutputFailed")
	}
	return nil
}
func (d *Delivery) acknowledge(ctx context.Context, app *api.HankoApplication, proof Proof, p outputPlan) error {
	annotations := outputAnnotations(app, p.record.Binding.Name, p.hash, p.revision, proof)
	var cm corev1.ConfigMap
	if err := d.Client.Get(ctx, metadataKey(p.record.Binding), &cm); err != nil {
		return failure("OutputUnconfirmed")
	}
	if string(cm.UID) != p.record.ConfigMapUID || cm.Data[MetadataKey] != string(p.metadata) || !containsAnnotations(cm.Annotations, annotations) {
		return failure("OutputUnconfirmed")
	}
	if err := authorized(&cm, app, p.record.Binding, p.record.WorkloadUID, "metadata"); err != nil {
		return err
	}
	if p.record.Binding.Credentials == nil {
		return nil
	}
	var secret corev1.Secret
	if err := d.Client.Get(ctx, credentialKey(p.record.Binding), &secret); err != nil {
		return failure("OutputUnconfirmed")
	}
	if string(secret.UID) != p.record.SecretUID || !equalCredential(secret.Data[CredentialKey], p.credential) || !containsAnnotations(secret.Annotations, annotations) {
		return failure("OutputUnconfirmed")
	}
	return authorized(&secret, app, p.record.Binding, p.record.WorkloadUID, "credentials")
}
func containsAnnotations(actual, desired map[string]string) bool {
	for k, v := range desired {
		if actual[k] != v {
			return false
		}
	}
	return true
}
func mergeAnnotations(actual, desired map[string]string) map[string]string {
	result := maps.Clone(actual)
	if result == nil {
		result = map[string]string{}
	}
	maps.Copy(result, desired)
	return result
}
