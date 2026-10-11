package workloadbinding

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"reflect"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Delivery always uses named, uncached reads. Verify freshly seals provider and
// local dependencies; persisted status never supplies this callback's authority.
type Delivery struct {
	Client client.Client
	Reader client.Reader
	Verify func(context.Context) error
}

func Authorization(sa *api.HankoServiceAccount, w api.KubernetesWorkloadBinding) map[string]string {
	return map[string]string{ConsentPrefix + "owner-kind": "HankoServiceAccount", ConsentPrefix + "owner-namespace": sa.Namespace, ConsentPrefix + "owner-name": sa.Name, ConsentPrefix + "owner-uid": string(sa.UID), ConsentPrefix + "service-account": w.ServiceAccountRef, ConsentPrefix + "service-account-uid": w.ExpectedUID}
}
func Authorize(target *corev1.ConfigMap, sa *api.HankoServiceAccount, w api.KubernetesWorkloadBinding, uid string) error {
	if !ValidUID(uid) || string(target.UID) != uid || !target.DeletionTimestamp.IsZero() || target.Labels[TargetLabel] != "workload-metadata" {
		return Failure("TargetNotAuthorized")
	}
	for key, value := range Authorization(sa, w) {
		if target.Annotations[key] != value {
			return Failure("TargetNotAuthorized")
		}
	}
	if _, exists := target.BinaryData[MetadataKey]; exists {
		return Failure("OutputConflict")
	}
	if _, exists := target.Data[MetadataKey]; exists && target.Annotations[ConsentPrefix+"source-uid"] != string(sa.UID) {
		return Failure("OutputConflict")
	}
	return nil
}

type Record struct {
	Schema       string                        `json:"schema"`
	OwnerUID     string                        `json:"ownerUID"`
	Namespace    string                        `json:"namespace"`
	Name         string                        `json:"name"`
	UID          string                        `json:"uid"`
	Workload     api.KubernetesWorkloadBinding `json:"workload"`
	Revision     string                        `json:"revision"`
	MetadataHash string                        `json:"metadataHash"`
}

func ParseRecord(value string) (*Record, error) {
	if value == "" {
		return nil, nil
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	var r Record
	if len(value) > 4096 || d.Decode(&r) != nil || !r.valid() {
		return nil, Failure("CleanupConflict")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, Failure("CleanupConflict")
	}
	b, _ := json.Marshal(r)
	if string(b) != value {
		return nil, Failure("CleanupConflict")
	}
	return &r, nil
}

func (r Record) valid() bool {
	return r.Schema == Schema && ValidUID(r.OwnerUID) && ValidUID(r.UID) && validWorkload(r.Workload) && iamcontract.ValidDigest(r.Revision) && iamcontract.ValidDigest(r.MetadataHash) && len(validation.IsDNS1123Label(r.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(r.Name)) == 0 && r.Workload.Namespace == r.Namespace
}
func (d *Delivery) current(ctx context.Context, sa *api.HankoServiceAccount, writing bool) (*api.HankoServiceAccount, error) {
	if d.Client == nil || d.Reader == nil {
		return nil, Failure("WorkloadBindingUnavailable")
	}
	var c api.HankoServiceAccount
	if d.Reader.Get(ctx, client.ObjectKeyFromObject(sa), &c) != nil || c.UID != sa.UID || c.Generation != sa.Generation || !reflect.DeepEqual(c.Spec, sa.Spec) || !reflect.DeepEqual(c.Labels, sa.Labels) || c.Spec.Mode == "Observe" || c.Labels["hanko.sh/imported-by"] != "" {
		return nil, Failure("StaleSource")
	}
	if writing && (!c.DeletionTimestamp.IsZero() || d.Verify == nil || d.Verify(ctx) != nil) {
		return nil, Failure("StaleSource")
	}
	return &c, nil
}
func (d *Delivery) save(ctx context.Context, sa *api.HankoServiceAccount, r *Record) error {
	c, err := d.current(ctx, sa, r != nil)
	if err != nil {
		return err
	}
	value := ""
	if r != nil {
		b, _ := json.Marshal(r)
		value = string(b)
	}
	if c.Annotations[JournalKey] == value {
		return nil
	}
	patch := client.MergeFromWithOptions(c.DeepCopy(), client.MergeFromWithOptimisticLock{})
	c.Annotations = maps.Clone(c.Annotations)
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	if r == nil {
		delete(c.Annotations, JournalKey)
	} else {
		c.Annotations[JournalKey] = value
	}
	if d.Client.Patch(ctx, c, patch) != nil {
		return Failure("OutputFailed")
	}
	return nil
}

func (d *Delivery) Deliver(ctx context.Context, sa *api.HankoServiceAccount, plan Plan) (*api.WorkloadRuntimeMetadataStatus, error) {
	if sa.Spec.RuntimeMetadata == nil {
		return nil, d.Cleanup(ctx, sa)
	}
	r, data, err := d.prepareDelivery(ctx, sa, plan)
	if err != nil {
		return nil, err
	}
	if _, err := d.current(ctx, sa, true); err != nil {
		return nil, err
	}
	var target corev1.ConfigMap
	key := client.ObjectKey{Namespace: r.Namespace, Name: r.Name}
	if d.Reader.Get(ctx, key, &target) != nil {
		return nil, Failure("TargetUnavailable")
	}
	if err := Authorize(&target, sa, r.Workload, r.UID); err != nil {
		return nil, err
	}
	if !d.workloadCurrent(ctx, r.Workload) {
		return nil, Failure("WorkloadUIDMismatch")
	}
	if err := d.writeMetadata(ctx, sa, r, &target, string(data)); err != nil {
		return nil, err
	}
	if _, err := d.current(ctx, sa, true); err != nil {
		return nil, err
	}
	if d.Reader.Get(ctx, key, &target) != nil || !d.deliveredCurrent(ctx, &target, sa, r) || target.Data[MetadataKey] != string(data) {
		return nil, Failure("OutputUnconfirmed")
	}
	return &api.WorkloadRuntimeMetadataStatus{ConfigMapRef: r.Name, ConfigMapUID: r.UID, MetadataHash: r.MetadataHash, BindingRevision: r.Revision}, nil
}

func (d *Delivery) prepareDelivery(ctx context.Context, sa *api.HankoServiceAccount, plan Plan) (*Record, []byte, error) {
	if err := Validate(sa); err != nil {
		return nil, nil, err
	}
	c, err := d.current(ctx, sa, true)
	if err != nil {
		return nil, nil, err
	}
	old, err := ParseRecord(c.Annotations[JournalKey])
	if err != nil {
		return nil, nil, err
	}
	t := sa.Spec.RuntimeMetadata
	w := sa.Spec.Authentication.Kubernetes.Workload
	data, hash, err := plan.Metadata(sa)
	if err != nil {
		return nil, nil, err
	}
	r := &Record{Schema: Schema, OwnerUID: string(sa.UID), Namespace: w.Namespace, Name: t.ConfigMapRef, UID: t.ExpectedUID, Workload: w, Revision: plan.Revision(), MetadataHash: hash}
	if old != nil && !old.sameTarget(r) {
		if err := d.Cleanup(ctx, sa); err != nil {
			return nil, nil, err
		}
	}
	if err := d.save(ctx, sa, r); err != nil {
		return nil, nil, err
	}
	return r, data, nil
}

func (r Record) sameTarget(other *Record) bool {
	return r.Namespace == other.Namespace && r.Name == other.Name && r.UID == other.UID && r.Workload == other.Workload
}

func (d *Delivery) writeMetadata(ctx context.Context, sa *api.HankoServiceAccount, r *Record, target *corev1.ConfigMap, data string) error {
	if target.Data[MetadataKey] != data || target.Annotations[ConsentPrefix+"binding-revision"] != r.Revision || target.Annotations[ConsentPrefix+"metadata-hash"] != r.MetadataHash {
		if target.Immutable != nil && *target.Immutable {
			return Failure("TargetImmutable")
		}
		if _, err := d.current(ctx, sa, true); err != nil {
			return err
		}
		if !d.workloadCurrent(ctx, r.Workload) {
			return Failure("WorkloadUIDMismatch")
		}
		patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
		target.Data = maps.Clone(target.Data)
		target.Annotations = maps.Clone(target.Annotations)
		if target.Data == nil {
			target.Data = map[string]string{}
		}
		if target.Annotations == nil {
			target.Annotations = map[string]string{}
		}
		target.Data[MetadataKey] = data
		target.Annotations[ConsentPrefix+"schema"] = Schema
		target.Annotations[ConsentPrefix+"source-uid"] = string(sa.UID)
		target.Annotations[ConsentPrefix+"binding-revision"] = r.Revision
		target.Annotations[ConsentPrefix+"metadata-hash"] = r.MetadataHash
		// Read back even if a successful patch lost its acknowledgement.
		_ = d.Client.Patch(ctx, target, patch)
	}
	return nil
}

func (d *Delivery) deliveredCurrent(ctx context.Context, target *corev1.ConfigMap, sa *api.HankoServiceAccount, r *Record) bool {
	return Authorize(target, sa, r.Workload, r.UID) == nil && d.workloadCurrent(ctx, r.Workload) && target.Annotations[ConsentPrefix+"source-uid"] == string(sa.UID) && target.Annotations[ConsentPrefix+"binding-revision"] == r.Revision && target.Annotations[ConsentPrefix+"metadata-hash"] == r.MetadataHash
}
func (d *Delivery) workloadCurrent(ctx context.Context, w api.KubernetesWorkloadBinding) bool {
	var sa corev1.ServiceAccount
	return d.Reader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: w.ServiceAccountRef}, &sa) == nil && string(sa.UID) == w.ExpectedUID && sa.DeletionTimestamp.IsZero()
}

// Cleanup treats the durable journal as lookup hints. Current UID consent and
// the actual delivered source/revision independently authorize field removal.
func (d *Delivery) Cleanup(ctx context.Context, sa *api.HankoServiceAccount) error {
	c, err := d.current(ctx, sa, false)
	if err != nil {
		return err
	}
	r, err := ParseRecord(c.Annotations[JournalKey])
	if err != nil || r == nil {
		return err
	}
	if r.OwnerUID != string(sa.UID) {
		return Failure("CleanupConflict")
	}
	var target corev1.ConfigMap
	key := client.ObjectKey{Namespace: r.Namespace, Name: r.Name}
	if err := d.Reader.Get(ctx, key, &target); err != nil {
		if apierrors.IsNotFound(err) {
			return d.save(ctx, sa, nil)
		}
		return Failure("CleanupConflict")
	}
	write, err := d.prepareCleanup(ctx, &target, sa, r)
	if err != nil {
		return err
	}
	if !write {
		return d.save(ctx, sa, nil)
	}
	if _, err := d.current(ctx, sa, false); err != nil {
		return err
	}
	patch := client.MergeFromWithOptions(target.DeepCopy(), client.MergeFromWithOptimisticLock{})
	delete(target.Data, MetadataKey)
	for _, key := range []string{"schema", "source-uid", "binding-revision", "metadata-hash"} {
		delete(target.Annotations, ConsentPrefix+key)
	}
	_ = d.Client.Patch(ctx, &target, patch)
	if _, err := d.current(ctx, sa, false); err != nil {
		return err
	}
	if !d.cleanedCurrent(ctx, key, sa, r) {
		return Failure("CleanupConflict")
	}
	return d.save(ctx, sa, nil)
}

func (d *Delivery) prepareCleanup(ctx context.Context, target *corev1.ConfigMap, sa *api.HankoServiceAccount, r *Record) (bool, error) {
	if string(target.UID) != r.UID || Authorize(target, sa, r.Workload, r.UID) != nil {
		return false, Failure("CleanupConflict")
	}
	if target.Data[MetadataKey] == "" && target.Annotations[ConsentPrefix+"source-uid"] == "" {
		return false, nil
	}
	if !d.deliveredCurrent(ctx, target, sa, r) || target.Immutable != nil && *target.Immutable {
		return false, Failure("CleanupConflict")
	}
	return true, nil
}

func (d *Delivery) cleanedCurrent(ctx context.Context, key client.ObjectKey, sa *api.HankoServiceAccount, r *Record) bool {
	var target corev1.ConfigMap
	return d.Reader.Get(ctx, key, &target) == nil && Authorize(&target, sa, r.Workload, r.UID) == nil && d.workloadCurrent(ctx, r.Workload) && target.Data[MetadataKey] == "" && target.Annotations[ConsentPrefix+"source-uid"] == ""
}
