package applicationbinding

import (
	"context"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Delivery uses a direct Kubernetes client: no cross-namespace cache/list/watch.
// Verify must revalidate current local and provider authority, independently of
// persisted status, before output execution and acknowledgement.
type Delivery struct {
	Client client.Client
	Reader client.Reader
	Verify func(context.Context) error
}

type outputPlan struct {
	record         record
	metadata       []byte
	hash, revision string
	credential     []byte
	version        CredentialVersion
	status         api.ApplicationRuntimeBindingStatus
}

// Deliver prevalidates every binding before writes. Metadata and credential
// patches are separate; the same intended revision retries after partial writes.
func (d *Delivery) Deliver(ctx context.Context, app *api.HankoApplication, proof Proof) ([]api.ApplicationRuntimeBindingStatus, error) {
	if err := Validate(app); err != nil {
		return Pending(app, Reason(err)), err
	}
	if len(app.Spec.RuntimeBindings) == 0 {
		if err := d.Cleanup(ctx, app, nil); err != nil {
			return Pending(app, Reason(err)), err
		}
		return nil, nil
	}
	if err := validateProtocol(proof); err != nil {
		return Pending(app, Reason(err)), err
	}
	if _, err := d.current(ctx, app, &proof); err != nil {
		return Pending(app, Reason(err)), err
	}
	plans, err := d.prepare(ctx, app, proof)
	if err != nil {
		return Pending(app, Reason(err)), err
	}
	desired := make([]record, 0, len(plans))
	for _, p := range plans {
		desired = append(desired, p.record)
	}
	if err := d.Cleanup(ctx, app, desired); err != nil {
		return Pending(app, Reason(err)), err
	}
	statuses := make([]api.ApplicationRuntimeBindingStatus, 0, len(plans))
	for _, p := range plans {
		err := d.write(ctx, app, proof, p)
		setReady(&p.status, app.Generation, err)
		statuses = append(statuses, p.status)
		if err != nil {
			for _, remaining := range plans[len(statuses):] {
				setReady(&remaining.status, app.Generation, failure("OutputPending"))
				statuses = append(statuses, remaining.status)
			}
			return statuses, err
		}
	}
	return statuses, nil
}

func (d *Delivery) prepare(ctx context.Context, app *api.HankoApplication, proof Proof) ([]outputPlan, error) {
	plans := make([]outputPlan, 0, len(app.Spec.RuntimeBindings))
	bindings := append([]api.ApplicationRuntimeBinding(nil), app.Spec.RuntimeBindings...)
	slices.SortFunc(bindings, func(a, b api.ApplicationRuntimeBinding) int { return cmpName(a.Name, b.Name) })
	for _, b := range bindings {
		p, err := d.prepareBinding(ctx, app, b, proof)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}
func cmpName(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func (d *Delivery) prepareBinding(ctx context.Context, app *api.HankoApplication, b api.ApplicationRuntimeBinding, proof Proof) (outputPlan, error) {
	sa, err := workload(ctx, d.Client, b)
	if err != nil {
		return outputPlan{}, err
	}
	var cm corev1.ConfigMap
	if err := d.Client.Get(ctx, metadataKey(b), &cm); err != nil {
		return outputPlan{}, failure("TargetUnavailable")
	}
	if err := authorized(&cm, app, b, string(sa.UID), "metadata"); err != nil {
		return outputPlan{}, err
	}
	if _, exists := cm.BinaryData[MetadataKey]; exists {
		return outputPlan{}, failure("OutputConflict")
	}
	p := outputPlan{record: record{Binding: b, WorkloadUID: string(sa.UID), ConfigMapUID: string(cm.UID)}, status: bindingStatus(b)}
	if b.Credentials != nil {
		if err := d.prepareCredential(ctx, app, &p); err != nil {
			return outputPlan{}, err
		}
	}
	p.metadata, p.hash, p.revision, err = Encode(runtimeDocument(app, b, string(sa.UID), proof), p.version, p.record.ConfigMapUID, p.record.SecretUID)
	if err != nil {
		return outputPlan{}, err
	}
	if cm.Immutable != nil && *cm.Immutable && cm.Data[MetadataKey] != string(p.metadata) {
		return outputPlan{}, failure("TargetImmutable")
	}
	p.status.ServiceAccountUID, p.status.SourceGeneration = string(sa.UID), proof.Generation
	p.status.SourceAppliedPlanHash, p.status.MetadataHash, p.status.BindingRevision = proof.AppliedPlanHash, p.hash, p.revision
	return p, nil
}

func (d *Delivery) prepareCredential(ctx context.Context, app *api.HankoApplication, p *outputPlan) error {
	var target corev1.Secret
	if err := d.Client.Get(ctx, credentialKey(p.record.Binding), &target); err != nil {
		return failure("TargetUnavailable")
	}
	if err := authorized(&target, app, p.record.Binding, p.record.WorkloadUID, "credentials"); err != nil {
		return err
	}
	if target.Type != "" && target.Type != corev1.SecretTypeOpaque {
		return failure("InvalidCredentials")
	}
	var source corev1.Secret
	if err := d.Reader.Get(ctx, sourceKey(app), &source); err != nil {
		return failure("CredentialUnavailable")
	}
	if !controllerOwned(&source, app) || len(source.Data[CredentialKey]) == 0 {
		return failure("CredentialSourceNotOwned")
	}
	p.version = CredentialVersion{string(source.UID), source.ResourceVersion}
	p.credential = append([]byte(nil), source.Data[CredentialKey]...)
	p.record.SecretUID = string(target.UID)
	if target.Immutable != nil && *target.Immutable && !equalCredential(target.Data[CredentialKey], p.credential) {
		return failure("TargetImmutable")
	}
	return nil
}

func metadataKey(b api.ApplicationRuntimeBinding) client.ObjectKey {
	return client.ObjectKey{Namespace: b.Workload.Namespace, Name: b.PublicMetadata.ConfigMapRef}
}
func credentialKey(b api.ApplicationRuntimeBinding) client.ObjectKey {
	return client.ObjectKey{Namespace: b.Workload.Namespace, Name: b.Credentials.SecretRef}
}
func sourceKey(app *api.HankoApplication) client.ObjectKey {
	return client.ObjectKey{Namespace: app.Namespace, Name: "hanko-app-" + app.Spec.ClientID}
}

func bindingStatus(b api.ApplicationRuntimeBinding) api.ApplicationRuntimeBindingStatus {
	s := api.ApplicationRuntimeBindingStatus{Name: b.Name, Namespace: b.Workload.Namespace, ServiceAccountRef: b.Workload.ServiceAccountRef, ConfigMapRef: b.PublicMetadata.ConfigMapRef}
	if b.Credentials != nil {
		s.SecretRef = b.Credentials.SecretRef
	}
	return s
}

// Pending clears current readiness without copying target contents into status.
func Pending(app *api.HankoApplication, reason string) []api.ApplicationRuntimeBindingStatus {
	result := make([]api.ApplicationRuntimeBindingStatus, 0, len(app.Spec.RuntimeBindings))
	for _, b := range app.Spec.RuntimeBindings {
		if len(result) >= MaxBindings {
			break
		}
		s := bindingStatus(b)
		setReady(&s, app.Generation, failure(reason))
		result = append(result, s)
	}
	return result
}
func setReady(status *api.ApplicationRuntimeBindingStatus, generation int64, err error) {
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "requested outputs carry the current binding revision", ObservedGeneration: generation}
	if err != nil {
		condition.Status, condition.Reason, condition.Message = metav1.ConditionFalse, Reason(err), "runtime delivery is not proven current"
	}
	meta.SetStatusCondition(&status.Conditions, condition)
}
