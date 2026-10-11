package controller

import (
	"context"
	"errors"
	"reflect"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const workloadTrustFinalizer = "hanko.sh/workload-trust-cleanup"

// HankoWorkloadTrustReconciler owns only native trust providers. It deliberately
// has no writer pool, client authenticator writer or workload-token interface.
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoworkloadtrusts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoworkloadtrusts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoworkloadtrusts/finalizers,verbs=update
type HankoWorkloadTrustReconciler struct {
	client.Client
	APIReader     client.Reader
	ClusterConfig *rest.Config
	// DiscoveryCheck is an injectable conformance boundary. Production leaves it
	// nil and validates against the actual configured Kubernetes API transport.
	DiscoveryCheck func(context.Context, workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error)
}

type workloadTrustError string

func (e workloadTrustError) Error() string { return string(e) }
func trustFailure(reason string) error     { return workloadTrustError(reason) }
func trustReason(err error) string {
	var e workloadTrustError
	if errors.As(err, &e) {
		return string(e)
	}
	return "ProviderUnavailable"
}

func effectiveWorkloadTrustMode(t *api.HankoWorkloadTrust) string {
	if isImported(t.Labels) || t.Spec.Mode == ModeObserve {
		return ModeObserve
	}
	return ModeManage
}

type workloadSnapshot struct {
	trust                  api.HankoWorkloadTrust
	realm                  api.HankoRealm
	source, writer, reader workloadConnection
	provider               *keycloak.KubernetesTrust
	providers              []keycloak.KubernetesTrust
	dependencies           []keycloak.DependentClient
	dependentCounts        api.WorkloadTrustDependents
	dependentOwnersHash    string
	discovery              workloadtrust.DiscoveryEvidence
	plan                   workloadtrust.Plan
	foreignInventoryHash   string
	checkpoint             *workloadtrust.Checkpoint
	imports                []api.HankoImport
}

func workloadIntent(t *api.HankoWorkloadTrust) workloadtrust.Intent {
	age := t.Spec.Kubernetes.AssertionMaxAgeSeconds
	if age == 0 {
		age = 600
	}
	return workloadtrust.Intent{RealmRef: t.Spec.RealmRef, Alias: t.Spec.KeycloakAlias, Issuer: t.Spec.Kubernetes.Issuer, DiscoveryURL: t.Spec.Kubernetes.DiscoveryURL, QualifiedVersion: t.Spec.QualifiedKeycloakVersion, NamespaceUID: t.Spec.Kubernetes.ClusterAnchor.KubeSystemNamespaceUID, CAHash: t.Spec.Kubernetes.ClusterAnchor.APIServerCAHash, MaxAge: age}
}

func nativeWorkloadStateHash(p keycloak.KubernetesTrust) string {
	return keycloak.WorkloadTrustStateHash(p)
}

func workloadConnectionEvidence(c workloadConnection) any {
	return struct {
		Name                                                       string
		UID                                                        types.UID
		Generation                                                 int64
		Mode, AdminRef, CARef, Origin, Trust, CAIdentity, ClientID string
		CredentialUID                                              types.UID
		CredentialVersion                                          string
		CAUID                                                      types.UID
		CAVersion                                                  string
	}{c.instance.Name, c.instance.UID, c.instance.Generation, c.instance.Spec.Mode, c.instance.Spec.AdminRef.Name, c.instance.Spec.TLSCARef, c.identity.Origin, c.identity.Trust, c.identity.CAIdentity, c.client.CredentialClientID(), c.credentialUID, c.credentialVersion, c.caUID, c.caVersion}
}

func (r *HankoWorkloadTrustReconciler) workloadSnapshot(ctx context.Context, key types.NamespacedName, writes bool, expectedProviderID string) (*workloadSnapshot, error) {
	if r.APIReader == nil {
		return nil, trustFailure("SourceUnavailable")
	}
	s := &workloadSnapshot{}
	defer s.closeIdleConnections()
	if err := r.APIReader.Get(ctx, key, &s.trust); err != nil {
		return nil, err
	}
	t := &s.trust
	i := workloadIntent(t)
	if t.UID == "" || t.Spec.Provider != "Kubernetes" || t.Spec.Mode != "" && t.Spec.Mode != ModeManage && t.Spec.Mode != ModeObserve || len(validation.IsDNS1123Subdomain(t.Spec.KeycloakAlias)) != 0 || t.Spec.RealmRef == "master" || !workloadtrust.ValidHTTPS(i.Issuer) {
		return s, trustFailure("UnsupportedNativeState")
	}
	if i.DiscoveryURL != "" && i.QualifiedVersion != "26.8.0" {
		return s, trustFailure("UnsupportedDiscoveryOverride")
	}
	if r.validateWorkloadCluster(ctx, t.Spec.Kubernetes.ClusterAnchor) != nil {
		return s, trustFailure("AnchorMismatch")
	}
	if r.APIReader.Get(ctx, types.NamespacedName{Namespace: t.Namespace, Name: t.Spec.RealmRef}, &s.realm) != nil || s.realm.UID == "" || !s.realm.DeletionTimestamp.IsZero() {
		return s, trustFailure("SourceUnavailable")
	}
	approval, err := adoption.ParseApproval(t.Annotations)
	if err != nil || approval.Source != "" && approval.Source != t.Spec.SourceRef {
		return s, trustFailure("AdoptionApprovalRequired")
	}
	if importName := t.Labels[importedByLabel]; importName != "" {
		var operation api.HankoImport
		if r.APIReader.Get(ctx, types.NamespacedName{Namespace: t.Namespace, Name: importName}, &operation) != nil || operation.Spec.SourceRef != t.Spec.SourceRef || !operation.DeletionTimestamp.IsZero() {
			return s, trustFailure("SourceUnavailable")
		}
		s.imports = append(s.imports, operation)
	}
	s.source, err = r.workloadConnection(ctx, t.Namespace, t.Spec.SourceRef)
	if err != nil {
		return s, err
	}
	// A realm's explicit/imported source must resolve to the same backend. No
	// status realm UUID or cached pool connection grants execution authority.
	realmSource := s.realm.Annotations[adoption.SourceAnnotation]
	if imported := s.realm.Labels[importedByLabel]; imported != "" {
		var operation api.HankoImport
		if r.APIReader.Get(ctx, types.NamespacedName{Namespace: t.Namespace, Name: imported}, &operation) != nil || !operation.DeletionTimestamp.IsZero() {
			return s, trustFailure("SourceUnavailable")
		}
		if realmSource != "" && realmSource != operation.Spec.SourceRef {
			return s, trustFailure("SourceUnavailable")
		}
		realmSource = operation.Spec.SourceRef
		s.imports = append(s.imports, operation)
	}
	if realmSource != "" && realmSource != t.Spec.SourceRef {
		other, err := r.workloadConnection(ctx, t.Namespace, realmSource)
		if err != nil || !sameWorkloadConnection(other, s.source) {
			return s, trustFailure("SourceUnavailable")
		}
	}
	s.writer = s.source
	active := s.source.client
	if writes {
		if t.Spec.WriterRef != "" {
			s.writer, err = r.workloadConnection(ctx, t.Namespace, t.Spec.WriterRef)
			if err != nil || !sameWorkloadConnection(s.source, s.writer) {
				return s, trustFailure("SourceUnavailable")
			}
		}
		active = s.writer.client
		s.reader, err = r.workloadConnection(ctx, t.Namespace, t.Spec.DependentReaderRef)
		if err != nil || !sameWorkloadConnection(s.source, s.reader) || s.reader.client.CredentialClientID() == s.writer.client.CredentialClientID() || s.reader.client.CredentialClientID() == s.source.client.CredentialClientID() || s.reader.credentialUID == s.writer.credentialUID || s.reader.credentialUID == s.source.credentialUID {
			return s, trustFailure("SourceUnavailable")
		}
		if s.reader.client.RestrictToDependentClients(t.Spec.RealmRef) != nil {
			return s, trustFailure("SourceUnavailable")
		}
		s.dependencies, err = s.reader.client.ListKubernetesWorkloadTrustDependents(ctx, t.Spec.RealmRef)
		if err != nil {
			return s, trustFailure("IncompleteProviderRead")
		}
		s.dependentCounts, s.dependentOwnersHash, err = r.workloadDependentOwners(ctx, s)
		if err != nil {
			return s, err
		}
	}
	flow, err := active.ValidateEffectiveFederatedClientFlow(ctx, t.Spec.RealmRef)
	if err != nil {
		return s, trustFailure("FlowPrerequisiteMissing")
	}
	s.source.identity.RealmID = flow.RealmID
	s.providers, s.provider, err = active.ObserveKubernetesWorkloadTrust(ctx, t.Spec.RealmRef, t.Spec.KeycloakAlias)
	if err != nil {
		return s, trustFailure("IncompleteProviderRead")
	}
	providerID := expectedProviderID
	if s.provider != nil {
		providerID = s.provider.InternalID
	}
	// Stable physical/source ownership is separate from freshly sealed credential
	// versions, modes, generation, flows and full dependency inventories.
	sourceHash := workloadtrust.Digest("source", struct {
		SourceUID, RealmUID, CredentialUID                          types.UID
		Origin, Trust, CA, CARef, AdminRef, ClientID, Mode, RealmID string
	}{s.source.instance.UID, s.realm.UID, s.source.credentialUID, s.source.identity.Origin, s.source.identity.Trust, s.source.identity.CAIdentity, s.source.instance.Spec.TLSCARef, s.source.instance.Spec.AdminRef.Name, s.source.client.CredentialClientID(), s.source.instance.Spec.Mode, flow.RealmID})
	if value := t.Annotations[workloadtrust.CheckpointKey]; value != "" {
		checkpoint, checkpointErr := workloadtrust.ParseCheckpoint(value)
		if checkpointErr != nil || checkpoint.Owner != string(t.UID) || checkpoint.RealmID != flow.RealmID || checkpoint.SourceHash != sourceHash || providerID != "" && checkpoint.ProviderID != providerID {
			return s, trustFailure("OwnershipConflict")
		}
		s.checkpoint = &checkpoint
		providerID = checkpoint.ProviderID
	}
	if providerID == "" {
		providerID = workloadtrust.PlannedProviderID(string(t.UID), flow.RealmID, sourceHash)
	}
	if err := r.workloadConflicts(ctx, s); err != nil {
		return s, err
	}
	if r.DiscoveryCheck != nil {
		s.discovery, err = r.DiscoveryCheck(ctx, i)
	} else {
		s.discovery, err = r.currentWorkloadDiscovery(ctx, i)
	}
	if err != nil || s.discovery.Issuer != i.Issuer || !workloadtrust.ValidHTTPS(s.discovery.JWKSURL) || !iamcontract.ValidDigest(s.discovery.KeysHash) {
		return s, trustFailure("DiscoverySourceMismatch")
	}
	connectionEvidence := []any{workloadConnectionEvidence(s.source)}
	if writes {
		connectionEvidence = append(connectionEvidence, workloadConnectionEvidence(s.writer), workloadConnectionEvidence(s.reader))
	}
	importEvidence := []any{}
	for _, operation := range s.imports {
		importEvidence = append(importEvidence, struct {
			Name       string
			UID        types.UID
			Generation int64
			Spec       api.HankoImportSpec
		}{operation.Name, operation.UID, operation.Generation, operation.Spec})
	}
	freshHash := workloadtrust.Digest("fresh-references", struct {
		Spec                                          api.HankoWorkloadTrustSpec
		RealmUID                                      types.UID
		RealmGeneration                               int64
		RealmSource, RealmImport, TrustImport, Tenant string
		Approval                                      adoption.Approval
		AgeApproval                                   string
		Connections                                   []any
		Discovery                                     workloadtrust.DiscoveryEvidence
		ForeignProviders                              string
		Imports                                       []any
	}{t.Spec, s.realm.UID, s.realm.Generation, realmSource, s.realm.Labels[importedByLabel], t.Labels[importedByLabel], t.Labels["hanko.sh/tenant"], approval, workloadAgeApprovalIdentity(t.Annotations), connectionEvidence, s.discovery, s.foreignInventoryHash, importEvidence})
	s.plan, err = workloadtrust.Compile(i, workloadtrust.References{Owner: string(t.UID), Generation: t.Generation, RealmID: flow.RealmID, ProviderID: providerID, SourceHash: sourceHash, FreshReferencesHash: freshHash, FlowHash: workloadtrust.Digest("flow", flow), DependenciesHash: workloadtrust.Digest("dependencies", struct {
		Native []keycloak.DependentClient
		Owners string
	}{s.dependencies, s.dependentOwnersHash})})
	if err != nil {
		return s, trustFailure("UnsupportedNativeState")
	}
	if err := r.verifyWorkloadReferences(ctx, s, writes); err != nil {
		return s, err
	}
	return s, nil
}

func (s *workloadSnapshot) closeIdleConnections() {
	for _, connection := range []workloadConnection{s.source, s.writer, s.reader} {
		if connection.client != nil {
			connection.client.CloseIdleConnections()
		}
	}
}

// Slow provider/discovery reads must not turn their initially read references
// into current execution authority. Re-read every local authority uncached at
// the end of the snapshot, including connection Secrets and approved metadata.
func (r *HankoWorkloadTrustReconciler) verifyWorkloadReferences(ctx context.Context, s *workloadSnapshot, writes bool) error {
	var target api.HankoWorkloadTrust
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(&s.trust), &target) != nil || target.UID != s.trust.UID || target.Generation != s.trust.Generation || !reflect.DeepEqual(target.Spec, s.trust.Spec) || !target.DeletionTimestamp.Equal(s.trust.DeletionTimestamp) || !reflect.DeepEqual(target.Labels, s.trust.Labels) {
		return trustFailure("CurrentIdentityChanged")
	}
	for _, key := range []string{adoption.SourceAnnotation, adoption.ContractAnnotation, adoption.CandidateAnnotation, workloadtrust.AgeApprovalKey, workloadtrust.CheckpointKey} {
		if target.Annotations[key] != s.trust.Annotations[key] {
			return trustFailure("CurrentIdentityChanged")
		}
	}
	var realm api.HankoRealm
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(&s.realm), &realm) != nil || realm.UID != s.realm.UID || realm.Generation != s.realm.Generation || !reflect.DeepEqual(realm.Spec, s.realm.Spec) || !realm.DeletionTimestamp.Equal(s.realm.DeletionTimestamp) || !reflect.DeepEqual(realm.Labels, s.realm.Labels) || realm.Annotations[adoption.SourceAnnotation] != s.realm.Annotations[adoption.SourceAnnotation] {
		return trustFailure("CurrentIdentityChanged")
	}
	for _, operation := range s.imports {
		var current api.HankoImport
		if r.APIReader.Get(ctx, client.ObjectKeyFromObject(&operation), &current) != nil || current.UID != operation.UID || current.Generation != operation.Generation || !reflect.DeepEqual(current.Spec, operation.Spec) || !current.DeletionTimestamp.IsZero() {
			return trustFailure("CurrentIdentityChanged")
		}
	}
	connections := []workloadConnection{s.source}
	if writes {
		connections = append(connections, s.writer, s.reader)
		_, owners, err := r.workloadDependentOwners(ctx, s)
		if err != nil || owners != s.dependentOwnersHash {
			return trustFailure("CurrentIdentityChanged")
		}
	}
	for _, before := range connections {
		current, err := r.workloadConnection(ctx, before.instance.Namespace, before.instance.Name)
		if err != nil || !reflect.DeepEqual(workloadConnectionEvidence(current), workloadConnectionEvidence(before)) {
			return trustFailure("CurrentIdentityChanged")
		}
	}
	if r.validateWorkloadCluster(ctx, target.Spec.Kubernetes.ClusterAnchor) != nil {
		return trustFailure("AnchorMismatch")
	}
	return r.workloadConflicts(ctx, s)
}

func workloadAgeApprovalIdentity(annotations map[string]string) string {
	// Only validated digest metadata can enter a plan. Approval binds that plan
	// through a separate authority digest below; its own payload is not recursive.
	return "explicit-age-review-v1"
}

func (r *HankoWorkloadTrustReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if r.APIReader == nil {
		return ctrl.Result{}, trustFailure("SourceUnavailable")
	}
	var current api.HankoWorkloadTrust
	if err := r.APIReader.Get(ctx, req.NamespacedName, &current); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	observe := effectiveWorkloadTrustMode(&current) == ModeObserve
	approval, approvalError := adoption.ParseApproval(current.Annotations)
	writes := !observe || approvalError == nil && approval.Requested && current.DeletionTimestamp.IsZero()
	if observe && controllerutil.ContainsFinalizer(&current, workloadTrustFinalizer) {
		patch := client.MergeFrom(current.DeepCopy())
		controllerutil.RemoveFinalizer(&current, workloadTrustFinalizer)
		if err := r.Patch(ctx, &current, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if observe && !current.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	s, err := r.workloadSnapshot(ctx, req.NamespacedName, writes, "")
	if err != nil {
		return r.workloadStatus(ctx, &current, s, trustReason(err), false)
	}
	if s.trust.UID != current.UID {
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if !current.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&current, workloadTrustFinalizer) {
			return ctrl.Result{}, nil
		}
		return r.deleteWorkloadTrust(ctx, s)
	}
	if observe {
		if approval.Requested {
			return r.acquireWorkloadTrust(ctx, s, approval)
		}
		ready := qualifiedWorkloadRead(s) && workloadConfigurationMatches(s)
		return r.workloadStatus(ctx, &s.trust, s, "Observed", ready)
	}
	if s.provider != nil && (s.provider.Config.Owner != string(s.trust.UID) || s.provider.Config.Journal == "") {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	if s.provider != nil && !workloadOwnershipMatches(s) {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	if s.provider == nil && (s.checkpoint != nil && s.checkpoint.Step != "CreateReserved" || s.checkpoint == nil && controllerutil.ContainsFinalizer(&s.trust, workloadTrustFinalizer)) {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	if s.provider != nil && (s.checkpoint == nil || s.checkpoint.Step != "Owned") {
		return r.workloadCheckpoint(ctx, s, "Owned", true)
	}
	if !controllerutil.ContainsFinalizer(&s.trust, workloadTrustFinalizer) {
		if s.provider != nil {
			return r.workloadCheckpoint(ctx, s, "Owned", true)
		}
		return r.workloadCheckpoint(ctx, s, "CreateReserved", true)
	}
	if s.provider != nil && workloadConfigurationMatches(s) {
		journal, _ := workloadtrust.ParseJournal(s.provider.Config.Journal)
		if journal.Generation == s.trust.Generation && journal.InputHash == string(s.plan.Identity().Intent) && journal.Step == "Applied" {
			return r.workloadStatus(ctx, &s.trust, s, "Ready", true)
		}
	}
	if s.provider != nil && s.provider.Config.MaxAge != s.plan.Intent().MaxAge {
		if s.plan.ApproveAge(s.trust.Annotations[workloadtrust.AgeApprovalKey], s.provider.Config.MaxAge) != nil {
			return r.workloadStatus(ctx, &s.trust, s, "SharedAgeReviewRequired", false)
		}
	}
	fresh, err := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, s.plan.References().ProviderID)
	if err != nil || s.plan.Validate(freshPlan(fresh)) != nil || !sameWorkloadProvider(s.provider, providerOf(fresh)) {
		return r.workloadStatus(ctx, &s.trust, s, "CurrentIdentityChanged", false)
	}
	// Approval is deliberately excluded from its own plan hash, but compared
	// exactly and revalidated immediately before and after the write.
	if s.trust.Annotations[workloadtrust.AgeApprovalKey] != fresh.trust.Annotations[workloadtrust.AgeApprovalKey] {
		return r.workloadStatus(ctx, &s.trust, s, "SharedAgeReviewRequired", false)
	}
	if fresh.provider == nil {
		if fresh.checkpoint == nil || fresh.checkpoint.Step != "CreateReserved" {
			return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
		}
		if _, err := r.workloadCheckpoint(ctx, fresh, "CreateAttempted", true); err != nil {
			return ctrl.Result{}, err
		}
		attempt, readErr := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&fresh.trust), true, fresh.plan.References().ProviderID)
		if readErr != nil || fresh.plan.Validate(freshPlan(attempt)) != nil || attempt.provider != nil || attempt.checkpoint == nil || attempt.checkpoint.Step != "CreateAttempted" {
			return r.workloadStatus(ctx, &fresh.trust, fresh, "CurrentIdentityChanged", false)
		}
		fresh = attempt
	}
	desired := desiredWorkloadProvider(fresh)
	journal, err := fresh.plan.Journal(nativeWorkloadStateHash(desired), "Applied")
	if err != nil {
		return r.workloadStatus(ctx, &s.trust, s, "OwnershipConflict", false)
	}
	desired.Config.Journal = journal
	if fresh.provider == nil {
		err = fresh.writer.client.CreateOwnedKubernetesWorkloadTrust(ctx, fresh.trust.Spec.RealmRef, desired)
	} else {
		err = fresh.writer.client.UpdateOwnedKubernetesWorkloadTrust(ctx, fresh.trust.Spec.RealmRef, *fresh.provider, desired)
	}
	// Read back even after transport failure: accepted writes with lost ACKs
	// are recognized by the exact UUID, journal, owner and expected semantics.
	after, readErr := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, fresh.plan.References().ProviderID)
	if readErr != nil || fresh.plan.Validate(freshPlan(after)) != nil || after.trust.Annotations[workloadtrust.AgeApprovalKey] != fresh.trust.Annotations[workloadtrust.AgeApprovalKey] || !workloadOwnershipMatches(after) || !workloadConfigurationMatches(after) || after.provider.Config.Journal != journal {
		_ = err
		return r.workloadStatus(ctx, &s.trust, s, "IncompleteProviderRead", false)
	}
	if _, err := r.workloadCheckpoint(ctx, after, "Owned", true); err != nil {
		return ctrl.Result{}, err
	}
	return r.workloadStatus(ctx, &after.trust, after, "Ready", true)
}

func (r *HankoWorkloadTrustReconciler) workloadCheckpoint(ctx context.Context, s *workloadSnapshot, step string, finalizer bool) (ctrl.Result, error) {
	value, err := s.plan.Checkpoint(step)
	if err != nil {
		return ctrl.Result{}, err
	}
	patch := client.MergeFrom(s.trust.DeepCopy())
	if s.trust.Annotations == nil {
		s.trust.Annotations = map[string]string{}
	}
	s.trust.Annotations[workloadtrust.CheckpointKey] = value
	if finalizer {
		controllerutil.AddFinalizer(&s.trust, workloadTrustFinalizer)
	}
	if err := r.Patch(ctx, &s.trust, patch); err != nil {
		return ctrl.Result{}, err
	}
	c, _ := workloadtrust.ParseCheckpoint(value)
	s.checkpoint = &c
	return ctrl.Result{RequeueAfter: requeueImmediately}, nil
}

func freshPlan(s *workloadSnapshot) workloadtrust.Plan {
	if s == nil {
		return workloadtrust.Plan{}
	}
	return s.plan
}
func providerOf(s *workloadSnapshot) *keycloak.KubernetesTrust {
	if s == nil {
		return nil
	}
	return s.provider
}
func sameWorkloadProvider(a, b *keycloak.KubernetesTrust) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a, b)
}
func qualifiedWorkloadRead(s *workloadSnapshot) bool {
	return s != nil && s.provider != nil && s.provider.Qualified && s.provider.ProviderID == "kubernetes" && workloadtrust.ValidHTTPS(s.provider.Config.Issuer)
}
func workloadOwnershipMatches(s *workloadSnapshot) bool {
	if !qualifiedWorkloadRead(s) || s.provider.Config.Owner != string(s.trust.UID) {
		return false
	}
	j, err := workloadtrust.ParseJournal(s.provider.Config.Journal)
	return err == nil && j.Matches(s.plan, nativeWorkloadStateHash(*s.provider))
}
func workloadConfigurationMatches(s *workloadSnapshot) bool {
	if !qualifiedWorkloadRead(s) {
		return false
	}
	p := s.provider
	i := s.plan.Intent()
	return p.Alias == i.Alias && p.Enabled && p.Config.Issuer == i.Issuer && p.Config.DiscoveryURL == i.DiscoveryURL && p.Config.ClockSkew == "0" && p.Config.MaxAge == i.MaxAge && (i.DiscoveryURL == "" && p.Config.JWKSURL == "" || i.QualifiedVersion == "26.8.0" && p.Config.JWKSURL == s.discovery.JWKSURL)
}
func desiredWorkloadProvider(s *workloadSnapshot) keycloak.KubernetesTrust {
	p := keycloak.KubernetesTrust{InternalID: s.plan.References().ProviderID, Alias: s.trust.Spec.KeycloakAlias, ProviderID: "kubernetes", Enabled: true, Qualified: true}
	if s.provider != nil {
		p = *s.provider
	}
	i := s.plan.Intent()
	p.Enabled = true
	p.Config.Issuer = i.Issuer
	p.Config.DiscoveryURL = i.DiscoveryURL
	p.Config.MaxAge = i.MaxAge
	p.Config.ClockSkew = "0"
	p.Config.Owner = string(s.trust.UID)
	p.Config.JWKSURL = ""
	if i.DiscoveryURL != "" {
		p.Config.JWKSURL = s.discovery.JWKSURL
	}
	return p
}

func (r *HankoWorkloadTrustReconciler) deleteWorkloadTrust(ctx context.Context, s *workloadSnapshot) (ctrl.Result, error) {
	if s.provider == nil {
		// A lost DELETE ACK can release only after current complete absence and
		// dependency inventories; no native client is ever deleted here.
		if s.checkpoint == nil || !s.checkpoint.Matches(s.plan) || s.checkpoint.Step == "AdoptionPending" {
			return r.workloadStatus(ctx, &s.trust, s, "CleanupConflict", false)
		}
		if workloadDependentCount(s) > 0 {
			return r.workloadStatus(ctx, &s.trust, s, "DependentClientsPresent", false)
		}
		patch := client.MergeFrom(s.trust.DeepCopy())
		controllerutil.RemoveFinalizer(&s.trust, workloadTrustFinalizer)
		return ctrl.Result{}, r.Patch(ctx, &s.trust, patch)
	}
	if !workloadOwnershipMatches(s) {
		return r.workloadStatus(ctx, &s.trust, s, "CleanupConflict", false)
	}
	if workloadDependentCount(s) > 0 {
		return r.workloadStatus(ctx, &s.trust, s, "DependentClientsPresent", false)
	}
	fresh, err := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, s.provider.InternalID)
	if err != nil || s.plan.Validate(freshPlan(fresh)) != nil || !sameWorkloadProvider(s.provider, providerOf(fresh)) || !workloadOwnershipMatches(fresh) {
		return r.workloadStatus(ctx, &s.trust, s, "CleanupConflict", false)
	}
	err = fresh.writer.client.DeleteOwnedKubernetesWorkloadTrust(ctx, fresh.trust.Spec.RealmRef, *fresh.provider)
	after, readErr := r.workloadSnapshot(ctx, client.ObjectKeyFromObject(&s.trust), true, s.provider.InternalID)
	if readErr != nil || fresh.plan.Validate(freshPlan(after)) != nil || after.provider != nil || workloadDependentCount(after) > 0 {
		_ = err
		return r.workloadStatus(ctx, &s.trust, s, "CleanupConflict", false)
	}
	patch := client.MergeFrom(after.trust.DeepCopy())
	controllerutil.RemoveFinalizer(&after.trust, workloadTrustFinalizer)
	return ctrl.Result{}, r.Patch(ctx, &after.trust, patch)
}
func workloadDependentCount(s *workloadSnapshot) int {
	return int(s.dependentCounts.Owned + s.dependentCounts.Foreign + s.dependentCounts.Ambiguous)
}

func (r *HankoWorkloadTrustReconciler) workloadStatus(ctx context.Context, t *api.HankoWorkloadTrust, s *workloadSnapshot, reason string, ready bool) (ctrl.Result, error) {
	patch := client.MergeFrom(t.DeepCopy())
	t.Status.Phase = "Error"
	if ready {
		t.Status.Phase = "Ready"
	}
	t.Status.ObservedGeneration = t.Generation
	t.Status.AppliedPlanHash = ""
	t.Status.ObservationComplete = false
	t.Status.AdoptionCandidate = nil
	t.Status.AdoptionReceipt = nil
	t.Status.ProviderID = ""
	t.Status.RealmID = ""
	t.Status.ContractVersion = ""
	t.Status.IntentHash = ""
	t.Status.EvaluatedPlanHash = ""
	t.Status.ObservedStateHash = ""
	t.Status.SharedAgeReviewHash = ""
	t.Status.DependentInventoryHash = ""
	t.Status.Dependents = api.WorkloadTrustDependents{}
	t.Status.CapabilityEvidence = api.IAMCapabilityEvidence{}
	t.Status.Capabilities = api.WorkloadTrustCapabilities{}
	if s != nil && s.plan.Identity().Contract == iamcontract.Version {
		id := s.plan.Identity()
		t.Status.ContractVersion = string(id.Contract)
		t.Status.IntentHash = string(id.Intent)
		t.Status.EvaluatedPlanHash = string(id.Plan)
		t.Status.RealmID = s.plan.References().RealmID
		t.Status.DependentInventoryHash = s.plan.References().DependenciesHash
		t.Status.Dependents = s.dependentCounts
		t.Status.CapabilityEvidence = api.IAMCapabilityEvidence{Source: "adapter-and-real-qualification", QualificationWindow: "26.7.5,26.8.0"}
		t.Status.Capabilities = api.WorkloadTrustCapabilities{KubernetesWorkloadIdentity: true, FederatedClientAuthentication: true, ShortLivedClientAssertion: true, IssuerDiscoveryOverride: s.plan.Intent().QualifiedVersion == "26.8.0"}
		if s.provider != nil {
			t.Status.ProviderID = s.provider.InternalID
			t.Status.ObservedStateHash = nativeWorkloadStateHash(*s.provider)
			t.Status.ObservationComplete = qualifiedWorkloadRead(s)
			t.Status.AdoptionCandidate = workloadTrustCandidate(s)
			if s.provider.Config.Receipt != "" {
				receipt, err := adoption.ParseReceipt(s.provider.Config.Receipt)
				if err == nil && receipt.TargetKind == "HankoWorkloadTrust" && receipt.TargetUID == string(t.UID) && workloadOwnershipMatches(s) {
					t.Status.AdoptionReceipt = &api.AdoptionReceiptStatus{ContractVersion: string(receipt.ContractVersion), CandidateHash: receipt.CandidateHash, State: "Verified"}
				}
			}
			if s.provider.Config.MaxAge != s.plan.Intent().MaxAge {
				t.Status.SharedAgeReviewHash = s.plan.AgeReview(s.provider.Config.MaxAge).ReviewHash
			} else {
				t.Status.SharedAgeReviewHash = ""
			}
		}
		if ready && effectiveWorkloadTrustMode(t) == ModeManage {
			t.Status.AppliedPlanHash = string(id.Plan)
		}
	}
	condition := metav1.ConditionFalse
	if ready {
		condition = metav1.ConditionTrue
	}
	message := "Trust configuration requires administrator review; no workload authentication is asserted."
	if reason == "FlowPrerequisiteMissing" {
		message = "Administrator prerequisite: restore the qualified effective federated-jwt client authentication flow; this controller never repairs flows."
	}
	meta.SetStatusCondition(&t.Status.Conditions, metav1.Condition{Type: "Ready", Status: condition, Reason: reason, Message: message, ObservedGeneration: t.Generation})
	if err := r.Status().Patch(ctx, t, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

func (r *HankoWorkloadTrustReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&api.HankoWorkloadTrust{}).Complete(r)
}
