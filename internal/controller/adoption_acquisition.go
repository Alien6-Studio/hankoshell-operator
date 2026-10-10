package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type adoptionGuard func(context.Context, client.Object, *keycloak.Client) error

// Acquisition is a separate Observe transaction. Status is output only. A
// provider receipt can recover a lost PUT acknowledgement or status patch, but
// cannot authorize semantic reconciliation or deletion.
func reconcileOwnershipAcquisition(ctx context.Context, kube client.Client, reader client.Reader, cached client.Object, writer *keycloak.Client, guard adoptionGuard) (bool, ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if reader == nil {
		reader = kube
	}
	current, ok := cached.DeepCopyObject().(client.Object)
	if !ok {
		return true, ctrl.Result{}, errAdoptionIdentity
	}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(cached), current); err != nil {
		return true, ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if current.GetUID() != cached.GetUID() {
		return true, ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if !acquisitionMetadataEqual(current, cached) {
		return true, ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}
	if !current.GetDeletionTimestamp().IsZero() {
		return false, ctrl.Result{}, nil
	}
	approval, err := adoption.ParseApproval(current.GetAnnotations())
	if err != nil {
		reason := "AdoptionApprovalRequired"
		if errors.Is(err, adoption.ErrApprovalConflict) {
			reason = "AdoptionApprovalConflict"
		}
		return adoptionResult(ctx, kube, current, nil, approval, "Conflict", reason)
	}
	// Manage of an acquired leaf is deliberately deferred to #49. Read the
	// provider, not status, even when approval annotations have been removed.
	if targetAdoptionMode(current) == ModeManage {
		if writer == nil {
			return false, ctrl.Result{}, nil
		}
		s, readErr := readAcquisitionSnapshot(ctx, writer, current)
		if readErr != nil {
			if approval.Requested {
				return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionIncomplete")
			}
			return false, ctrl.Result{}, nil
		}
		if s.receiptPresent() {
			return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "ManagePreservationUnqualified")
		}
		if approval.Requested {
			return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionUnsupported")
		}
		return false, ctrl.Result{}, nil
	}
	if !approval.Requested {
		return false, ctrl.Result{}, nil
	}
	source, err := resolveAdoptionSource(ctx, reader, current)
	if err != nil {
		return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionIdentityChanged")
	}
	observer, err := buildKCClientForInstance(ctx, reader, source, false)
	if err != nil || writer == nil {
		return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionIncomplete")
	}
	observer.RestrictToInventory()
	before, err := readAcquisitionSnapshot(ctx, observer, current)
	if err != nil {
		return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionIncomplete")
	}
	receipt, _ := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: adoptionTargetKind(current), TargetUID: string(current.GetUID()), CandidateHash: approval.CandidateHash}).Canonical()
	recovering := before.exactReceipt(current, receipt)
	if before.receiptPresent() && !recovering || !before.unmarked() && !before.owned(current) {
		return adoptionResult(ctx, kube, current, nil, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	if before.owned(current) && !before.receiptPresent() {
		return adoptionResult(ctx, kube, current, nil, approval, "Verified", "AlreadyOwned")
	}
	if (before.client != nil && !before.client.QualifiedLeaf()) || (before.role != nil && !before.role.QualifiedLeaf()) {
		state, reason := "Conflict", "AdoptionUnsupported"
		if recovering {
			state, reason = "Partial", "AdoptionPartial"
		}
		return adoptionResult(ctx, kube, current, nil, approval, state, reason)
	}
	candidate := readTargetCandidate(ctx, kube, reader, current, recovering)
	if reason := adoptionCandidateFailure(candidate, approval); reason != "" {
		state := "Conflict"
		if recovering {
			state, reason = "Partial", "AdoptionPartial"
		}
		return adoptionResult(ctx, kube, current, candidate, approval, state, reason)
	}
	if recovering {
		return adoptionResult(ctx, kube, current, candidate, approval, "Verified", "AdoptionVerified")
	}
	writerOrigin, originErr := adoptionEndpointOrigin(writer.BaseURL())
	if originErr != nil || writerOrigin != candidate.ProviderIdentity.Origin {
		return adoptionResult(ctx, kube, current, candidate, approval, "Conflict", "AdoptionIdentityChanged")
	}
	wRealm, err := writer.GetRealm(ctx, targetAdoptionRealm(current))
	if err != nil || wRealm.ID != candidate.ProviderIdentity.RealmID {
		return adoptionResult(ctx, kube, current, candidate, approval, "Conflict", "AdoptionIdentityChanged")
	}
	if guard != nil && guard(ctx, current, writer) != nil {
		return adoptionResult(ctx, kube, current, candidate, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	wBefore, err := readAcquisitionSnapshot(ctx, writer, current)
	if err != nil || !before.same(wBefore) || !wBefore.unmarked() {
		return adoptionResult(ctx, kube, current, candidate, approval, "Conflict", "AdoptionObservationChanged")
	}
	// Re-read uncached metadata/spec/latch and the full reviewed candidate at
	// the mutation boundary. A label or annotation edit need not change generation.
	if !acquisitionTargetUnchanged(ctx, reader, current) {
		return adoptionResult(ctx, kube, current, candidate, approval, "Conflict", "AdoptionIdentityChanged")
	}
	last := readTargetCandidate(ctx, kube, reader, current, false)
	if reason := adoptionCandidateFailure(last, approval); reason != "" {
		return adoptionResult(ctx, kube, current, last, approval, "Conflict", reason)
	}
	if guard != nil && guard(ctx, current, writer) != nil {
		return adoptionResult(ctx, kube, current, last, approval, "Conflict", "AdoptionOwnershipConflict")
	}
	// A failed PUT may have committed. Always read back before deciding; never
	// retry the PUT inside this transaction and never roll back external state.
	_ = wBefore.mark(ctx, writer, current, receipt)
	after, err := readAcquisitionSnapshot(ctx, observer, current)
	if err != nil || !after.exactReceipt(current, receipt) || !before.same(after) || !acquisitionTargetUnchanged(ctx, reader, current) {
		return adoptionResult(ctx, kube, current, last, approval, "Partial", "AdoptionPartial")
	}
	verified := readTargetCandidate(ctx, kube, reader, current, true)
	if adoptionCandidateFailure(verified, approval) != "" {
		return adoptionResult(ctx, kube, current, verified, approval, "Partial", "AdoptionPartial")
	}
	return adoptionResult(ctx, kube, current, verified, approval, "Verified", "AdoptionVerified")
}

func adoptionCandidateFailure(c *api.AdoptionCandidateStatus, a adoption.Approval) string {
	if c == nil || !c.Complete || c.Truncated {
		return "AdoptionIncomplete"
	}
	for _, d := range c.Diff {
		if d.Code == "recreation-required" {
			return "AdoptionRequiresRecreation"
		}
		// Credential exclusion is intentional. Other opaque/native state is
		// not an acquisition exception to #47's reviewed semantic boundary.
		if d.Classification != string(adoption.SecurityExcluded) && d.RoundTrip != string(adoption.Lossless) && !qualifiedDefaultDiff(d) {
			return "AdoptionUnsupported"
		}
	}
	if !c.Approvable {
		return "AdoptionUnsupported"
	}
	if c.CandidateHash != a.CandidateHash {
		return "AdoptionObservationChanged"
	}
	return ""
}

func qualifiedDefaultDiff(d api.AdoptionDiffEntry) bool {
	const prefix = "keycloakDefault."
	return strings.HasPrefix(d.Field, prefix) && d.Code == string(adoption.NativeReadOnly) && d.Classification == string(adoption.Preserved) && d.RoundTrip == string(adoption.PreservedNative) && d.Current != nil && d.Desired == nil && adoption.KeycloakDefault(strings.TrimPrefix(d.Field, prefix), d.Current.Text)
}

func targetAdoptionMode(o client.Object) string {
	switch t := o.(type) {
	case *api.HankoApplication:
		return effectiveMode(t)
	case *api.HankoRole:
		return effectiveRoleMode(t)
	case *api.HankoServiceAccount:
		return effectiveServiceAccountMode(t)
	}
	return ""
}
func targetAdoptionRealm(o client.Object) string {
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Spec.RealmRef
	case *api.HankoRole:
		return t.Spec.RealmRef
	case *api.HankoServiceAccount:
		return t.Spec.RealmRef
	}
	return ""
}
func adoptionTargetSpec(o client.Object) any {
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Spec
	case *api.HankoRole:
		return t.Spec
	case *api.HankoServiceAccount:
		return t.Spec
	}
	return nil
}
func acquisitionTargetUnchanged(ctx context.Context, reader client.Reader, expected client.Object) bool {
	return acquisitionCurrentTarget(ctx, reader, expected, false)
}

func acquisitionCurrentTarget(ctx context.Context, reader client.Reader, expected client.Object, deleting bool) bool {
	current, ok := expected.DeepCopyObject().(client.Object)
	return ok && reader.Get(ctx, client.ObjectKeyFromObject(expected), current) == nil && current.GetUID() == expected.GetUID() && current.GetDeletionTimestamp().IsZero() != deleting && acquisitionMetadataEqual(current, expected)
}

func acquisitionMetadataEqual(current, expected client.Object) bool {
	return current.GetGeneration() == expected.GetGeneration() && current.GetDeletionTimestamp().Equal(expected.GetDeletionTimestamp()) && reflect.DeepEqual(current.GetAnnotations(), expected.GetAnnotations()) && reflect.DeepEqual(current.GetLabels(), expected.GetLabels()) && reflect.DeepEqual(adoptionTargetSpec(current), adoptionTargetSpec(expected))
}

func adoptionResult(ctx context.Context, kube client.Client, o client.Object, candidate *api.AdoptionCandidateStatus, a adoption.Approval, state, reason string) (bool, ctrl.Result, error) {
	base, ok := o.DeepCopyObject().(client.Object)
	if !ok {
		return true, ctrl.Result{}, errAdoptionIdentity
	}
	patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
	receipt := &api.AdoptionReceiptStatus{ContractVersion: string(adoption.Version), CandidateHash: a.CandidateHash, State: state}
	if _, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: adoptionTargetKind(o), TargetUID: string(o.GetUID()), CandidateHash: a.CandidateHash}).Canonical(); err != nil || reason == "AlreadyOwned" {
		receipt = nil
	}
	condition := metav1.ConditionFalse
	if state == "Verified" {
		condition = metav1.ConditionTrue
	}
	message := "ownership acquisition requires live reviewed identity and lossless observation; semantic Manage is a separate decision"
	switch t := o.(type) {
	case *api.HankoApplication:
		t.Status.AdoptionCandidate, t.Status.AdoptionReceipt = candidate, receipt
		t.Status.AppliedGeneration, t.Status.AppliedPlanHash = 0, ""
		iamCondition(&t.Status.Conditions, t.Generation, "OwnershipAdopted", condition, reason, message)
	case *api.HankoRole:
		t.Status.AdoptionCandidate, t.Status.AdoptionReceipt = candidate, receipt
		t.Status.AppliedGeneration, t.Status.AppliedPlanHash = 0, ""
		iamCondition(&t.Status.Conditions, t.Generation, "OwnershipAdopted", condition, reason, message)
	case *api.HankoServiceAccount:
		t.Status.AdoptionCandidate, t.Status.AdoptionReceipt = candidate, receipt
		t.Status.SecretRef, t.Status.LastRotated, t.Status.NextRotation = nil, nil, nil
		iamCondition(&t.Status.Conditions, t.Generation, "OwnershipAdopted", condition, reason, message)
	}
	err := kube.Status().Patch(ctx, o, patch)
	return true, ctrl.Result{RequeueAfter: requeueWithJitter()}, err
}

type acquisitionSnapshot struct {
	client *keycloak.ClientOwnershipSnapshot
	role   *keycloak.RoleOwnershipSnapshot
}

func readAcquisitionSnapshot(ctx context.Context, kc *keycloak.Client, o client.Object) (*acquisitionSnapshot, error) {
	s := &acquisitionSnapshot{}
	var err error
	switch t := o.(type) {
	case *api.HankoApplication:
		s.client, err = kc.ReadClientOwnership(ctx, t.Spec.RealmRef, t.Spec.ClientID)
	case *api.HankoServiceAccount:
		s.client, err = kc.ReadClientOwnership(ctx, t.Spec.RealmRef, t.Spec.ClientID)
	case *api.HankoRole:
		s.role, err = kc.ReadRoleOwnership(ctx, t.Spec.RealmRef, t.Spec.Name)
	default:
		err = keycloak.ErrAdoptionPrecondition
	}
	return s, err
}
func (s *acquisitionSnapshot) attributes() map[string][]string {
	if s == nil {
		return nil
	}
	if s.role != nil {
		return s.role.Role.Attributes
	}
	r := map[string][]string{}
	if s.client != nil {
		for key, value := range s.client.Application.Attributes {
			r[key] = []string{value}
		}
	}
	return r
}
func (s *acquisitionSnapshot) receiptPresent() bool {
	_, present := s.attributes()[adoption.ReceiptKey]
	return present
}
func (s *acquisitionSnapshot) unmarked() bool {
	for key := range s.attributes() {
		if adoption.ReservedAttribute(key) {
			return false
		}
	}
	return true
}
func (s *acquisitionSnapshot) owned(o client.Object) bool {
	attrs := s.attributes()
	allowed := map[string]bool{adoption.ReceiptKey: true}
	key := adoption.ApplicationOwnerKey
	if s.role != nil {
		key = adoption.RoleOwnerKey
	}
	if adoptionTargetKind(o) == "HankoServiceAccount" {
		allowed[adoption.ClientOwnerKindKey], allowed[adoption.ClientOwnerUIDKey] = true, true
		if !reflect.DeepEqual(attrs[adoption.ClientOwnerKindKey], []string{"HankoServiceAccount"}) || !reflect.DeepEqual(attrs[adoption.ClientOwnerUIDKey], []string{string(o.GetUID())}) {
			return false
		}
	} else {
		allowed[key] = true
		if !reflect.DeepEqual(attrs[key], []string{string(o.GetUID())}) || o.GetUID() == "" {
			return false
		}
	}
	for key := range attrs {
		if adoption.ReservedAttribute(key) && !allowed[key] {
			return false
		}
	}
	return true
}
func (s *acquisitionSnapshot) exactReceipt(o client.Object, expected string) bool {
	values := s.attributes()[adoption.ReceiptKey]
	return s.owned(o) && reflect.DeepEqual(values, []string{expected})
}
func (s *acquisitionSnapshot) same(other *acquisitionSnapshot) bool {
	if s == nil || other == nil {
		return false
	}
	if s.role != nil {
		return s.role.SameSemantics(other.role)
	}
	return s.client.SameSemantics(other.client)
}
func (s *acquisitionSnapshot) mark(ctx context.Context, kc *keycloak.Client, o client.Object, receipt string) error {
	uid, realm := string(o.GetUID()), targetAdoptionRealm(o)
	switch o.(type) {
	case *api.HankoApplication:
		return kc.MarkApplicationAdoption(ctx, realm, s.client, uid, receipt)
	case *api.HankoRole:
		return kc.MarkRoleAdoption(ctx, realm, s.role, uid, receipt)
	case *api.HankoServiceAccount:
		return kc.MarkServiceAccountAdoption(ctx, realm, s.client, uid, receipt)
	}
	return keycloak.ErrAdoptionPrecondition
}
