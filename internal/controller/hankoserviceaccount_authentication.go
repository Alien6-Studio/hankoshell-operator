package controller

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func authenticationMode(sa *api.HankoServiceAccount) string {
	if workloadbinding.KubernetesMode(sa) {
		return "Kubernetes"
	}
	return "Secret"
}

func (r *HankoServiceAccountReconciler) deleteFederatedServiceAccount(ctx context.Context, sa *api.HankoServiceAccount) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(sa, saFinalizerName) {
		return ctrl.Result{}, nil
	}
	s, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
	if err != nil {
		return r.authenticationTransitionResult(ctx, sa, nil, nil, workloadbinding.Reason(err))
	}
	verify := func(ctx context.Context) error {
		fresh, e := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
		if e != nil || fresh.seal != s.seal || effectiveServiceAccountMode(&fresh.account) != ModeManage {
			return workloadauth.ErrPrecondition
		}
		if conflict, e := r.serviceAccountOwnershipConflict(ctx, &fresh.account, fresh.source.client); e != nil || conflict != "" {
			return workloadauth.ErrPrecondition
		}
		return nil
	}
	if s.native != nil {
		if err := s.source.client.DeleteFederatedServiceAccountIfOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa), s.native, verify); err != nil {
			return r.authenticationTransitionResult(ctx, sa, s, nil, "AuthenticationCleanupConflict")
		}
	}
	fresh, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
	if err != nil || fresh.native != nil || fresh.authoritySeal != s.authoritySeal || effectiveServiceAccountMode(&fresh.account) != ModeManage {
		return r.authenticationTransitionResult(ctx, sa, nil, nil, "AuthenticationCleanupConflict")
	}
	if conflict, err := r.serviceAccountOwnershipConflict(ctx, &fresh.account, fresh.source.client); err != nil || conflict != "" {
		return r.authenticationTransitionResult(ctx, sa, nil, nil, "OwnershipConflict")
	}
	controllerutil.RemoveFinalizer(sa, saFinalizerName)
	return ctrl.Result{}, r.Update(ctx, sa)
}
func nativeAuthenticationMode(a *keycloak.Application) string {
	if a == nil {
		return "Absent"
	}
	if a.ClientAuthenticatorType == "federated-jwt" {
		return "Kubernetes"
	}
	return "Secret"
}

// saveAuthenticationJournal uses authoritative reads, optimistic concurrency
// and read-back, including accepted patches whose acknowledgement was lost.
func (r *HankoServiceAccountReconciler) saveAuthenticationJournal(ctx context.Context, sa *api.HankoServiceAccount, j *workloadauth.Journal, verify func(context.Context) error) error {
	if !j.Valid() || verify(ctx) != nil {
		return workloadbinding.Failure("AuthenticationTransactionStale")
	}
	var live api.HankoServiceAccount
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(sa), &live) != nil || live.UID != sa.UID || live.Generation != sa.Generation || !reflect.DeepEqual(live.Spec, sa.Spec) || !reflect.DeepEqual(live.Labels, sa.Labels) || effectiveServiceAccountMode(&live) != ModeManage || !live.DeletionTimestamp.IsZero() {
		return workloadbinding.Failure("AuthenticationTransactionStale")
	}
	value := workloadauth.Encode(j)
	if live.Annotations[workloadauth.JournalKey] != value {
		patch := client.MergeFromWithOptions(live.DeepCopy(), client.MergeFromWithOptimisticLock{})
		live.Annotations = maps.Clone(live.Annotations)
		if live.Annotations == nil {
			live.Annotations = map[string]string{}
		}
		live.Annotations[workloadauth.JournalKey] = value
		_ = r.Patch(ctx, &live, patch)
	}
	if verify(ctx) != nil || r.APIReader.Get(ctx, client.ObjectKeyFromObject(sa), &live) != nil || live.UID != sa.UID || live.Generation != sa.Generation || live.Annotations[workloadauth.JournalKey] != value {
		return workloadbinding.Failure("AuthenticationCheckpointUnconfirmed")
	}
	return nil
}

func (r *HankoServiceAccountReconciler) authenticationVerifier(sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot) func(context.Context) error {
	return func(ctx context.Context) error {
		fresh, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, false)
		if err != nil {
			return err
		}
		if conflict, err := r.serviceAccountOwnershipConflict(ctx, &fresh.account, fresh.source.client); err != nil || conflict != "" {
			return workloadbinding.Failure("OwnershipConflict")
		}
		if s.plan.Validate(fresh.plan) != nil {
			return workloadbinding.Failure("AuthenticationTransactionStale")
		}
		for _, key := range []string{workloadauth.ApprovalKey, workloadauth.ReviewKey, workloadauth.CleanupKey} {
			if fresh.account.Annotations[key] != sa.Annotations[key] {
				return workloadbinding.Failure("AuthenticationApprovalChanged")
			}
		}
		return nil
	}
}

func authenticationTransitionAuthorityMissing(sa *api.HankoServiceAccount) bool {
	return effectiveServiceAccountMode(sa) != ModeObserve && authenticationMode(sa) == "Secret" && sa.Annotations[workloadauth.JournalKey] != "" && (sa.Spec.Authentication == nil || sa.Spec.Authentication.FallbackBinding == nil)
}

func transitionStatus(j *workloadauth.Journal) *api.AuthenticationTransitionStatus {
	if j == nil {
		return nil
	}
	return &api.AuthenticationTransitionStatus{RequestID: j.RequestID, ClientUUID: j.ClientUUID, PreviousMode: j.PreviousMode, DesiredMode: j.DesiredMode, BindingRevision: j.BindingRevision, NativeStateHash: j.NativeStateHash, PlanHash: j.PlanHash, Step: j.Step}
}

// prepareAuthenticationTransaction seals an exact before/after native state.
// Ordinary edits of an existing active method never authorize a cutover.
func (r *HankoServiceAccountReconciler) prepareAuthenticationTransaction(ctx context.Context, sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot) (*workloadauth.Journal, error) {
	j, err := workloadauth.ParseJournal(sa.Annotations[workloadauth.JournalKey])
	if err != nil {
		return nil, workloadbinding.Failure("AuthenticationJournalInvalid")
	}
	if value := sa.Annotations[saRotationJournalKey]; value != "" {
		var rotation serviceAccountRotationJournal
		if workloadauth.Decode(value, &rotation) != nil || rotation.Schema != saRotationSchema || rotation.OwnerUID != string(sa.UID) || rotation.Source != s.source.client.BaseURL() || s.native == nil || rotation.ClientUUID != s.native.ID || rotation.Step != "Committed" {
			return nil, workloadbinding.Failure("SecretRotationRecoveryRequired")
		}
	}
	refs := s.plan.References()
	desired := authenticationMode(sa)
	request, prepared := "initial-"+string(sa.UID)+"."+fmt.Sprint(sa.Generation), "initial"
	if t := sa.Spec.Authentication.Transition; t != nil {
		if t.Strategy != "CoordinatedCutover" {
			return nil, workloadbinding.Failure("AuthenticationApprovalRequired")
		}
		request, prepared = t.RequestID, t.PreparedWorkloadRevision
	}
	if j != nil && j.Generation == sa.Generation {
		if j.PreviousMode == "Absent" && s.native != nil && !keycloak.FederatedWorkloadOwned(s.native, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) {
			return nil, workloadbinding.Failure("AuthenticationTransactionStale")
		}
		if j.OwnerUID != string(sa.UID) || j.RequestID != request || j.DesiredMode != desired || j.TrustUID != refs.TrustUID || j.ProviderID != refs.ProviderID || j.BindingRevision != s.plan.Revision() || j.WorkloadUID != refs.WorkloadUID || j.PreparedWorkloadRevision != prepared || j.ClientUUID != refs.NativeClientID || j.PlanHash != authenticationTransactionPlanHash(sa, s, *j) {
			return nil, workloadbinding.Failure("AuthenticationTransactionStale")
		}
		return j, nil
	}
	if j != nil && (j.Step != "Committed" || j.RequestID == request) {
		return nil, workloadbinding.Failure("AuthenticationTransactionStale")
	}
	previous := nativeAuthenticationMode(s.native)
	if previous != desired && previous != "Absent" && sa.Spec.Authentication.Transition == nil {
		return nil, workloadbinding.Failure("AuthenticationApprovalRequired")
	}
	if s.native != nil && !s.native.Enabled && sa.Spec.Authentication.Transition == nil {
		return nil, workloadbinding.Failure("AuthenticationReactivationApprovalRequired")
	}
	before, after := workloadauth.Hash("absent", sa.Spec.ClientID), workloadauth.Hash("new-federated", refs)
	id := refs.NativeClientID
	if s.native == nil {
		id = string(uuid.NewUUID())
		refs.NativeClientID = id
		s.plan, err = workloadbinding.Compile(workloadBindingView(sa), refs)
		if err != nil {
			return nil, err
		}
	} else {
		native, err := s.source.client.ReadClientOwnership(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
		if err != nil || native == nil || native.Application.ID != s.native.ID || !keycloak.ServiceAccountOwned(&native.Application, string(sa.UID)) {
			return nil, workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
		before, err = native.AuthenticationStateHash()
		if err != nil {
			return nil, workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
		method := "client-secret"
		if desired == "Kubernetes" {
			method = "federated-jwt"
		}
		after, err = native.AuthenticationTargetHash(method, s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa), desired == "Kubernetes")
		if err != nil {
			return nil, workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
	}
	j = &workloadauth.Journal{Schema: workloadauth.Schema, OwnerUID: string(sa.UID), Generation: sa.Generation, RequestID: request, ClientUUID: id, PreviousMode: previous, DesiredMode: desired, TrustUID: refs.TrustUID, ProviderID: refs.ProviderID, BindingRevision: s.plan.Revision(), WorkloadUID: refs.WorkloadUID, PreparedWorkloadRevision: prepared, NativeStateHash: before, AppliedStateHash: after, Step: "Prepared"}
	j.PlanHash = authenticationTransactionPlanHash(sa, s, *j)
	// A fresh reservation has not yet been persisted: validate dependencies with
	// only that exact anticipated UUID added to the same binding plan.
	verify := r.authenticationVerifier(sa, s)
	if s.native == nil {
		verify = func(ctx context.Context) error {
			fresh, e := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, false)
			if e != nil {
				return e
			}
			rr := fresh.plan.References()
			if rr.NativeClientID != "" && rr.NativeClientID != j.ClientUUID {
				return workloadbinding.Failure("AuthenticationTransactionStale")
			}
			rr.NativeClientID = j.ClientUUID
			p, e := workloadbinding.Compile(workloadBindingView(sa), rr)
			if e != nil || s.plan.Validate(p) != nil {
				return workloadbinding.Failure("AuthenticationTransactionStale")
			}
			if conflict, e := r.serviceAccountOwnershipConflict(ctx, sa, fresh.source.client); e != nil || conflict != "" {
				return workloadbinding.Failure("OwnershipConflict")
			}
			return nil
		}
	}
	if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
		return nil, err
	}
	return j, nil
}

func authenticationTransactionPlanHash(sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, j workloadauth.Journal) string {
	j.PlanHash = ""
	j.Step = "Prepared"
	j.Attempted = false
	j.SecretUID = ""
	// Creation has no native document yet; its immutable target is the typed
	// desired mapping plus reserved UUID. Native defaults are sealed at read-back.
	if j.PreviousMode == "Absent" {
		j.AppliedStateHash = ""
	}
	return workloadauth.Hash("activation-plan", struct {
		Transaction workloadauth.Journal
		Binding     string
		Scopes      []string
		Claims      []api.ApplicationTokenClaim
	}{j, string(s.plan.Identity().Plan), sa.Spec.Scopes, sa.Spec.TokenClaims})
}

func approvedAuthentication(sa *api.HankoServiceAccount, j *workloadauth.Journal) bool {
	if j.PreviousMode == "Absent" {
		return true
	}
	if j.PreviousMode == j.DesiredMode && j.NativeStateHash == j.AppliedStateHash && sa.Spec.Authentication.Transition == nil {
		return true
	}
	var a workloadauth.Approval
	return workloadauth.Decode(sa.Annotations[workloadauth.ApprovalKey], &a) == nil && a.Matches(*j)
}

func (r *HankoServiceAccountReconciler) applyAuthenticationTransaction(ctx context.Context, sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, j *workloadauth.Journal) error {
	verify := r.authenticationVerifier(sa, s)
	if verify(ctx) != nil {
		return workloadbinding.Failure("AuthenticationTransactionStale")
	}
	if j.Step == "Committed" {
		native, err := s.source.client.ReadClientOwnership(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
		if err != nil || native == nil || native.Application.ID != j.ClientUUID || !native.PreservationQualified() || !keycloak.ServiceAccountOwned(&native.Application, string(sa.UID)) || nativeAuthenticationMode(&native.Application) != j.DesiredMode || !native.Application.Enabled {
			return workloadbinding.Failure("NativeAuthenticationDrift")
		}
		if j.DesiredMode == "Kubernetes" && !keycloak.FederatedWorkloadOwned(&native.Application, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) {
			return workloadbinding.Failure("NativeAuthenticationDrift")
		}
		return nil
	}
	if j.DesiredMode == "Secret" {
		if err := r.stageFallbackSecret(ctx, sa, s, j, verify); err != nil {
			return err
		}
	}
	if !approvedAuthentication(sa, j) {
		return workloadbinding.Failure("AuthenticationApprovalRequired")
	}
	if s.native == nil {
		if j.Step != "Prepared" || j.PreviousMode != "Absent" || j.Attempted {
			return workloadbinding.Failure("AuthenticationCreateUnconfirmed")
		}
		j.Attempted = true
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
		if err := s.source.client.CreateFederatedServiceAccount(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, j.ClientUUID, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa), sa.Spec.Attributes, verify); err != nil {
			return workloadbinding.Failure("AuthenticationCreateUnconfirmed")
		}
		native, err := s.source.client.ReadClientOwnership(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
		if err != nil || native == nil {
			return workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
		j.AppliedStateHash, err = native.AuthenticationStateHash()
		if err != nil {
			return workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
	} else {
		native, err := s.source.client.ReadClientOwnership(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
		if err != nil || native == nil {
			return workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
		h, err := native.AuthenticationStateHash()
		if err != nil {
			return workloadbinding.Failure("NativeAuthenticationUnqualified")
		}
		// Accepted CREATE with lost local checkpoint is recognized by the exact
		// reserved identity and native envelope, never by matching names alone.
		if j.PreviousMode == "Absent" && j.Step == "Prepared" && j.Attempted && native.Application.ID == j.ClientUUID && native.Application.Enabled && keycloak.FederatedWorkloadOwned(&native.Application, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) {
			j.AppliedStateHash = h
		}
		if h != j.AppliedStateHash {
			if j.Step != "Prepared" || h != j.NativeStateHash {
				return workloadbinding.Failure("NativeAuthenticationDrift")
			}
			if !j.Attempted {
				j.Attempted = true
				if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
					return err
				}
			}
			method := "client-secret"
			if j.DesiredMode == "Kubernetes" {
				method = "federated-jwt"
			}
			if err := s.source.client.ApplyServiceAccountAuthenticator(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa), method, native, j.NativeStateHash, j.AppliedStateHash, j.DesiredMode == "Kubernetes", verify); err != nil {
				return workloadbinding.Failure("AuthenticationApplyUnconfirmed")
			}
		}
	}
	if j.Step == "Prepared" {
		j.Step = "ModeApplied"
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
	}
	if j.DesiredMode == "Secret" || j.PreviousMode == "Absent" || j.PreviousMode == j.DesiredMode && sa.Spec.Authentication.Transition == nil {
		j.Step = "Committed"
		return r.saveAuthenticationJournal(ctx, sa, j, verify)
	}
	return r.reviewAndCleanupAuthentication(ctx, sa, s, j, verify)
}

func (r *HankoServiceAccountReconciler) stageFallbackSecret(ctx context.Context, sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, j *workloadauth.Journal, verify func(context.Context) error) error {
	credential, err := s.source.client.RecoverServiceAccountTransitionSecret(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID), *j, verify)
	if err != nil {
		return workloadbinding.Failure("FallbackSecretUnavailable")
	}
	key := client.ObjectKey{Namespace: sa.Namespace, Name: saSecretName(sa.Spec.ClientID)}
	var secret corev1.Secret
	err = r.APIReader.Get(ctx, key, &secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return workloadbinding.Failure("FallbackSecretUnavailable")
	}
	if err == nil && (!metav1.IsControlledBy(&secret, sa) || !secret.DeletionTimestamp.IsZero() || j.SecretUID != "" && string(secret.UID) != j.SecretUID) {
		return workloadbinding.Failure("FallbackSecretConflict")
	}
	if verify(ctx) != nil {
		return workloadbinding.Failure("AuthenticationTransactionStale")
	}
	if err != nil || canonicalServiceAccountSecret(&secret) != credential {
		if err == nil && secret.Immutable != nil && *secret.Immutable {
			return workloadbinding.Failure("FallbackSecretConflict")
		}
		_ = r.upsertSASecret(ctx, sa, credential)
	}
	if verify(ctx) != nil || r.APIReader.Get(ctx, key, &secret) != nil || !metav1.IsControlledBy(&secret, sa) || canonicalServiceAccountSecret(&secret) != credential {
		return workloadbinding.Failure("FallbackSecretUnconfirmed")
	}
	if j.SecretUID != "" && string(secret.UID) != j.SecretUID {
		return workloadbinding.Failure("FallbackSecretConflict")
	}
	if j.SecretUID == "" {
		j.SecretUID = string(secret.UID)
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
	}
	return nil
}

func (r *HankoServiceAccountReconciler) reviewAndCleanupAuthentication(ctx context.Context, sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, j *workloadauth.Journal, verify func(context.Context) error) error {
	var review workloadauth.Review
	if workloadauth.Decode(sa.Annotations[workloadauth.ReviewKey], &review) != nil || !review.Matches(*j) {
		return workloadbinding.Failure("AuthenticationReviewRequired")
	}
	if j.Step == "ModeApplied" {
		j.Step = "AuthReviewed"
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
	}
	var cleanup workloadauth.Cleanup
	if workloadauth.Decode(sa.Annotations[workloadauth.CleanupKey], &cleanup) != nil || !cleanup.Matches(*j) || !workloadbinding.ValidUID(cleanup.SecretUID) {
		return workloadbinding.Failure("AuthenticationCleanupApprovalRequired")
	}
	key := client.ObjectKey{Namespace: sa.Namespace, Name: saSecretName(sa.Spec.ClientID)}
	var secret corev1.Secret
	err := r.APIReader.Get(ctx, key, &secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return workloadbinding.Failure("AuthenticationCleanupConflict")
	}
	if j.SecretUID != "" && j.SecretUID != cleanup.SecretUID {
		return workloadbinding.Failure("AuthenticationCleanupConflict")
	}
	if j.SecretUID == "" {
		j.SecretUID = cleanup.SecretUID
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
	}
	if err == nil {
		_, hasCredential := secret.Data["client_secret"]
		if (j.Step == "OutputsCleaned" || j.Step == "Committed") && hasCredential || string(secret.UID) != j.SecretUID || !metav1.IsControlledBy(&secret, sa) || !secret.DeletionTimestamp.IsZero() {
			return workloadbinding.Failure("AuthenticationCleanupConflict")
		}
		state, stateErr := s.source.client.ReadClientOwnership(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
		if stateErr != nil || state == nil {
			return workloadbinding.Failure("NativeAuthenticationDrift")
		}
		stateHash, stateErr := state.AuthenticationStateHash()
		if stateErr != nil || stateHash != j.AppliedStateHash {
			return workloadbinding.Failure("NativeAuthenticationDrift")
		}
		if verify(ctx) != nil || s.source.client.CheckFederatedServiceAccountOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) != nil {
			return workloadbinding.Failure("AuthenticationTransactionStale")
		}
		// Remove only the canonical owned credential field, preserving unrelated
		// output keys and the object. UID preconditions reject a replacement.
		patch := client.MergeFromWithOptions(secret.DeepCopy(), client.MergeFromWithOptimisticLock{})
		delete(secret.Data, "client_secret")
		_ = r.Patch(ctx, &secret, patch)
		if r.APIReader.Get(ctx, key, &secret) != nil || string(secret.UID) != j.SecretUID || !metav1.IsControlledBy(&secret, sa) {
			return workloadbinding.Failure("AuthenticationCleanupConflict")
		}
		if _, present := secret.Data["client_secret"]; present {
			return workloadbinding.Failure("AuthenticationCleanupUnconfirmed")
		}
	}
	if verify(ctx) != nil {
		return workloadbinding.Failure("AuthenticationTransactionStale")
	}
	if j.Step == "AuthReviewed" {
		j.Step = "OutputsCleaned"
		if err := r.saveAuthenticationJournal(ctx, sa, j, verify); err != nil {
			return err
		}
	}
	j.Step = "Committed"
	return r.saveAuthenticationJournal(ctx, sa, j, verify)
}

func (r *HankoServiceAccountReconciler) authenticationTransitionResult(ctx context.Context, sa *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, j *workloadauth.Journal, reason string) (ctrl.Result, error) {
	var current api.HankoServiceAccount
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sa), &current); err != nil {
		return ctrl.Result{}, err
	}
	if current.UID != sa.UID || current.Generation != sa.Generation {
		return ctrl.Result{}, workloadauth.ErrPrecondition
	}
	patch := client.MergeFromWithOptions(current.DeepCopy(), client.MergeFromWithOptimisticLock{})
	current.Status.AuthenticationTransition = transitionStatus(j)
	current.Status.Phase, current.Status.ObservedGeneration = "Pending", sa.Generation
	if s == nil {
		current.Status.WorkloadBinding, current.Status.RuntimeMetadata = nil, nil
		iamCondition(&current.Status.Conditions, sa.Generation, "WorkloadBindingReady", metav1.ConditionFalse, reason, "current binding evidence unavailable")
		iamCondition(&current.Status.Conditions, sa.Generation, "RuntimeMetadataReady", metav1.ConditionFalse, reason, "current runtime evidence unavailable")
	}
	iamCondition(&current.Status.Conditions, sa.Generation, "Synced", metav1.ConditionFalse, reason, "authentication transaction requires exact current approval and read-back")
	iamCondition(&current.Status.Conditions, sa.Generation, "FederatedModeApplied", metav1.ConditionFalse, reason, "configuration evidence is independent of external workload authentication review")
	return ctrl.Result{RequeueAfter: workloadBindingPoll}, r.Status().Patch(ctx, &current, patch)
}

func (r *HankoServiceAccountReconciler) reconcileServiceAccountFallback(ctx context.Context, sa *api.HankoServiceAccount) (ctrl.Result, error) {
	if effectiveServiceAccountMode(sa) == ModeObserve {
		return r.workloadAccountStatus(ctx, sa, nil, nil, "ObserveOnly")
	}
	if !sa.DeletionTimestamp.IsZero() {
		s, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
		if err != nil {
			return r.authenticationTransitionResult(ctx, sa, nil, nil, workloadbinding.Reason(err))
		}
		if s.native != nil && s.native.ClientAuthenticatorType == "federated-jwt" {
			return r.deleteFederatedServiceAccount(ctx, sa)
		}
		if err := r.workloadDelivery(nil).Cleanup(ctx, sa); err != nil {
			return r.authenticationTransitionResult(ctx, sa, s, nil, workloadbinding.Reason(err))
		}
		return r.reconcileServiceAccountDeletion(ctx, sa, s.source.client, false)
	}
	if sa.Spec.Authentication.Transition == nil {
		return r.authenticationTransitionResult(ctx, sa, nil, nil, "AuthenticationApprovalRequired")
	}
	s, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, false)
	if err != nil {
		return r.authenticationTransitionResult(ctx, sa, nil, nil, workloadbinding.Reason(err))
	}
	if conflict, err := r.serviceAccountOwnershipConflict(ctx, sa, s.source.client); err != nil || conflict != "" {
		return r.authenticationTransitionResult(ctx, sa, s, nil, "OwnershipConflict")
	}
	if s.native == nil {
		return r.authenticationTransitionResult(ctx, sa, s, nil, "FallbackNativeClientMissing")
	}
	if !s.native.Enabled {
		return r.authenticationTransitionResult(ctx, sa, s, nil, "AuthenticationContained")
	}
	j, err := r.prepareAuthenticationTransaction(ctx, sa, s)
	if err != nil {
		return r.authenticationTransitionResult(ctx, sa, s, j, workloadbinding.Reason(err))
	}
	if err := r.applyAuthenticationTransaction(ctx, sa, s, j); err != nil {
		return r.authenticationTransitionResult(ctx, sa, s, j, workloadbinding.Reason(err))
	}
	// Once native Secret mode and its staged output are verified, the historical
	// Secret controller owns recovery/claims/rotation. No automatic method change
	// is available there, and the current dedicated connection remains explicit.
	if err := r.authenticationVerifier(sa, s)(ctx); err != nil {
		return r.authenticationTransitionResult(ctx, sa, s, j, "AuthenticationTransactionStale")
	}
	if err := r.workloadDelivery(nil).Cleanup(ctx, sa); err != nil {
		return r.authenticationTransitionResult(ctx, sa, s, j, workloadbinding.Reason(err))
	}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sa), sa); err != nil {
		return ctrl.Result{}, err
	}
	if controllerutil.ContainsFinalizer(sa, workloadbinding.RuntimeFinalizer) {
		controllerutil.RemoveFinalizer(sa, workloadbinding.RuntimeFinalizer)
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, err
		}
	}
	sa.Status.AuthenticationTransition = transitionStatus(j)
	sa.Status.WorkloadBinding, sa.Status.RuntimeMetadata = nil, nil
	return r.reconcileManagedServiceAccount(ctx, sa, s.source.client)
}
