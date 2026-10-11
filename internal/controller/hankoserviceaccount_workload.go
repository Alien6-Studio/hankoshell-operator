package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const workloadBindingPoll = 30 * time.Second

type serviceAccountWorkloadSnapshot struct {
	account         api.HankoServiceAccount
	trust           *workloadSnapshot
	source          workloadConnection
	native          *keycloak.Application
	plan            workloadbinding.Plan
	workloadInvalid bool
	workloadUID     string
	seal            string
}

// serviceAccountWorkloadSnapshot uses the shared trust resolver and exact live
// API reads. The containment variant verifies authority even when readiness is
// lost, but never makes a new binding or approves a replacement UID.
func (r *HankoWorkloadTrustReconciler) serviceAccountWorkloadSnapshot(ctx context.Context, expected *api.HankoServiceAccount, containment bool) (*serviceAccountWorkloadSnapshot, error) {
	if r == nil || r.APIReader == nil {
		return nil, workloadbinding.Failure("WorkloadBindingUnavailable")
	}
	s := &serviceAccountWorkloadSnapshot{}
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(expected), &s.account) != nil || s.account.UID != expected.UID || s.account.Generation != expected.Generation || !reflect.DeepEqual(s.account.Spec, expected.Spec) || !reflect.DeepEqual(s.account.Labels, expected.Labels) {
		return nil, workloadbinding.Failure("StaleSource")
	}
	sa := &s.account
	if err := workloadbinding.Validate(sa); err != nil {
		return s, err
	}
	k := sa.Spec.Authentication.Kubernetes
	var err error
	s.trust, err = r.workloadSnapshot(ctx, client.ObjectKey{Namespace: sa.Namespace, Name: k.TrustRef}, false, "")
	if err != nil || s.trust.trust.Spec.RealmRef != sa.Spec.RealmRef || !s.trust.trust.DeletionTimestamp.IsZero() || !workloadOwnershipMatches(s.trust) || !workloadConfigurationMatches(s.trust) {
		return s, workloadbinding.Failure("WorkloadTrustNotReady")
	}
	t := &s.trust.trust
	j, err := workloadtrust.ParseJournal(s.trust.provider.Config.Journal)
	if err != nil || j.Generation != t.Generation || j.InputHash != string(s.trust.plan.Identity().Intent) {
		return s, workloadbinding.Failure("WorkloadTrustNotReady")
	}
	if !containment && (t.Status.ObservedGeneration != t.Generation || !meta.IsStatusConditionTrue(t.Status.Conditions, "Ready")) {
		return s, workloadbinding.Failure("WorkloadTrustNotReady")
	}
	s.source, err = r.workloadConnection(ctx, sa.Namespace, k.SourceRef)
	if err != nil || !sameWorkloadConnection(s.source, s.trust.source) {
		return s, workloadbinding.Failure("SourceUnavailable")
	}
	defer s.source.client.CloseIdleConnections()
	flow, err := s.source.client.ValidateEffectiveFederatedClientFlow(ctx, sa.Spec.RealmRef)
	if err != nil || flow.RealmID != s.trust.plan.References().RealmID {
		return s, workloadbinding.Failure("FlowPrerequisiteMissing")
	}
	if isStaticallyProtectedServiceAccountClient(sa.Spec.ClientID) || sa.Spec.ClientID == s.source.client.CredentialClientID() || sa.Spec.ClientID == s.trust.source.client.CredentialClientID() {
		return s, workloadbinding.Failure("OwnershipConflict")
	}
	s.native, err = s.source.client.GetApplication(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if err != nil {
		return s, workloadbinding.Failure("ProviderUnavailable")
	}
	if s.native != nil && !keycloak.ServiceAccountOwned(s.native, string(sa.UID)) {
		return s, workloadbinding.Failure("OwnershipConflict")
	}
	if !containment && s.native != nil && s.native.ClientAuthenticatorType == "federated-jwt" && !keycloak.FederatedWorkloadOwned(s.native, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) {
		return s, workloadbinding.Failure("NativeBindingMismatch")
	}
	w := k.Workload
	var account corev1.ServiceAccount
	err = r.APIReader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: w.ServiceAccountRef}, &account)
	if err != nil && !apierrors.IsNotFound(err) {
		return s, workloadbinding.Failure("WorkloadUnavailable")
	}
	s.workloadUID = string(account.UID)
	s.workloadInvalid = apierrors.IsNotFound(err) || !account.DeletionTimestamp.IsZero() || s.workloadUID != w.ExpectedUID
	s.seal = workloadbinding.Digest("containment", struct {
		UID                          string
		Generation                   int64
		Authentication               *api.ServiceAccountAuthentication
		Realm, ClientID, WorkloadUID string
		Labels                       map[string]string
		Trust                        iamcontract.PlanIdentity
		Source                       any
		Flow                         any
		NativeID                     string
	}{string(sa.UID), sa.Generation, sa.Spec.Authentication, sa.Spec.RealmRef, sa.Spec.ClientID, s.workloadUID, sa.Labels, s.trust.plan.Identity(), workloadConnectionEvidence(s.source), flow, nativeWorkloadClientID(s.native)})
	if containment {
		return s, r.verifyServiceAccountWorkloadReferences(ctx, s)
	}
	if s.workloadInvalid {
		return s, workloadbinding.Failure("WorkloadUIDMismatch")
	}
	if !sa.DeletionTimestamp.IsZero() {
		return s, workloadbinding.Failure("StaleSource")
	}
	public, err := workloadRealmMetadata(ctx, s.source.client, sa.Spec.RealmRef)
	if err != nil {
		return s, err
	}
	refs := workloadbinding.References{TrustUID: string(t.UID), TrustGeneration: t.Generation, ProviderID: s.trust.provider.InternalID, RealmID: flow.RealmID, ClusterUID: t.Spec.Kubernetes.ClusterAnchor.KubeSystemNamespaceUID, CAHash: t.Spec.Kubernetes.ClusterAnchor.APIServerCAHash, SourceHash: workloadbinding.Digest("source", workloadConnectionEvidence(s.source)), TrustHash: workloadbinding.Digest("trust", s.trust.plan.Identity()), FlowHash: workloadbinding.Digest("flow", flow), WorkloadUID: w.ExpectedUID, AssertionAudience: public.Issuer, TokenEndpoint: public.TokenEndpoint, TrustMaxAge: workloadIntent(t).MaxAge, NativeClientID: nativeWorkloadClientID(s.native)}
	if target := sa.Spec.RuntimeMetadata; target != nil {
		var cm corev1.ConfigMap
		if r.APIReader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: target.ConfigMapRef}, &cm) != nil {
			return s, workloadbinding.Failure("TargetUnavailable")
		}
		if err := workloadbinding.Authorize(&cm, sa, w, target.ExpectedUID); err != nil {
			return s, err
		}
		refs.TargetUID = string(cm.UID)
		refs.ConsentHash = workloadbinding.Digest("consent", workloadbinding.Authorization(sa, w))
	}
	s.plan, err = workloadbinding.Compile(sa, refs)
	if err == nil {
		err = r.verifyServiceAccountWorkloadReferences(ctx, s)
	}
	return s, err
}

type workloadPublicRealmMetadata struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
}

func workloadRealmMetadata(ctx context.Context, source *keycloak.Client, realm string) (workloadPublicRealmMetadata, error) {
	var result workloadPublicRealmMetadata
	document, err := source.ProtocolDocument(ctx, realm, "oidc")
	if err != nil || httpsecurity.ValidateJSON(document) != nil || json.Unmarshal(document, &result) != nil || !workloadtrust.ValidHTTPS(result.Issuer) || !workloadtrust.ValidHTTPS(result.TokenEndpoint) || len(result.Issuer) > 2048 || len(result.TokenEndpoint) > 2048 {
		return result, workloadbinding.Failure("RealmMetadataUnavailable")
	}
	return result, nil
}

func (r *HankoWorkloadTrustReconciler) verifyServiceAccountWorkloadReferences(ctx context.Context, s *serviceAccountWorkloadSnapshot) error {
	var current api.HankoServiceAccount
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(&s.account), &current) != nil || current.UID != s.account.UID || current.Generation != s.account.Generation || !reflect.DeepEqual(current.Spec, s.account.Spec) || !reflect.DeepEqual(current.Labels, s.account.Labels) || !reflect.DeepEqual(current.DeletionTimestamp, s.account.DeletionTimestamp) {
		return workloadbinding.Failure("StaleSource")
	}
	if r.verifyWorkloadReferences(ctx, s.trust, false) != nil {
		return workloadbinding.Failure("StaleSource")
	}
	source, err := r.workloadConnection(ctx, current.Namespace, current.Spec.Authentication.Kubernetes.SourceRef)
	if err != nil {
		return workloadbinding.Failure("StaleSource")
	}
	defer source.client.CloseIdleConnections()
	if !reflect.DeepEqual(workloadConnectionEvidence(source), workloadConnectionEvidence(s.source)) {
		return workloadbinding.Failure("StaleSource")
	}
	if refs := s.plan.References(); refs.AssertionAudience != "" {
		public, err := workloadRealmMetadata(ctx, source.client, current.Spec.RealmRef)
		if err != nil || public.Issuer != refs.AssertionAudience || public.TokenEndpoint != refs.TokenEndpoint {
			return workloadbinding.Failure("StaleSource")
		}
	}
	var live corev1.ServiceAccount
	w := current.Spec.Authentication.Kubernetes.Workload
	err = r.APIReader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: w.ServiceAccountRef}, &live)
	if err != nil && !apierrors.IsNotFound(err) || string(live.UID) != s.workloadUID || (apierrors.IsNotFound(err) || !live.DeletionTimestamp.IsZero() || string(live.UID) != w.ExpectedUID) != s.workloadInvalid {
		return workloadbinding.Failure("StaleSource")
	}
	if target := current.Spec.RuntimeMetadata; !s.workloadInvalid && target != nil {
		var cm corev1.ConfigMap
		if r.APIReader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: target.ConfigMapRef}, &cm) != nil || workloadbinding.Authorize(&cm, &current, w, target.ExpectedUID) != nil {
			return workloadbinding.Failure("StaleSource")
		}
	}
	return nil
}

func nativeWorkloadClientID(a *keycloak.Application) string {
	if a == nil {
		return ""
	}
	return a.ID
}
func workloadSubject(sa *api.HankoServiceAccount) string {
	w := sa.Spec.Authentication.Kubernetes.Workload
	return "system:serviceaccount:" + w.Namespace + ":" + w.ServiceAccountRef
}

// requireActiveWorkloadBinding is shared by grants and mesh. Neither passive
// metadata nor a forged Ready status establishes native authentication.
func (r *HankoWorkloadTrustReconciler) requireActiveWorkloadBinding(ctx context.Context, sa *api.HankoServiceAccount) (*serviceAccountWorkloadSnapshot, error) {
	s, err := r.serviceAccountWorkloadSnapshot(ctx, sa, false)
	if err != nil {
		return s, err
	}
	current := &s.account
	if current.Status.Phase != "Ready" || current.Status.ObservedGeneration != current.Generation || current.Status.WorkloadBinding == nil || current.Status.WorkloadBinding.BindingRevision != s.plan.Revision() || !currentWorkloadCondition(current, "Synced") || !currentWorkloadCondition(current, "FederatedModeApplied") {
		return s, workloadbinding.Failure("FederatedAuthenticationNotActive")
	}
	if effectiveServiceAccountMode(sa) != ModeManage || !keycloak.FederatedWorkloadOwned(s.native, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) || !s.native.Enabled {
		return s, workloadbinding.Failure("FederatedAuthenticationNotActive")
	}
	return s, nil
}

func currentWorkloadCondition(sa *api.HankoServiceAccount, name string) bool {
	c := meta.FindStatusCondition(sa.Status.Conditions, name)
	return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == sa.Generation
}

func (r *HankoServiceAccountReconciler) workloadDelivery(verify func(context.Context) error) *workloadbinding.Delivery {
	writer := r.RuntimeClient
	if writer == nil {
		writer = r.Client
	}
	return &workloadbinding.Delivery{Client: writer, Reader: r.APIReader, Verify: verify}
}

func (r *HankoServiceAccountReconciler) containInvalidWorkload(ctx context.Context, sa *api.HankoServiceAccount) error {
	s, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
	if err != nil {
		return err
	}
	if !s.workloadInvalid {
		return workloadbinding.Failure("StaleSource")
	}
	if conflict, err := r.serviceAccountOwnershipConflict(ctx, &s.account, s.source.client); err != nil || conflict != "" {
		return workloadbinding.Failure("ContainmentOwnershipConflict")
	}
	if s.native == nil {
		return nil
	}
	if !keycloak.FederatedWorkloadOwned(s.native, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa)) {
		return workloadbinding.Failure("ContainmentOwnershipConflict")
	}
	verify := func(ctx context.Context) error {
		fresh, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, true)
		if err != nil || !fresh.workloadInvalid || fresh.seal != s.seal || effectiveServiceAccountMode(&fresh.account) != ModeManage {
			return iamcontract.ErrStale
		}
		if conflict, err := r.serviceAccountOwnershipConflict(ctx, &fresh.account, fresh.source.client); err != nil || conflict != "" {
			return iamcontract.ErrStale
		}
		return nil
	}
	if err := s.source.client.DisableFederatedWorkloadIfOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID), s.trust.trust.Spec.KeycloakAlias, workloadSubject(sa), s.native, verify); err != nil {
		return workloadbinding.Failure("ContainmentUnconfirmed")
	}
	return nil
}

func (r *HankoServiceAccountReconciler) reconcileWorkloadServiceAccount(ctx context.Context, sa *api.HankoServiceAccount) (ctrl.Result, error) {
	observe := effectiveServiceAccountMode(sa) == ModeObserve
	if observe {
		return r.workloadAccountStatus(ctx, sa, nil, nil, "ObserveOnly")
	}
	// Containment precedes output cleanup. A missing/replaced workload can hold
	// cleanup consent, including during deletion, but must not leave its strictly
	// owned native client enabled while waiting for administrator resolution.
	if workloadbinding.Validate(sa) == nil && r.confirmedInvalidWorkload(ctx, sa) {
		return r.recordInvalidWorkload(ctx, sa)
	}
	if !sa.DeletionTimestamp.IsZero() || sa.Spec.RuntimeMetadata == nil {
		if err := r.workloadDelivery(nil).Cleanup(ctx, sa); err != nil {
			return r.workloadAccountStatus(ctx, sa, nil, nil, workloadbinding.Reason(err))
		}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sa), sa); err != nil {
			return ctrl.Result{RequeueAfter: workloadBindingPoll}, iamcontract.SafeError(client.IgnoreNotFound(err))
		}
		if controllerutil.ContainsFinalizer(sa, workloadbinding.RuntimeFinalizer) {
			controllerutil.RemoveFinalizer(sa, workloadbinding.RuntimeFinalizer)
			if err := r.Update(ctx, sa); err != nil {
				return ctrl.Result{}, err
			}
		}
		if !sa.DeletionTimestamp.IsZero() {
			return ctrl.Result{}, nil
		}
	}
	s, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, false)
	if err != nil {
		reason := workloadbinding.Reason(err)
		// Confirmed absence/replacement is the sole UID containment trigger.
		if workloadbinding.Validate(sa) == nil && r.confirmedInvalidWorkload(ctx, sa) {
			return r.recordInvalidWorkload(ctx, sa)
		}
		return r.workloadAccountStatus(ctx, sa, nil, nil, reason)
	}
	if conflict, err := r.serviceAccountOwnershipConflict(ctx, sa, s.source.client); err != nil || conflict != "" {
		return r.workloadAccountStatus(ctx, sa, nil, nil, "OwnershipConflict")
	}
	if sa.Spec.RuntimeMetadata != nil && !controllerutil.ContainsFinalizer(sa, workloadbinding.RuntimeFinalizer) {
		controllerutil.AddFinalizer(sa, workloadbinding.RuntimeFinalizer)
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, err
		}
	}
	verify := func(ctx context.Context) error {
		fresh, err := r.WorkloadTrust.serviceAccountWorkloadSnapshot(ctx, sa, false)
		if err != nil {
			return err
		}
		if conflict, err := r.serviceAccountOwnershipConflict(ctx, &fresh.account, fresh.source.client); err != nil || conflict != "" {
			return workloadbinding.Failure("OwnershipConflict")
		}
		return s.plan.Validate(fresh.plan)
	}
	metadata, err := r.workloadDelivery(verify).Deliver(ctx, sa, s.plan)
	if err != nil {
		return r.workloadAccountStatus(ctx, sa, nil, nil, workloadbinding.Reason(err))
	}
	if err := verify(ctx); err != nil {
		return r.workloadAccountStatus(ctx, sa, nil, nil, "StaleSource")
	}
	return r.workloadAccountStatus(ctx, sa, s, metadata, "BindingValidated")
}

func (r *HankoServiceAccountReconciler) recordInvalidWorkload(ctx context.Context, sa *api.HankoServiceAccount) (ctrl.Result, error) {
	reason := "WorkloadUIDMismatch"
	if _, err := r.workloadAccountStatus(ctx, sa, nil, nil, reason); err != nil {
		return ctrl.Result{RequeueAfter: workloadBindingPoll}, err
	}
	if err := r.containInvalidWorkload(ctx, sa); err != nil {
		reason = workloadbinding.Reason(err)
	}
	return r.workloadAccountStatus(ctx, sa, nil, nil, reason)
}

func (r *HankoServiceAccountReconciler) confirmedInvalidWorkload(ctx context.Context, sa *api.HankoServiceAccount) bool {
	w := sa.Spec.Authentication.Kubernetes.Workload
	var live corev1.ServiceAccount
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: w.Namespace, Name: w.ServiceAccountRef}, &live)
	return apierrors.IsNotFound(err) || err == nil && (!live.DeletionTimestamp.IsZero() || string(live.UID) != w.ExpectedUID)
}

// Cross-namespace workload changes use bounded named polling. These watches
// only cover Hanko configuration; no ServiceAccount informer is added here.
func (r *HankoServiceAccountReconciler) requestsForWorkloadBinding(ctx context.Context, obj client.Object) []reconcile.Request {
	var accounts api.HankoServiceAccountList
	if r.List(ctx, &accounts, client.InNamespace(obj.GetNamespace())) != nil {
		return nil
	}
	var requests []reconcile.Request
	for i := range accounts.Items {
		sa := &accounts.Items[i]
		if !workloadbinding.KubernetesMode(sa) || sa.Spec.Authentication.Kubernetes == nil {
			continue
		}
		k := sa.Spec.Authentication.Kubernetes
		_, trust := obj.(*api.HankoWorkloadTrust)
		if trust && k.TrustRef != obj.GetName() {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(sa)})
	}
	return requests
}

func (r *HankoServiceAccountReconciler) workloadAccountStatus(ctx context.Context, expected *api.HankoServiceAccount, s *serviceAccountWorkloadSnapshot, metadata *api.WorkloadRuntimeMetadataStatus, reason string) (ctrl.Result, error) {
	var sa api.HankoServiceAccount
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(expected), &sa); err != nil {
		return ctrl.Result{RequeueAfter: workloadBindingPoll}, iamcontract.SafeError(client.IgnoreNotFound(err))
	}
	if sa.UID != expected.UID || sa.Generation != expected.Generation || !reflect.DeepEqual(sa.Spec, expected.Spec) || !reflect.DeepEqual(sa.Labels, expected.Labels) {
		return ctrl.Result{RequeueAfter: workloadBindingPoll}, iamcontract.ErrStale
	}
	patch := client.MergeFromWithOptions(sa.DeepCopy(), client.MergeFromWithOptimisticLock{})
	sa.Status.Phase, sa.Status.ObservedGeneration = "Pending", sa.Generation
	sa.Status.WorkloadBinding, sa.Status.RuntimeMetadata = nil, nil
	sa.Status.SecretRef, sa.Status.NextRotation = nil, nil
	status := metav1.ConditionFalse
	if s != nil {
		refs := s.plan.References()
		id := s.plan.Identity()
		sa.Status.WorkloadBinding = &api.WorkloadBindingStatus{Workload: sa.Spec.Authentication.Kubernetes.Workload, ClusterNamespaceUID: refs.ClusterUID, APIServerCAHash: refs.CAHash, TrustUID: refs.TrustUID, TrustGeneration: refs.TrustGeneration, ProviderID: refs.ProviderID, RealmID: refs.RealmID, SourceGeneration: sa.Generation, IntentHash: string(id.Intent), PlanHash: string(id.Plan), BindingRevision: s.plan.Revision()}
		sa.Status.RuntimeMetadata = metadata
		status = metav1.ConditionTrue
	} else {
		sa.Status.Phase = "Error"
	}
	iamCondition(&sa.Status.Conditions, sa.Generation, "WorkloadBindingReady", status, reason, "binding evidence requires live UID and current trust/source; metadata alone does not activate authentication")
	iamCondition(&sa.Status.Conditions, sa.Generation, "RuntimeMetadataReady", status, reason, "public runtime configuration requires current target UID consent and read-back")
	if sa.Spec.RuntimeMetadata == nil {
		iamCondition(&sa.Status.Conditions, sa.Generation, "RuntimeMetadataReady", metav1.ConditionUnknown, "NotConfigured", "no runtime metadata target configured")
	}
	iamCondition(&sa.Status.Conditions, sa.Generation, "Synced", metav1.ConditionFalse, "AuthenticationActivationPending", "federated authentication activation requires its dedicated reconciliation contract")
	iamCondition(&sa.Status.Conditions, sa.Generation, "FederatedModeApplied", metav1.ConditionFalse, "AuthenticationActivationPending", "binding validation does not apply a native authenticator")
	if err := r.Status().Patch(ctx, &sa, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: workloadBindingPoll}, nil
}
