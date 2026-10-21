package controller

import (
	"context"
	"reflect"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *HankoApplicationReconciler) runtimeDelivery(verify func(context.Context) error) *applicationbinding.Delivery {
	writer := r.RuntimeClient
	if writer == nil {
		writer = r.secretProjectionClient()
	}
	reader := r.OwnershipReader
	if reader == nil {
		reader = writer
	}
	return &applicationbinding.Delivery{Client: writer, Reader: reader, Verify: verify}
}

func (r *HankoApplicationReconciler) reconcileRuntimeBindings(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client, plan applications.Plan, driver *applications.KeycloakDriver) (ctrl.Result, error) {
	proof := applicationbinding.Proof{ApplicationUID: string(app.UID), Generation: app.Generation,
		ContractVersion: string(plan.Identity().Contract), IntentHash: string(plan.Identity().Intent), AppliedPlanHash: string(plan.Identity().Plan),
		Protocol: applications.Protocol(app.Spec.Protocol), Pattern: app.Spec.Type, ClientID: app.Spec.ClientID,
		OIDC: app.Status.OIDCEndpoints, SAML: app.Status.SAMLEndpoints}
	if app.Spec.SAML != nil {
		proof.NameIDFormat = app.Spec.SAML.NameIDFormat
		if proof.NameIDFormat == "" {
			proof.NameIDFormat = "persistent"
		}
	}
	verify := func(ctx context.Context) error {
		if err := r.validateOwnedApplicationExecution(ctx, app, kc, plan); err != nil {
			return err
		}
		state, err := driver.Observe(ctx, plan)
		if err != nil {
			return err
		}
		if !applicationStateCurrent(state, app) {
			return iamcontract.ErrStale
		}
		return nil
	}
	var statuses []api.ApplicationRuntimeBindingStatus
	var deliveryErr error
	if len(app.Spec.RuntimeBindings) != 0 && !meta.IsStatusConditionTrue(app.Status.Conditions, "Operational") {
		deliveryErr = &applicationbinding.Failure{Reason: "ApplicationNotReady"}
		statuses = applicationbinding.Pending(app, "ApplicationNotReady")
	} else {
		statuses, deliveryErr = r.runtimeDelivery(verify).Deliver(ctx, app, proof)
	}
	// Delivery may update the durable journal. Reload before the status patch;
	// preserve independently persisted provider evidence and resource identity.
	reader := r.runtimeDelivery(nil).Reader
	var current api.HankoApplication
	if err := reader.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if current.UID != app.UID || current.Generation != app.Generation || !current.DeletionTimestamp.IsZero() || !reflect.DeepEqual(current.Spec, app.Spec) || !reflect.DeepEqual(current.Labels, app.Labels) {
		return ctrl.Result{RequeueAfter: requeueOnError}, iamcontract.ErrStale
	}
	patch := client.MergeFromWithOptions(current.DeepCopy(), client.MergeFromWithOptimisticLock{})
	current.Status.RuntimeBindings = statuses
	current.Status.Phase = "Ready"
	status, reason, message := metav1.ConditionTrue, "Reconciled", "all runtime outputs carry the current binding revision"
	if deliveryErr != nil {
		status, reason, message = metav1.ConditionFalse, applicationbinding.Reason(deliveryErr), "runtime delivery is not proven current; last-known outputs are retained"
		current.Status.Phase = "Error"
	} else if len(app.Spec.RuntimeBindings) == 0 {
		status, reason, message = metav1.ConditionUnknown, "NotConfigured", "no runtime bindings configured"
	}
	iamCondition(&current.Status.Conditions, app.Generation, "RuntimeBindings", status, reason, message)
	if err := r.Status().Patch(ctx, &current, patch); err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}
	if deliveryErr != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, deliveryErr
	}
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoApplicationReconciler) cleanupRuntimeApplication(ctx context.Context, app *api.HankoApplication) error {
	delivery := r.runtimeDelivery(nil)
	if err := delivery.Cleanup(ctx, app, nil); err != nil {
		return err
	}
	var current api.HankoApplication
	if err := delivery.Reader.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
		return err
	}
	if current.UID != app.UID || current.Generation != app.Generation || !reflect.DeepEqual(current.Spec, app.Spec) || !reflect.DeepEqual(current.Labels, app.Labels) {
		return iamcontract.ErrStale
	}
	// Cleanup patches the durable journal; deletion/finalizer must use its new RV.
	*app = current
	return nil
}

func markRuntimePending(app *api.HankoApplication, reason string) {
	status, message := metav1.ConditionFalse, "current provider state is not proven; last-known runtime outputs are retained"
	if len(app.Spec.RuntimeBindings) == 0 {
		status, reason, message = metav1.ConditionUnknown, "NotConfigured", "no runtime bindings configured"
	}
	app.Status.RuntimeBindings = applicationbinding.Pending(app, reason)
	iamCondition(&app.Status.Conditions, app.Generation, "RuntimeBindings", status, reason, message)
}

func (r *HankoApplicationReconciler) runtimeCleanupFailure(ctx context.Context, app *api.HankoApplication, err error) (ctrl.Result, error) {
	patch := client.MergeFrom(app.DeepCopy())
	app.Status.Phase = "Error"
	iamCondition(&app.Status.Conditions, app.Generation, "RuntimeBindings", metav1.ConditionFalse, applicationbinding.Reason(err), "runtime cleanup requires current target authorization; targets were preserved")
	if patchErr := r.Status().Patch(ctx, app, patch); patchErr != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, patchErr
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, err
}

func (r *HankoApplicationReconciler) applicationCredentialReader() client.Reader {
	if r.OwnershipReader != nil {
		return r.OwnershipReader
	}
	return r.Client
}
func setApplicationCredentialReference(app *api.HankoApplication) {
	app.Status.ClientSecret = &api.SecretReference{SecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName(app.Spec.ClientID)}, Key: "client_secret"}}
}

const applicationRotationCheckpointAnnotation = "hanko.sh/client-secret-rotated-at"

func applicationRotationCheckpoint(app *api.HankoApplication) map[string]string {
	if app.Status.LastRotated == nil {
		return nil
	}
	return map[string]string{applicationRotationCheckpointAnnotation: app.Status.LastRotated.UTC().Format(time.RFC3339Nano)}
}
func recoverApplicationRotationCheckpoint(app *api.HankoApplication, secret *corev1.Secret) {
	owner := metav1.GetControllerOf(secret)
	if owner == nil || owner.UID != app.UID {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, secret.Annotations[applicationRotationCheckpointAnnotation])
	if err == nil {
		app.Status.LastRotated = &metav1.Time{Time: at}
	}
}

func applicationMapperCleanupPending(app *api.HankoApplication) bool {
	claims, mappings := map[string]bool{}, map[string]bool{}
	for _, claim := range app.Spec.TokenClaims {
		claims[claim.Name] = true
	}
	for _, mapping := range app.Spec.IdentityMappings {
		mappings[mapping.Name] = true
	}
	for _, previous := range app.Status.ManagedTokenClaims {
		if !claims[previous.Name] {
			return true
		}
	}
	for _, previous := range app.Status.ManagedIdentityMappings {
		if !mappings[previous.Name] {
			return true
		}
	}
	return false
}
