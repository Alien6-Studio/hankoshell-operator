package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const (
	defaultServiceAccountMaxAge = 90 * 24 * time.Hour
	rotationRetryDelay          = 5 * time.Second
	adminClientSecretKey        = "HANKO_KC_CLIENT_SECRET"
	pendingClientSecretKey      = "HANKO_KC_CLIENT_SECRET_PENDING"
	rotatedAtAnnotation         = "hanko.sh/sa-rotated-at"
	rotationStateAnnotation     = "hanko.sh/sa-rotation-state"
	rotationIDAnnotation        = "hanko.sh/sa-rotation-id"
	rotationPreparedAnnotation  = "hanko.sh/sa-rotation-prepared-at"
	rotationAuditAnnotation     = "hanko.sh/sa-audit-pending"
	rotationStatePrepared       = "prepared"
	credentialRotationCondition = "CredentialRotationReady"
)

// CredentialRotationAuditor persists the metadata-only Hanko audit receipt.
type CredentialRotationAuditor interface {
	RecordServiceAccountRotation(context.Context, string, string, string, string, time.Time) error
}

// ParseServiceAccountMaxAge accepts Go durations and an operator-friendly day
// suffix (for example 2160h or 90d). Empty values use the ADR-021 default.
func ParseServiceAccountMaxAge(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultServiceAccountMaxAge, nil
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 32)
		const maxDuration = time.Duration(1<<63 - 1)
		if err != nil || days <= 0 || days > int64(maxDuration/(24*time.Hour)) {
			return 0, fmt.Errorf("HANKO_KC_SA_MAX_AGE must be a positive duration")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("HANKO_KC_SA_MAX_AGE must be a positive duration")
	}
	return duration, nil
}

func (r *HankoKeycloakInstanceReconciler) reconcileServiceAccountCredential(
	ctx context.Context,
	instance *hankoshv1alpha1.HankoKeycloakInstance,
	activeClient *keycloak.Client,
	statusPatch client.Patch,
) (ctrl.Result, bool, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Name: instance.Spec.AdminRef.Name, Namespace: instance.Namespace}
	if err := r.Get(ctx, key, &secret); err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AdminSecretUnavailable", err)
	}
	if !instance.Spec.RotateAdminCredentials {
		instance.Status.NextCredentialRotation = nil
		if len(secret.Data[pendingClientSecretKey]) != 0 {
			return r.rotationFailure(ctx, instance, statusPatch, "RotationNotRequested",
				fmt.Errorf("AdminRef has a pending rotation; resolve it manually or enable spec.rotateAdminCredentials"))
		}
		setCondition(&instance.Status.Conditions, credentialRotationCondition, metav1.ConditionTrue,
			"ExternallyManaged", "AdminRef credential rotation is administrator-managed")
		return ctrl.Result{}, false, nil
	}
	now := r.rotationNow()
	if pending := secret.Data[pendingClientSecretKey]; len(pending) != 0 {
		return r.resumeServiceAccountRotation(ctx, instance, &secret, activeClient, statusPatch, now)
	}
	if rotationID := secret.Annotations[rotationAuditAnnotation]; rotationID != "" {
		return r.flushServiceAccountRotationAudit(ctx, instance, &secret, statusPatch, rotationID)
	}

	rotatedAtRaw := secret.Annotations[rotatedAtAnnotation]
	if rotatedAtRaw == "" {
		if err := r.initializeServiceAccountRotationClock(ctx, key, now); err != nil {
			return r.rotationFailure(ctx, instance, statusPatch, "RotationClockWriteFailed", err)
		}
		rotatedAtRaw = now.Format(time.RFC3339Nano)
	}
	rotatedAt, err := time.Parse(time.RFC3339Nano, rotatedAtRaw)
	if err != nil {
		log.FromContext(ctx).Info("invalid service-account rotation timestamp; rotating immediately", "secret", key.String())
		return r.prepareServiceAccountRotation(ctx, instance, statusPatch, now)
	}
	r.setRotationSchedule(instance, rotatedAt)
	if now.Before(rotatedAt.Add(r.serviceAccountMaxAge())) {
		setCondition(&instance.Status.Conditions, credentialRotationCondition, metav1.ConditionTrue,
			"Scheduled", "Keycloak service-account credential is within its maximum age")
		return ctrl.Result{}, false, nil
	}
	return r.prepareServiceAccountRotation(ctx, instance, statusPatch, now)
}

func (r *HankoKeycloakInstanceReconciler) prepareServiceAccountRotation(
	ctx context.Context,
	instance *hankoshv1alpha1.HankoKeycloakInstance,
	statusPatch client.Patch,
	now time.Time,
) (ctrl.Result, bool, error) {
	pending, rotationID, err := newPendingServiceAccountCredential()
	if err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "CredentialGenerationFailed", err)
	}
	key := types.NamespacedName{Name: instance.Spec.AdminRef.Name, Namespace: instance.Namespace}
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current corev1.Secret
		if getErr := r.Get(ctx, key, &current); getErr != nil {
			return getErr
		}
		if len(current.Data[pendingClientSecretKey]) != 0 {
			return nil
		}
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Data[pendingClientSecretKey] = pending
		current.Annotations[rotationStateAnnotation] = rotationStatePrepared
		current.Annotations[rotationIDAnnotation] = rotationID
		current.Annotations[rotationPreparedAnnotation] = now.Format(time.RFC3339Nano)
		return r.Update(ctx, &current)
	})
	if err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "RotationPrepareFailed", err)
	}
	instance.Status.Phase = "Probing"
	setCondition(&instance.Status.Conditions, credentialRotationCondition, metav1.ConditionUnknown,
		"RotationPrepared", "A pending credential was persisted before the Keycloak update")
	if err := r.Status().Patch(ctx, instance, statusPatch); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("patch credential rotation preparation status: %w", err)
	}
	return ctrl.Result{RequeueAfter: rotationRetryDelay}, true, nil
}

func (r *HankoKeycloakInstanceReconciler) resumeServiceAccountRotation(
	ctx context.Context,
	instance *hankoshv1alpha1.HankoKeycloakInstance,
	secret *corev1.Secret,
	activeClient *keycloak.Client,
	statusPatch client.Patch,
	now time.Time,
) (ctrl.Result, bool, error) {
	rotationID := secret.Annotations[rotationIDAnnotation]
	if rotationID == "" || secret.Annotations[rotationStateAnnotation] != rotationStatePrepared {
		return r.rotationFailure(ctx, instance, statusPatch, "InvalidPendingRotation", fmt.Errorf("pending credential metadata is incomplete"))
	}
	pendingClient, err := buildKCClientFromAdminSecret(ctx, r.Client, instance, secret, pendingClientSecretKey, r.RequireHTTPS)
	if err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "PendingCredentialInvalid", err)
	}
	if _, pendingErr := pendingClient.ServerVersion(ctx); pendingErr != nil {
		if _, activeErr := activeClient.ServerVersion(ctx); activeErr != nil {
			return r.rotationFailure(ctx, instance, statusPatch, "CredentialRecoveryFailed",
				fmt.Errorf("active and pending credentials were rejected"))
		}
		clientID := string(secret.Data["HANKO_KC_CLIENT_ID"])
		if err := activeClient.SetClientSecret(ctx, "master", clientID, string(secret.Data[pendingClientSecretKey])); err != nil {
			return r.rotationFailure(ctx, instance, statusPatch, "KeycloakRotationFailed", err)
		}
		if _, err := pendingClient.ServerVersion(ctx); err != nil {
			return r.rotationFailure(ctx, instance, statusPatch, "PendingCredentialVerificationFailed", err)
		}
	}
	if err := r.promotePendingServiceAccountCredential(ctx, client.ObjectKeyFromObject(secret), secret.Data[pendingClientSecretKey], rotationID, now); err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "CredentialPromotionFailed", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(instance, nil, corev1.EventTypeNormal, "ServiceAccountCredentialRotated", "Reconcile",
			"Rotated Keycloak service-account credential for client %s", string(secret.Data["HANKO_KC_CLIENT_ID"]))
	}
	r.setRotationSchedule(instance, now)
	result, handled, err := r.flushServiceAccountRotationAudit(ctx, instance, secret, statusPatch, rotationID)
	if err != nil || handled {
		return result, handled, err
	}
	// activeClient was constructed before promotion and still contains the old
	// credential. Persist the completed status and immediately reconcile again
	// so every subsequent Admin API call uses the promoted Secret value.
	instance.Status.Phase = "Probing"
	if err := r.Status().Patch(ctx, instance, statusPatch); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("patch completed credential rotation status: %w", err)
	}
	return ctrl.Result{RequeueAfter: requeueImmediately}, true, nil
}

func (r *HankoKeycloakInstanceReconciler) promotePendingServiceAccountCredential(
	ctx context.Context,
	key client.ObjectKey,
	pending []byte,
	rotationID string,
	rotatedAt time.Time,
) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current corev1.Secret
		if err := r.Get(ctx, key, &current); err != nil {
			return err
		}
		if !bytes.Equal(current.Data[pendingClientSecretKey], pending) || current.Annotations[rotationIDAnnotation] != rotationID {
			return fmt.Errorf("pending credential changed during promotion")
		}
		current.Data[adminClientSecretKey] = append([]byte(nil), pending...)
		delete(current.Data, pendingClientSecretKey)
		delete(current.Annotations, rotationStateAnnotation)
		delete(current.Annotations, rotationIDAnnotation)
		delete(current.Annotations, rotationPreparedAnnotation)
		current.Annotations[rotatedAtAnnotation] = rotatedAt.Format(time.RFC3339Nano)
		current.Annotations[rotationAuditAnnotation] = rotationID
		return r.Update(ctx, &current)
	})
}

func (r *HankoKeycloakInstanceReconciler) flushServiceAccountRotationAudit(
	ctx context.Context,
	instance *hankoshv1alpha1.HankoKeycloakInstance,
	secret *corev1.Secret,
	statusPatch client.Patch,
	rotationID string,
) (ctrl.Result, bool, error) {
	if r.CredentialRotationAudit == nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AuditRecorderUnavailable",
			fmt.Errorf("hanko operator audit endpoint is not configured"))
	}
	key := client.ObjectKeyFromObject(secret)
	var current corev1.Secret
	if err := r.Get(ctx, key, &current); err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AuditMetadataUnavailable", err)
	}
	rotatedAt, err := time.Parse(time.RFC3339Nano, current.Annotations[rotatedAtAnnotation])
	if err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AuditMetadataInvalid", err)
	}
	clientID := string(current.Data["HANKO_KC_CLIENT_ID"])
	if err := r.CredentialRotationAudit.RecordServiceAccountRotation(ctx, instance.Namespace, instance.Name, clientID, rotationID, rotatedAt); err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AuditWriteFailed", err)
	}
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var latest corev1.Secret
		if getErr := r.Get(ctx, key, &latest); getErr != nil {
			return getErr
		}
		if latest.Annotations[rotationAuditAnnotation] != rotationID {
			return nil
		}
		delete(latest.Annotations, rotationAuditAnnotation)
		return r.Update(ctx, &latest)
	}); err != nil {
		return r.rotationFailure(ctx, instance, statusPatch, "AuditReceiptUpdateFailed", err)
	}
	r.setRotationSchedule(instance, rotatedAt)
	setCondition(&instance.Status.Conditions, credentialRotationCondition, metav1.ConditionTrue,
		"RotationCompleted", "Keycloak credential rotation was verified and audited")
	return ctrl.Result{}, false, nil
}

func (r *HankoKeycloakInstanceReconciler) initializeServiceAccountRotationClock(ctx context.Context, key client.ObjectKey, now time.Time) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current corev1.Secret
		if err := r.Get(ctx, key, &current); err != nil {
			return err
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		if current.Annotations[rotatedAtAnnotation] != "" {
			return nil
		}
		current.Annotations[rotatedAtAnnotation] = now.Format(time.RFC3339Nano)
		return r.Update(ctx, &current)
	})
}

func (r *HankoKeycloakInstanceReconciler) rotationFailure(
	ctx context.Context,
	instance *hankoshv1alpha1.HankoKeycloakInstance,
	statusPatch client.Patch,
	reason string,
	cause error,
) (ctrl.Result, bool, error) {
	instance.Status.Phase = "Degraded"
	setCondition(&instance.Status.Conditions, credentialRotationCondition, metav1.ConditionFalse, reason, cause.Error())
	if err := r.Status().Patch(ctx, instance, statusPatch); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("patch credential rotation failure status: %w", err)
	}
	log.FromContext(ctx).Error(cause, "Keycloak service-account credential rotation degraded", "reason", reason)
	return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
}

func (r *HankoKeycloakInstanceReconciler) setRotationSchedule(instance *hankoshv1alpha1.HankoKeycloakInstance, rotatedAt time.Time) {
	last := metav1.NewTime(rotatedAt.UTC())
	next := metav1.NewTime(rotatedAt.Add(r.serviceAccountMaxAge()).UTC())
	instance.Status.LastCredentialRotation = &last
	instance.Status.NextCredentialRotation = &next
}

func (r *HankoKeycloakInstanceReconciler) serviceAccountMaxAge() time.Duration {
	if r.ServiceAccountMaxAge > 0 {
		return r.ServiceAccountMaxAge
	}
	return defaultServiceAccountMaxAge
}

func (r *HankoKeycloakInstanceReconciler) rotationNow() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func newPendingServiceAccountCredential() ([]byte, string, error) {
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("generate pending service-account credential: %w", err)
	}
	operation := make([]byte, 16)
	if _, err := rand.Read(operation); err != nil {
		return nil, "", fmt.Errorf("generate service-account rotation ID: %w", err)
	}
	return []byte(base64.RawURLEncoding.EncodeToString(secret)), "rot_" + hex.EncodeToString(operation), nil
}
