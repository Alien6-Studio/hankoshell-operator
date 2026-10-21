package controller

import (
	"context"
	"maps"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const saRotationJournalKey = "hanko.sh/sa-secret-rotation"
const saRotationSchema = "hanko.sh/service-account-rotation/v1alpha1"
const saRotationOutputKey = "hanko.sh/sa-secret-rotation-request"

type serviceAccountRotationJournal struct {
	Schema     string `json:"schema"`
	OwnerUID   string `json:"ownerUID"`
	Generation int64  `json:"generation"`
	ClientUUID string `json:"clientUUID"`
	Source     string `json:"source"`
	SecretUID  string `json:"secretUID"`
	RequestID  string `json:"requestID"`
	RotatedAt  string `json:"rotatedAt"`
	Step       string `json:"step"`
	Attempted  bool   `json:"attempted"`
}

func canonicalServiceAccountSecret(s *corev1.Secret) string {
	if v := s.StringData["client_secret"]; v != "" {
		return v
	}
	return string(s.Data["client_secret"])
}

func (r *HankoServiceAccountReconciler) saveServiceAccountRotation(ctx context.Context, sa *api.HankoServiceAccount, kc *keycloak.Client, j serviceAccountRotationJournal) error {
	if r.validateServiceAccountExecution(ctx, sa, kc, true) != nil {
		return keycloak.ErrApplicationPrecondition
	}
	var current api.HankoServiceAccount
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if reader.Get(ctx, client.ObjectKeyFromObject(sa), &current) != nil || current.UID != sa.UID || current.Generation != sa.Generation {
		return keycloak.ErrApplicationPrecondition
	}
	value := workloadauth.Encode(j)
	if current.Annotations[saRotationJournalKey] != value {
		patch := client.MergeFromWithOptions(current.DeepCopy(), client.MergeFromWithOptimisticLock{})
		current.Annotations = maps.Clone(current.Annotations)
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[saRotationJournalKey] = value
		_ = r.Patch(ctx, &current, patch)
	}
	if reader.Get(ctx, client.ObjectKeyFromObject(sa), &current) != nil || current.UID != sa.UID || current.Generation != sa.Generation || current.Annotations[saRotationJournalKey] != value {
		return keycloak.ErrApplicationPrecondition
	}
	sa.Annotations = maps.Clone(current.Annotations)
	sa.ResourceVersion = current.ResourceVersion
	return nil
}

// Rotation retains the previous canonical credential until fresh native
// read-back proves the change. Only ephemeral equality compares credentials;
// no credential hash enters the public journal, plan, status or evidence.
func (r *HankoServiceAccountReconciler) durableServiceAccountRotation(ctx context.Context, sa *api.HankoServiceAccount, p *api.SecretRotationPolicy, now *metav1.Time, kc *keycloak.Client) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var current api.HankoServiceAccount
	if reader.Get(ctx, client.ObjectKeyFromObject(sa), &current) != nil || current.UID != sa.UID {
		return keycloak.ErrApplicationPrecondition
	}
	var j serviceAccountRotationJournal
	if value := current.Annotations[saRotationJournalKey]; value != "" {
		if workloadauth.Decode(value, &j) != nil || j.Schema != saRotationSchema || j.OwnerUID != string(sa.UID) || j.Source != kc.BaseURL() || (j.Step != "Prepared" && j.Step != "OutputPrepared" && j.Step != "Committed") {
			return keycloak.ErrApplicationPrecondition
		}
		at, err := time.Parse(time.RFC3339Nano, j.RotatedAt)
		if err != nil {
			return keycloak.ErrApplicationPrecondition
		}
		if j.Step == "Committed" {
			recovered := metav1.NewTime(at)
			if sa.Status.LastRotated == nil || sa.Status.LastRotated.Before(&recovered) {
				sa.Status.LastRotated = &recovered
			}
		}
	}
	if j.Step == "Committed" || j.Step == "" {
		if p == nil || !p.Enabled || !serviceAccountRotationDue(sa, p, now) {
			setServiceAccountNextRotation(sa, p)
			return nil
		}
		j = serviceAccountRotationJournal{}
	} else if j.Generation != sa.Generation || authenticationMode(sa) != "Secret" || p == nil || !p.Enabled {
		return keycloak.ErrApplicationPrecondition
	}
	if r.validateServiceAccountExecution(ctx, sa, kc, true) != nil {
		return keycloak.ErrApplicationPrecondition
	}
	native, err := kc.GetApplication(ctx, sa.Spec.RealmRef, sa.Spec.ClientID)
	if err != nil || native == nil {
		return keycloak.ErrApplicationPrecondition
	}
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: sa.Namespace, Name: saSecretName(sa.Spec.ClientID)}
	if reader.Get(ctx, key, &secret) != nil || !metav1.IsControlledBy(&secret, sa) || !secret.DeletionTimestamp.IsZero() || canonicalServiceAccountSecret(&secret) == "" {
		return keycloak.ErrApplicationPrecondition
	}
	if j.Schema == "" {
		j = serviceAccountRotationJournal{Schema: saRotationSchema, OwnerUID: string(sa.UID), Generation: sa.Generation, ClientUUID: native.ID, Source: kc.BaseURL(), SecretUID: string(secret.UID), RequestID: workloadauth.Hash("rotation-request", struct{ UID, ClientID, At string }{string(sa.UID), native.ID, now.UTC().Format(time.RFC3339Nano)}), RotatedAt: now.UTC().Format(time.RFC3339Nano), Step: "Prepared"}
		if err := r.saveServiceAccountRotation(ctx, sa, kc, j); err != nil {
			return err
		}
	}
	if native.ID != j.ClientUUID || string(secret.UID) != j.SecretUID {
		return keycloak.ErrApplicationPrecondition
	}
	if secret.Annotations[saRotationOutputKey] != j.RequestID {
		old := canonicalServiceAccountSecret(&secret)
		if !j.Attempted {
			// Persist intent before the non-idempotent native rotation.
			j.Attempted = true
			if err := r.saveServiceAccountRotation(ctx, sa, kc, j); err != nil {
				return err
			}
			_, _ = kc.RotateServiceAccountSecretIfOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID))
		}
		value, err := kc.GetServiceAccountSecretIfOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID))
		if err != nil {
			return keycloak.ErrApplicationPrecondition
		}
		if value == "" || value == old {
			return keycloak.ErrApplicationPrecondition
		}
		if r.validateServiceAccountExecution(ctx, sa, kc, true) != nil {
			return keycloak.ErrApplicationPrecondition
		}
		patch := client.MergeFromWithOptions(secret.DeepCopy(), client.MergeFromWithOptimisticLock{})
		secret.Data = maps.Clone(secret.Data)
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data["client_secret"] = []byte(value)
		secret.StringData = nil
		secret.Annotations = maps.Clone(secret.Annotations)
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[saRotationOutputKey] = j.RequestID
		_ = r.Patch(ctx, &secret, patch)
	}
	if reader.Get(ctx, key, &secret) != nil || !metav1.IsControlledBy(&secret, sa) || string(secret.UID) != j.SecretUID || secret.Annotations[saRotationOutputKey] != j.RequestID || canonicalServiceAccountSecret(&secret) == "" {
		return keycloak.ErrApplicationPrecondition
	}
	value, err := kc.GetServiceAccountSecretIfOwned(ctx, sa.Spec.RealmRef, sa.Spec.ClientID, string(sa.UID))
	if err != nil || value != canonicalServiceAccountSecret(&secret) {
		return keycloak.ErrApplicationPrecondition
	}
	if j.Step == "Prepared" {
		j.Step = "OutputPrepared"
		if err := r.saveServiceAccountRotation(ctx, sa, kc, j); err != nil {
			return err
		}
	}
	j.Step = "Committed"
	if err := r.saveServiceAccountRotation(ctx, sa, kc, j); err != nil {
		return err
	}
	at, _ := time.Parse(time.RFC3339Nano, j.RotatedAt)
	rotated := metav1.NewTime(at)
	setServiceAccountSecretStatus(sa, &rotated)
	setServiceAccountNextRotation(sa, p)
	return nil
}
