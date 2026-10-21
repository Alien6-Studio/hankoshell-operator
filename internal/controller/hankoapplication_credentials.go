package controller

import (
	"context"
	"fmt"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ownedApplicationCredential(secret *corev1.Secret, app *api.HankoApplication) bool {
	owner := metav1.GetControllerOf(secret)
	return secret.UID != "" && secret.ResourceVersion != "" && secret.DeletionTimestamp.IsZero() &&
		app.UID != "" && owner != nil && owner.UID == app.UID && owner.Name == app.Name &&
		owner.Kind == "HankoApplication" && owner.APIVersion == api.GroupVersion.String()
}

func checkCredentialAuthority(ctx context.Context, guard func(context.Context) error) error {
	if guard != nil {
		return guard(ctx)
	}
	return nil
}

func (r *HankoApplicationReconciler) acknowledgeApplicationCredential(ctx context.Context, app *api.HankoApplication, written *corev1.Secret, value string, guard func(context.Context) error) error {
	var current corev1.Secret
	if err := r.applicationCredentialReader().Get(ctx, client.ObjectKeyFromObject(written), &current); err != nil {
		return err
	}
	if !ownedApplicationCredential(&current, app) || current.UID != written.UID || value == "" || string(current.Data["client_secret"]) != value {
		return fmt.Errorf("canonical application credential write is not proven current")
	}
	if err := checkCredentialAuthority(ctx, guard); err != nil {
		return err
	}
	return r.reconcileSecretProjections(ctx, app, value, guard)
}

func (r *HankoApplicationReconciler) acknowledgeSecretProjection(ctx context.Context, app *api.HankoApplication, written *corev1.Secret, value string, cleanup bool, guard func(context.Context) error) error {
	var current corev1.Secret
	if err := r.secretProjectionClient().Get(ctx, client.ObjectKeyFromObject(written), &current); err != nil {
		return err
	}
	if !secretProjectionOwnedBy(&current, app) || current.UID != written.UID ||
		(!cleanup && string(current.Data["client_secret"]) != value) || (cleanup && len(current.Data) != 0) {
		return fmt.Errorf("application Secret projection write is not proven current")
	}
	return checkCredentialAuthority(ctx, guard)
}
