package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// effectiveSecretRotationPolicy gives a child-specific policy precedence over
// the realm default. Imported/Observe objects never call this helper from their
// mutation path, so a realm default cannot rotate credentials Hanko does not own.
func effectiveSecretRotationPolicy(ctx context.Context, reader client.Reader, namespace, realmRef string, explicit *hankoshv1alpha1.SecretRotationPolicy) (*hankoshv1alpha1.SecretRotationPolicy, error) {
	if explicit != nil {
		return explicit, nil
	}
	var realm hankoshv1alpha1.HankoRealm
	if err := reader.Get(ctx, types.NamespacedName{Name: realmRef, Namespace: namespace}, &realm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if realm.Spec.SecurityProfile == nil || realm.Spec.SecurityProfile.ClientSecretRotationDays == nil {
		effective, resolveErr := resolveRealmIAMProfile(ctx, reader, &realm)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if effective.Security == nil || effective.Security.ClientSecretRotationDays == nil {
			return nil, nil
		}
		days := *effective.Security.ClientSecretRotationDays
		return &hankoshv1alpha1.SecretRotationPolicy{Enabled: days > 0, IntervalDays: days}, nil
	}
	days := *realm.Spec.SecurityProfile.ClientSecretRotationDays
	return &hankoshv1alpha1.SecretRotationPolicy{Enabled: days > 0, IntervalDays: days}, nil
}
