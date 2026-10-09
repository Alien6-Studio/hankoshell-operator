package controller

import (
	"context"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Projection preconditions request Kubernetes metadata only. Secret contents
// never enter the compiler; UID and independently checked local authorization
// make replacement/revocation stale without reacting to our own value writes.
func (r *HankoApplicationReconciler) applicationProjectionReferences(ctx context.Context, app *api.HankoApplication, references *contractReferenceReader) error {
	for _, target := range app.Spec.ClientSecretProjections {
		metadata := &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}}
		if err := r.secretProjectionClient().Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Name}, metadata); err != nil {
			return err
		}
		if !metadata.DeletionTimestamp.IsZero() || !secretProjectionOwnedBy(&corev1.Secret{ObjectMeta: metadata.ObjectMeta}, app) {
			return iamcontract.ErrRejected
		}
		references.references = append(references.references, referenceIdentity{metadata.Namespace, metadata.Name, string(metadata.UID), metadata.Generation})
	}
	return nil
}
