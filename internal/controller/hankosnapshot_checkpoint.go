package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	snapshotIntentAnnotation = "hanko.sh/snapshot-intent"
	snapshotHashAnnotation   = "hanko.sh/snapshot-hash"
)

func (r *HankoSnapshotReconciler) snapshotReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func snapshotPatch(snapshot *api.HankoSnapshot) client.Patch {
	return client.MergeFromWithOptions(snapshot.DeepCopy(), client.MergeFromWithOptimisticLock{})
}

func snapshotHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func snapshotIntentHash(snapshot *api.HankoSnapshot) string {
	data, _ := json.Marshal(struct {
		Spec   api.HankoSnapshotSpec
		Tenant string
	}{snapshot.Spec, snapshot.Labels["hanko.sh/tenant"]})
	return snapshotHash(data)
}

func validateSnapshotCheckpoint(snapshot *api.HankoSnapshot, instance *api.HankoKeycloakInstance) string {
	if snapshot.UID == "" || instance.UID == "" || !instance.DeletionTimestamp.IsZero() || snapshot.Labels["hanko.sh/tenant"] != instance.Labels["hanko.sh/tenant"] {
		return "snapshot requires a current instance in the same tenant"
	}
	s := snapshot.Status
	if s.IntentHash == "" {
		if (s.Phase != "" && s.Phase != "Pending") || s.ConfigMapRef != "" || s.ConfigMapUID != "" || s.ConfigHash != "" || s.DBJobRef != "" || s.DBJobUID != "" || s.InstanceUID != "" || s.StartedGeneration != 0 {
			return "snapshot checkpoint is incomplete or predates identity binding"
		}
		return ""
	}
	if s.Phase != "Running" || s.IntentHash != snapshotIntentHash(snapshot) || s.StartedGeneration != snapshot.Generation || s.InstanceUID != string(instance.UID) {
		return "snapshot intent or source identity changed after execution began"
	}
	if (s.ConfigMapUID == "") != (s.ConfigHash == "") || (s.ConfigMapUID == "") != (s.ConfigMapRef == "") || (s.DBJobUID == "") != (s.DBJobRef == "") {
		return "snapshot child checkpoint is incomplete"
	}
	if (s.ConfigMapRef != "" && s.ConfigMapRef != "snap-"+snapshot.Name+"-config") || (s.DBJobRef != "" && (!snapshot.Spec.IncludeData || s.DBJobRef != "snap-"+snapshot.Name+"-pgdump" || s.ConfigMapUID == "")) {
		return "snapshot child checkpoint differs from its intent"
	}
	return ""
}

func snapshotChildMatches(snapshot *api.HankoSnapshot, child client.Object) bool {
	owner := metav1.GetControllerOf(child)
	return snapshot.UID != "" && child.GetUID() != "" && owner != nil &&
		owner.UID == snapshot.UID && owner.Name == snapshot.Name && owner.Kind == "HankoSnapshot" && owner.APIVersion == api.GroupVersion.String() &&
		child.GetDeletionTimestamp().IsZero() && child.GetNamespace() == snapshot.Namespace &&
		snapshot.Status.IntentHash != "" && child.GetAnnotations()[snapshotIntentAnnotation] == snapshot.Status.IntentHash &&
		child.GetLabels()["hanko.sh/tenant"] == snapshot.Labels["hanko.sh/tenant"]
}

// Recover the stored capture before enumerating live configuration: a retry must
// preserve the point in time already written, even if the source inventory changed.
func (r *HankoSnapshotReconciler) ensureSnapshotConfig(ctx context.Context, snapshot *api.HankoSnapshot, patch client.Patch) (bool, error) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "snap-" + snapshot.Name + "-config", Namespace: snapshot.Namespace}}
	err := r.snapshotReader().Get(ctx, client.ObjectKeyFromObject(cm), cm)
	if client.IgnoreNotFound(err) != nil {
		return true, err
	}
	if errors.IsNotFound(err) {
		if snapshot.Status.ConfigMapUID != "" {
			return true, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"ConfigMapContractMismatch", "checkpointed configuration disappeared; inspect it before creating a new snapshot", "configuration missing"})
		}
		raw, err := r.snapshotPayload(ctx, snapshot.Namespace)
		if err != nil {
			return true, err
		}
		cm.Immutable = boolPtr(true)
		cm.Data = map[string]string{"snapshot.json": string(raw)}
		cm.Annotations = map[string]string{snapshotIntentAnnotation: snapshot.Status.IntentHash, snapshotHashAnnotation: snapshotHash(raw)}
		cm.Labels = map[string]string{"hanko.sh/tenant": snapshot.Labels["hanko.sh/tenant"]}
		if err := controllerutil.SetControllerReference(snapshot, cm, r.Scheme); err != nil {
			return true, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"OwnerRefError", err.Error(), "configuration owner reference"})
		}
		if err := r.Create(ctx, cm); err != nil {
			return true, err
		}
	}
	raw := []byte(cm.Data["snapshot.json"])
	digest := snapshotHash(raw)
	if !snapshotChildMatches(snapshot, cm) || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || !json.Valid(raw) || cm.Annotations[snapshotHashAnnotation] != digest ||
		(snapshot.Status.ConfigMapUID != "" && (snapshot.Status.ConfigMapUID != string(cm.UID) || snapshot.Status.ConfigHash != digest)) {
		return true, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"ConfigMapContractMismatch", "existing configuration differs from this snapshot's ownership, identity or immutable content; inspect it manually", "configuration contract mismatch"})
	}
	if snapshot.Status.ConfigMapUID == "" {
		snapshot.Status.ConfigMapRef, snapshot.Status.ConfigMapUID, snapshot.Status.ConfigHash = cm.Name, string(cm.UID), digest
		// Persist the capture identity before starting an external database action.
		if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
			return true, err
		}
	}
	return false, nil
}
