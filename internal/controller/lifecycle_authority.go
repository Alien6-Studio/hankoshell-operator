package controller

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const lifecycleApprovalAnnotation = "hanko.sh/lifecycle-approval"

var errLifecycleApproval = errors.New("current administrator lifecycle approval is required")

// The registered controller always enters through this guard. The step-machine
// helpers remain independently testable; the context rechecks authority at each
// effect boundary, including after a slow capture or image verification.
type lifecycleApprovalGuard struct {
	client.Client
	reader   client.Reader
	inner    reconcile.Reconciler
	snapshot bool
}

type lifecycleAuthorityKey struct{}

func checkLifecycleAuthority(ctx context.Context) error {
	if check, ok := ctx.Value(lifecycleAuthorityKey{}).(func() error); ok {
		return check()
	}
	return nil // State-machine unit tests run without a registered controller context.
}

func lifecycleApprovalValue(object client.Object, intent, instanceUID string) string {
	return "v1|" + string(object.GetUID()) + "|" + strconv.FormatInt(object.GetGeneration(), 10) + "|" + instanceUID + "|" + intent
}

func (g *lifecycleApprovalGuard) authority(ctx context.Context, key client.ObjectKey) (client.Object, string, bool, error) {
	var object client.Object = &api.HankoOperation{}
	if g.snapshot {
		object = &api.HankoSnapshot{}
	}
	if err := g.reader.Get(ctx, key, object); err != nil {
		return nil, "", false, err
	}
	var ref, intent string
	switch value := object.(type) {
	case *api.HankoOperation:
		if value.Status.Phase == "Done" || value.Status.Phase == "Failed" || value.Spec.DryRun || !value.DeletionTimestamp.IsZero() {
			return object, "", true, nil
		}
		ref, intent = value.Spec.InstanceRef, operationIntentHash(value)
	case *api.HankoSnapshot:
		if value.Status.Phase == "Done" || value.Status.Phase == "Failed" || !value.DeletionTimestamp.IsZero() {
			return object, "", true, nil
		}
		ref, intent = value.Spec.InstanceRef, snapshotIntentHash(value)
	}
	var instance api.HankoKeycloakInstance
	if err := g.reader.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: ref}, &instance); err != nil {
		return object, "", false, err
	}
	if object.GetUID() == "" || object.GetGeneration() < 1 || instance.UID == "" || !instance.DeletionTimestamp.IsZero() || !sameTenantScope(object, &instance) {
		return object, "", false, errLifecycleApproval
	}
	expected := lifecycleApprovalValue(object, intent, string(instance.UID))
	if object.GetAnnotations()[lifecycleApprovalAnnotation] == expected {
		if operation, ok := object.(*api.HankoOperation); ok && operation.Spec.Type == api.OperationDBSwitch {
			if err := g.databaseReference(ctx, operation, &instance); err != nil {
				return object, expected, false, err
			}
		}
		return object, expected, true, nil
	}
	if snapshot, ok := object.(*api.HankoSnapshot); ok && g.approvedSnapshotChild(ctx, snapshot, &instance) {
		return object, expected, true, nil
	}
	return object, expected, false, nil
}

var errLifecycleDatabase = errors.New("DBSwitch requires a current same-scope dedicated PostgreSQL Secret with only KC_DB, KC_DB_URL, KC_DB_USERNAME and KC_DB_PASSWORD")

func (g *lifecycleApprovalGuard) databaseReference(ctx context.Context, operation *api.HankoOperation, instance *api.HankoKeycloakInstance) error {
	if operation.Spec.DBSwitch == nil || instance.Spec.Managed == nil {
		return errLifecycleDatabase
	}
	ref := operation.Spec.DBSwitch.NewDatabaseSecretRef
	if ref == "" || ref == instance.Spec.AdminRef.Name || ref == instance.Spec.TLSCARef || ref == instance.Spec.Managed.TLSSecretRef {
		return errLifecycleDatabase
	}
	var secret corev1.Secret
	if err := g.reader.Get(ctx, client.ObjectKey{Namespace: operation.Namespace, Name: ref}, &secret); err != nil {
		return errLifecycleDatabase
	}
	if !secret.DeletionTimestamp.IsZero() || !sameTenantScope(operation, &secret) || len(secret.Data) != 4 ||
		string(secret.Data["KC_DB"]) != "postgres" || !strings.HasPrefix(string(secret.Data["KC_DB_URL"]), "jdbc:postgresql://") ||
		len(secret.Data["KC_DB_URL"]) > 4096 || len(secret.Data["KC_DB_USERNAME"]) == 0 || len(secret.Data["KC_DB_PASSWORD"]) == 0 {
		return errLifecycleDatabase
	}
	endpoint, err := url.Parse(strings.TrimPrefix(string(secret.Data["KC_DB_URL"]), "jdbc:"))
	if err != nil || endpoint.Hostname() == "" || endpoint.Path == "" || endpoint.Path == "/" || endpoint.User != nil || endpoint.Fragment != "" {
		return errLifecycleDatabase
	}
	return nil
}

func (g *lifecycleApprovalGuard) approvedSnapshotChild(ctx context.Context, snapshot *api.HankoSnapshot, instance *api.HankoKeycloakInstance) bool {
	owner := metav1.GetControllerOf(snapshot)
	if owner == nil || owner.Kind != "HankoOperation" || owner.APIVersion != api.GroupVersion.String() {
		return false
	}
	var parent api.HankoOperation
	if err := g.reader.Get(ctx, client.ObjectKey{Namespace: snapshot.Namespace, Name: owner.Name}, &parent); err != nil {
		return false
	}
	if parent.UID != owner.UID || !parent.DeletionTimestamp.IsZero() || parent.Spec.DryRun || parent.Status.Phase == "Failed" ||
		validateOperationSource(&parent, instance) != "" || validateOperationCheckpoint(&parent, instance) != "" ||
		parent.Annotations[lifecycleApprovalAnnotation] != lifecycleApprovalValue(&parent, operationIntentHash(&parent), string(instance.UID)) {
		return false
	}
	wanted := &api.HankoSnapshot{Spec: api.HankoSnapshotSpec{InstanceRef: parent.Spec.InstanceRef}}
	for i := range parent.Status.Steps {
		step := &parent.Status.Steps[i]
		if step.Name == "Snapshot" && (step.Status == "Pending" || step.Status == "Running") &&
			(parent.Spec.SnapshotBefore == nil || *parent.Spec.SnapshotBefore) && snapshot.Name == "op-"+parent.Name+"-snap" {
			return operationChildMatches(&parent, step, snapshot, operationChildSpec(wanted))
		}
	}
	return false
}

func (g *lifecycleApprovalGuard) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object, expected, approved, err := g.authority(ctx, request.NamespacedName)
	if err != nil {
		if object == nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		patch := lifecyclePatch(object)
		iamCondition(lifecycleConditions(object), object.GetGeneration(), "Authorized", metav1.ConditionFalse, "AuthorityUnavailable", "current lifecycle source, scope or database authority is unavailable")
		return ctrl.Result{RequeueAfter: requeueOnError}, errors.Join(err, g.Status().Patch(ctx, object, patch))
	}
	if !approved {
		patch := lifecyclePatch(object)
		conditions := lifecycleConditions(object)
		iamCondition(conditions, object.GetGeneration(), "Authorized", metav1.ConditionFalse, "ApprovalRequired", "Approval required: "+expected)
		return ctrl.Result{RequeueAfter: requeueOnError}, g.Status().Patch(ctx, object, patch)
	}
	if expected != "" {
		patch := lifecyclePatch(object)
		conditions := lifecycleConditions(object)
		condition := meta.FindStatusCondition(*conditions, "Authorized")
		if condition == nil || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != object.GetGeneration() {
			iamCondition(conditions, object.GetGeneration(), "Authorized", metav1.ConditionTrue, "AdministratorApproved", "current lifecycle intent has administrator approval")
			if err := g.Status().Patch(ctx, object, patch); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	check := func() error {
		current, currentExpected, allowed, err := g.authority(ctx, request.NamespacedName)
		if err != nil {
			return err
		}
		if !allowed || current.GetUID() != object.GetUID() || current.GetGeneration() != object.GetGeneration() || currentExpected != expected || !current.GetDeletionTimestamp().IsZero() {
			return errLifecycleApproval
		}
		return nil
	}
	return g.inner.Reconcile(context.WithValue(ctx, lifecycleAuthorityKey{}, check), request)
}

func lifecycleConditions(object client.Object) *[]metav1.Condition {
	if snapshot, ok := object.(*api.HankoSnapshot); ok {
		return &snapshot.Status.Conditions
	}
	if operation, ok := object.(*api.HankoOperation); ok {
		return &operation.Status.Conditions
	}
	panic("unsupported lifecycle guard object")
}

func lifecyclePatch(object client.Object) client.Patch {
	switch value := object.(type) {
	case *api.HankoOperation:
		return client.MergeFromWithOptions(value.DeepCopy(), client.MergeFromWithOptimisticLock{})
	case *api.HankoSnapshot:
		return client.MergeFromWithOptions(value.DeepCopy(), client.MergeFromWithOptimisticLock{})
	default:
		panic("unsupported lifecycle guard object")
	}
}
