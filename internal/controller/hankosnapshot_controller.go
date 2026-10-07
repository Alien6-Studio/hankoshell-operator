package controller

import (
	"context"
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// HankoSnapshotReconciler reconciles HankoSnapshot objects (one-shot).
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankosnapshots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankosnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms;hankoapplications;hankoserviceaccounts;hankoissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create
type HankoSnapshotReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// snapshotData is the JSON structure stored in the config ConfigMap.
type snapshotData struct {
	Realms          []hankoshv1alpha1.HankoRealm          `json:"realms"`
	Applications    []hankoshv1alpha1.HankoApplication    `json:"applications"`
	ServiceAccounts []hankoshv1alpha1.HankoServiceAccount `json:"serviceAccounts"`
	Issuers         []hankoshv1alpha1.HankoIssuer         `json:"issuers"`
}

func (r *HankoSnapshotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var snapshot hankoshv1alpha1.HankoSnapshot
	if err := r.Get(ctx, req.NamespacedName, &snapshot); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if snapshot.Status.Phase == "Done" || snapshot.Status.Phase == "Failed" {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFrom(snapshot.DeepCopy())
	snapshot.Status.Phase = "Running"
	if err := r.Status().Patch(ctx, &snapshot, patch); err != nil {
		log.FromContext(ctx).Error(err, "patch status to Running")
	}
	patch = client.MergeFrom(snapshot.DeepCopy())

	instance, handled := r.snapshotInstance(ctx, &snapshot, patch)
	if handled {
		return ctrl.Result{}, nil
	}
	if r.ensureSnapshotConfig(ctx, &snapshot, patch) {
		return ctrl.Result{}, nil
	}
	if result, handled := r.reconcileSnapshotData(ctx, &snapshot, instance, patch); handled {
		return result, nil
	}
	return r.completeSnapshot(ctx, &snapshot, patch)
}

type snapshotFailure struct {
	reason     string
	message    string
	logMessage string
}

func (r *HankoSnapshotReconciler) failSnapshot(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch, failure snapshotFailure) {
	snapshot.Status.Phase = "Failed"
	setCondition(&snapshot.Status.Conditions, "SnapshotReady", metav1.ConditionFalse, failure.reason, failure.message)
	if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
		log.FromContext(ctx).Error(err, failure.logMessage)
	}
}

func (r *HankoSnapshotReconciler) snapshotInstance(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) (*hankoshv1alpha1.HankoKeycloakInstance, bool) {
	var instance hankoshv1alpha1.HankoKeycloakInstance
	err := r.Get(ctx, types.NamespacedName{Name: snapshot.Spec.InstanceRef, Namespace: snapshot.Namespace}, &instance)
	if err == nil {
		return &instance, false
	}
	failure := snapshotFailure{
		reason:     "InstanceNotFound",
		message:    fmt.Sprintf("HankoKeycloakInstance %q not found in namespace %q", snapshot.Spec.InstanceRef, snapshot.Namespace),
		logMessage: "patch status after instance error",
	}
	if !errors.IsNotFound(err) {
		failure.reason = "InstanceError"
		failure.message = fmt.Sprintf("get HankoKeycloakInstance %q: %v", snapshot.Spec.InstanceRef, err)
	}
	r.failSnapshot(ctx, snapshot, patch, failure)
	return nil, true
}

func (r *HankoSnapshotReconciler) ensureSnapshotConfig(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) bool {
	raw, failure := r.snapshotPayload(ctx, snapshot.Namespace)
	if failure != nil {
		r.failSnapshot(ctx, snapshot, patch, *failure)
		return true
	}
	name := "snap-" + snapshot.Name + "-config"
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: snapshot.Namespace}}
	if err := controllerutil.SetControllerReference(snapshot, configMap, r.Scheme); err != nil {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"OwnerRefError", err.Error(), "patch status after owner ref error"})
		return true
	}
	if failure := r.createSnapshotConfigMap(ctx, configMap, raw); failure != nil {
		r.failSnapshot(ctx, snapshot, patch, *failure)
		return true
	}
	snapshot.Status.ConfigMapRef = name
	return false
}

func (r *HankoSnapshotReconciler) snapshotPayload(ctx context.Context, namespace string) ([]byte, *snapshotFailure) {
	var payload snapshotData
	var realms hankoshv1alpha1.HankoRealmList
	if err := r.List(ctx, &realms, client.InNamespace(namespace)); err != nil {
		return nil, &snapshotFailure{"ListRealmsError", err.Error(), "patch status after list realms error"}
	}
	payload.Realms = realms.Items
	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(namespace)); err != nil {
		return nil, &snapshotFailure{"ListAppsError", err.Error(), "patch status after list apps error"}
	}
	payload.Applications = applications.Items
	var serviceAccounts hankoshv1alpha1.HankoServiceAccountList
	if err := r.List(ctx, &serviceAccounts, client.InNamespace(namespace)); err != nil {
		return nil, &snapshotFailure{"ListSAsError", err.Error(), "patch status after list service accounts error"}
	}
	payload.ServiceAccounts = serviceAccounts.Items
	var issuers hankoshv1alpha1.HankoIssuerList
	if err := r.List(ctx, &issuers, client.InNamespace(namespace)); err != nil {
		return nil, &snapshotFailure{"ListIssuersError", err.Error(), "patch status after list issuers error"}
	}
	payload.Issuers = issuers.Items
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, &snapshotFailure{"SerializeError", err.Error(), "patch status after serialize error"}
	}
	return raw, nil
}

func (r *HankoSnapshotReconciler) createSnapshotConfigMap(ctx context.Context, configMap *corev1.ConfigMap, raw []byte) *snapshotFailure {
	var existing corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, &existing)
	if err == nil {
		return nil
	}
	if !errors.IsNotFound(err) {
		return &snapshotFailure{"ConfigMapGetError", err.Error(), "patch status after configmap get error"}
	}
	configMap.Data = map[string]string{"snapshot.json": string(raw)}
	if err := r.Create(ctx, configMap); err != nil {
		return &snapshotFailure{"ConfigMapCreateError", err.Error(), "patch status after configmap create error"}
	}
	log.FromContext(ctx).Info("created snapshot ConfigMap", "configmap", configMap.Name)
	return nil
}

func (r *HankoSnapshotReconciler) reconcileSnapshotData(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch) (ctrl.Result, bool) {
	if !snapshot.Spec.IncludeData {
		return ctrl.Result{}, false
	}
	if snapshot.Spec.BackupPVC == "" {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"BackupPVCMissing", "includeData=true requires backupPVC to be set", "patch status after backup PVC missing"})
		return ctrl.Result{}, true
	}
	if instance.Spec.Managed == nil {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"ManagedSpecMissing", "includeData=true requires mode=managed with a Database secret", "patch status after managed spec missing"})
		return ctrl.Result{}, true
	}

	jobName := "snap-" + snapshot.Name + "-pgdump"
	snapshot.Status.DBJobRef = jobName
	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: snapshot.Namespace}, &job)
	if errors.IsNotFound(err) {
		return r.createSnapshotJob(ctx, snapshot, instance, patch, jobName), true
	}
	if err != nil {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"JobGetError", err.Error(), "patch status after job get error"})
		return ctrl.Result{}, true
	}
	if !isJobComplete(&job) {
		if isJobFailed(&job) {
			message := fmt.Sprintf("pg_dump Job %q failed", jobName)
			r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"JobFailed", message, "patch status after job failed"})
			return ctrl.Result{}, true
		}
		r.patchSnapshotWhileWaiting(ctx, snapshot, patch)
		return ctrl.Result{RequeueAfter: requeueOnError}, true
	}
	log.FromContext(ctx).Info("pg_dump Job completed", "job", jobName)
	return ctrl.Result{}, false
}

func (r *HankoSnapshotReconciler) createSnapshotJob(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch, jobName string) ctrl.Result {
	job := r.buildPGDumpJob(jobName, snapshot.Namespace, snapshot.Spec.BackupPVC, instance.Spec.Managed.Database.Name)
	if err := controllerutil.SetControllerReference(snapshot, job, r.Scheme); err != nil {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"JobOwnerRefError", err.Error(), "patch status after job owner ref error"})
		return ctrl.Result{}
	}
	if err := r.Create(ctx, job); err != nil {
		r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"JobCreateError", err.Error(), "patch status after job create error"})
		return ctrl.Result{}
	}
	log.FromContext(ctx).Info("created pg_dump Job", "job", jobName)
	r.patchSnapshotWhileWaiting(ctx, snapshot, patch)
	return ctrl.Result{RequeueAfter: requeueOnError}
}

func (r *HankoSnapshotReconciler) patchSnapshotWhileWaiting(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) {
	if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
		log.FromContext(ctx).Error(err, "patch snapshot status while waiting for job")
	}
}

func (r *HankoSnapshotReconciler) completeSnapshot(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) (ctrl.Result, error) {
	now := metav1.Now()
	snapshot.Status.Phase = "Done"
	snapshot.Status.TakenAt = &now
	setCondition(&snapshot.Status.Conditions, "SnapshotReady", metav1.ConditionTrue, "Completed", "snapshot completed successfully")
	if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch HankoSnapshot status to Done: %w", err)
	}
	log.FromContext(ctx).Info("HankoSnapshot completed", "snapshot", snapshot.Name, "configmap", snapshot.Status.ConfigMapRef)
	return ctrl.Result{}, nil
}

// buildPGDumpJob constructs a pg_dump Job that writes to a persistent PVC.
func (r *HankoSnapshotReconciler) buildPGDumpJob(jobName, namespace, backupPVC, dbSecretName string) *batchv1.Job {
	backoffLimit := int32(2)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(70), // postgres uid in postgres:16-alpine
					},
					Containers: []corev1.Container{
						{
							Name:  "pgdump",
							Image: "postgres:16-alpine",
							Command: []string{
								"pg_dump",
								"--format=custom",
								"--no-acl",
								"--no-owner",
								"--file=/backup/keycloak.dump",
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									SecretRef: &corev1.SecretEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{Name: dbSecretName},
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "backup", MountPath: "/backup"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "backup",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: backupPVC,
								},
							},
						},
					},
				},
			},
		},
	}
}

// isJobComplete returns true if the Job has succeeded.
func isJobComplete(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// isJobFailed returns true if the Job has permanently failed.
func isJobFailed(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// SetupWithManager registers the reconciler and declares owned resources.
func (r *HankoSnapshotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoSnapshot{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}
