package controller

import (
	"context"
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

// HankoSnapshotReconciler reconciles HankoSnapshot objects (one-shot).
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankosnapshots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankosnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms;hankoapplications;hankoserviceaccounts;hankoissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create
type HankoSnapshotReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	APIReader      client.Reader
	ImageValidator *imagevalidator.Validator
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
	if err := r.snapshotReader().Get(ctx, req.NamespacedName, &snapshot); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if snapshot.Status.Phase == "Done" || snapshot.Status.Phase == "Failed" || !snapshot.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	patch := snapshotPatch(&snapshot)
	instance, handled, err := r.snapshotInstance(ctx, &snapshot, patch)
	if handled || err != nil {
		return ctrl.Result{}, err
	}
	if reason := validateSnapshotCheckpoint(&snapshot, instance); reason != "" {
		return ctrl.Result{}, r.failSnapshot(ctx, &snapshot, patch, snapshotFailure{"CheckpointRejected", reason, "checkpoint rejected"})
	}
	if snapshot.Status.IntentHash == "" {
		snapshot.Status.Phase = "Running"
		snapshot.Status.StartedGeneration = snapshot.Generation
		snapshot.Status.InstanceUID = string(instance.UID)
		snapshot.Status.IntentHash = snapshotIntentHash(&snapshot)
		if err := r.Status().Patch(ctx, &snapshot, patch); err != nil {
			return ctrl.Result{}, err
		}
	}
	if handled, err := r.ensureSnapshotConfig(ctx, &snapshot, snapshotPatch(&snapshot)); handled || err != nil {
		return ctrl.Result{}, err
	}
	patch = snapshotPatch(&snapshot)
	if result, handled, err := r.reconcileSnapshotData(ctx, &snapshot, instance, patch); handled || err != nil {
		return result, err
	}
	return r.completeSnapshot(ctx, &snapshot, patch)
}

type snapshotFailure struct {
	reason     string
	message    string
	logMessage string
}

func (r *HankoSnapshotReconciler) failSnapshot(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch, failure snapshotFailure) error {
	snapshot.Status.Phase = "Failed"
	iamCondition(&snapshot.Status.Conditions, snapshot.Generation, "SnapshotReady", metav1.ConditionFalse, failure.reason, failure.message)
	if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
		return fmt.Errorf("%s: %w", failure.logMessage, err)
	}
	return nil
}

func (r *HankoSnapshotReconciler) snapshotInstance(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) (*hankoshv1alpha1.HankoKeycloakInstance, bool, error) {
	var instance hankoshv1alpha1.HankoKeycloakInstance
	err := r.snapshotReader().Get(ctx, types.NamespacedName{Name: snapshot.Spec.InstanceRef, Namespace: snapshot.Namespace}, &instance)
	if err == nil {
		return &instance, false, nil
	}
	if !errors.IsNotFound(err) {
		return nil, true, err
	}
	return nil, true, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{
		"InstanceNotFound", "referenced HankoKeycloakInstance no longer exists", "instance not found",
	})
}

func (r *HankoSnapshotReconciler) snapshotPayload(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot) ([]byte, error) {
	// An unlabelled snapshot belongs to the standalone scope, not every tenant
	// in its namespace. Presence of an empty tenant label is also a distinct scope.
	scope := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "hanko.sh/tenant", Operator: metav1.LabelSelectorOpDoesNotExist}}}
	if tenant, present := snapshot.Labels["hanko.sh/tenant"]; present {
		scope = &metav1.LabelSelector{MatchLabels: map[string]string{"hanko.sh/tenant": tenant}}
	}
	selector, err := metav1.LabelSelectorAsSelector(scope)
	if err != nil {
		return nil, fmt.Errorf("SnapshotScopeError: %w", err)
	}
	options := []client.ListOption{client.InNamespace(snapshot.Namespace), client.MatchingLabelsSelector{Selector: selector}}
	var payload snapshotData
	var realms hankoshv1alpha1.HankoRealmList
	if err := r.snapshotReader().List(ctx, &realms, options...); err != nil {
		return nil, fmt.Errorf("ListRealmsError: %w", err)
	}
	payload.Realms = realms.Items
	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.snapshotReader().List(ctx, &applications, options...); err != nil {
		return nil, fmt.Errorf("ListAppsError: %w", err)
	}
	payload.Applications = applications.Items
	var serviceAccounts hankoshv1alpha1.HankoServiceAccountList
	if err := r.snapshotReader().List(ctx, &serviceAccounts, options...); err != nil {
		return nil, fmt.Errorf("ListSAsError: %w", err)
	}
	payload.ServiceAccounts = serviceAccounts.Items
	var issuers hankoshv1alpha1.HankoIssuerList
	if err := r.snapshotReader().List(ctx, &issuers, options...); err != nil {
		return nil, fmt.Errorf("ListIssuersError: %w", err)
	}
	payload.Issuers = issuers.Items
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("SerializeError: %w", err)
	}
	return raw, nil
}

func (r *HankoSnapshotReconciler) reconcileSnapshotData(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch) (ctrl.Result, bool, error) {
	if !snapshot.Spec.IncludeData {
		return ctrl.Result{}, false, nil
	}
	fail := func(f snapshotFailure) (ctrl.Result, bool, error) {
		return ctrl.Result{}, true, r.failSnapshot(ctx, snapshot, patch, f)
	}
	if snapshot.Spec.BackupPVC == "" {
		return fail(snapshotFailure{"BackupPVCMissing", "includeData=true requires backupPVC to be set", "backup PVC missing"})
	}
	if instance.Spec.Mode != "managed" || instance.Spec.Managed == nil || instance.Spec.Managed.Database.Name == "" {
		return fail(snapshotFailure{"ManagedSpecMissing", "includeData=true requires mode=managed with a Database secret", "managed spec missing"})
	}
	if failure := r.validateSnapshotBackup(ctx, snapshot, instance); failure != nil {
		return fail(*failure)
	}
	jobName := "snap-" + snapshot.Name + "-pgdump"
	var job batchv1.Job
	err := r.snapshotReader().Get(ctx, types.NamespacedName{Name: jobName, Namespace: snapshot.Namespace}, &job)
	if errors.IsNotFound(err) {
		if snapshot.Status.DBJobUID != "" {
			return fail(snapshotFailure{"JobContractMismatch", "checkpointed pg_dump Job disappeared; inspect the backup before starting a new snapshot", "job missing"})
		}
		result, err := r.createSnapshotJob(ctx, snapshot, instance, patch, jobName)
		return result, true, err
	}
	if err != nil {
		return ctrl.Result{}, true, err
	}
	if !r.snapshotJobMatches(snapshot, &job) || (snapshot.Status.DBJobUID != "" && snapshot.Status.DBJobUID != string(job.UID)) {
		return fail(snapshotFailure{"JobContractMismatch", "existing pg_dump Job differs from this snapshot's ownership, identity or approved workload contract; inspect it manually", "job contract mismatch"})
	}
	if err := r.ImageValidator.VerifyImage(ctx, imagevalidator.DatabaseBackup, snapshot.Spec.BackupImage); err != nil {
		return fail(snapshotFailure{"UntrustedBackupImage", err.Error(), "backup image verification"})
	}
	snapshot.Status.DBJobRef, snapshot.Status.DBJobUID = jobName, string(job.UID)
	// A contradictory terminal state is never evidence of a successful backup.
	if isJobFailed(&job) {
		return fail(snapshotFailure{"JobFailed", fmt.Sprintf("pg_dump Job %q failed", jobName), "job failed"})
	}
	if !isJobComplete(&job) {
		return ctrl.Result{RequeueAfter: requeueOnError}, true, r.Status().Patch(ctx, snapshot, patch)
	}
	return ctrl.Result{}, false, nil
}

func (r *HankoSnapshotReconciler) createSnapshotJob(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch, jobName string) (ctrl.Result, error) {
	if failure := r.validateSnapshotBackup(ctx, snapshot, instance); failure != nil {
		return ctrl.Result{}, r.failSnapshot(ctx, snapshot, patch, *failure)
	}
	if err := r.ImageValidator.VerifyImage(ctx, imagevalidator.DatabaseBackup, snapshot.Spec.BackupImage); err != nil {
		return ctrl.Result{}, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"UntrustedBackupImage", err.Error(), "backup image verification"})
	}
	job := r.buildPGDumpJob(jobName, snapshot)
	job.Annotations = map[string]string{snapshotIntentAnnotation: snapshot.Status.IntentHash}
	job.Labels = map[string]string{"hanko.sh/tenant": snapshot.Labels["hanko.sh/tenant"]}
	if err := controllerutil.SetControllerReference(snapshot, job, r.Scheme); err != nil {
		return ctrl.Result{}, r.failSnapshot(ctx, snapshot, patch, snapshotFailure{"JobOwnerRefError", err.Error(), "job owner ref error"})
	}
	// A failed acknowledgement can conceal a successful create. Retry by reading
	// the deterministic name, never by declaring this execution failed.
	if err := checkLifecycleAuthority(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Create(ctx, job); err != nil {
		return ctrl.Result{}, err
	}
	snapshot.Status.DBJobRef, snapshot.Status.DBJobUID = job.Name, string(job.UID)
	return ctrl.Result{RequeueAfter: requeueOnError}, r.Status().Patch(ctx, snapshot, patch)
}

// validateSnapshotBackup never includes credential values or an untrusted image
// reference in errors. No Secret is copied into a Job; kubelet projects selected keys.
func (r *HankoSnapshotReconciler) validateSnapshotBackup(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, instance *hankoshv1alpha1.HankoKeycloakInstance) *snapshotFailure {
	if err := r.ImageValidator.ValidateWorkloadImage(imagevalidator.DatabaseBackup, snapshot.Spec.BackupImage); err != nil {
		return &snapshotFailure{"UntrustedBackupImage", err.Error(), "patch status after backup image admission"}
	}
	ref := snapshot.Spec.BackupSecretRef
	if ref == "" || ref == instance.Spec.AdminRef.Name || (instance.Spec.Managed != nil && (ref == instance.Spec.Managed.Database.Name || ref == instance.Spec.Managed.TLSSecretRef)) {
		return &snapshotFailure{"BackupCredentialsInvalid", "backupSecretRef must name a dedicated database backup Secret", "patch status after backup credential validation"}
	}
	var secret corev1.Secret
	if err := r.snapshotReader().Get(ctx, types.NamespacedName{Name: ref, Namespace: snapshot.Namespace}, &secret); err != nil {
		return &snapshotFailure{"BackupCredentialsInvalid", "cannot read the dedicated backup Secret", "patch status after backup credential lookup"}
	}
	for _, key := range []string{"PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD"} {
		if len(secret.Data[key]) == 0 {
			return &snapshotFailure{"BackupCredentialsInvalid", "backup Secret requires nonempty PGHOST, PGDATABASE, PGUSER and PGPASSWORD", "patch status after backup credential validation"}
		}
	}
	return nil
}

// Existing Jobs are not adopted by name. Check the credential-bearing execution
// contract before trusting even a completed Job; legacy mutable Jobs fail closed.
func (r *HankoSnapshotReconciler) snapshotJobMatches(snapshot *hankoshv1alpha1.HankoSnapshot, job *batchv1.Job) bool {
	if !snapshotChildMatches(snapshot, job) {
		return false
	}
	actual := job.Spec.Template.Spec
	expected := r.buildPGDumpJob(job.Name, snapshot).Spec.Template.Spec
	return !actual.HostNetwork && !actual.HostPID && !actual.HostIPC &&
		len(actual.InitContainers) == 0 && len(actual.EphemeralContainers) == 0 &&
		apiequality.Semantic.DeepEqual(actual.Containers, expected.Containers) &&
		apiequality.Semantic.DeepEqual(actual.Volumes, expected.Volumes) &&
		apiequality.Semantic.DeepEqual(actual.SecurityContext, expected.SecurityContext) &&
		apiequality.Semantic.DeepEqual(actual.AutomountServiceAccountToken, expected.AutomountServiceAccountToken) &&
		actual.RestartPolicy == expected.RestartPolicy
}

func (r *HankoSnapshotReconciler) completeSnapshot(ctx context.Context, snapshot *hankoshv1alpha1.HankoSnapshot, patch client.Patch) (ctrl.Result, error) {
	now := metav1.Now()
	snapshot.Status.Phase = "Done"
	snapshot.Status.TakenAt = &now
	iamCondition(&snapshot.Status.Conditions, snapshot.Generation, "SnapshotReady", metav1.ConditionTrue, "Completed", "snapshot completed successfully")
	if err := r.Status().Patch(ctx, snapshot, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch HankoSnapshot status to Done: %w", err)
	}
	log.FromContext(ctx).Info("HankoSnapshot completed", "snapshot", snapshot.Name, "configmap", snapshot.Status.ConfigMapRef)
	return ctrl.Result{}, nil
}

// snapshotDumpPath names a dump file unique to this snapshot so snapshots
// sharing one backup PVC never overwrite each other's archive. The UID digest
// also separates archives when a snapshot is deleted and recreated by name.
func snapshotDumpPath(snapshot *hankoshv1alpha1.HankoSnapshot) string {
	suffix := ""
	if snapshot.UID != "" {
		suffix = "-" + snapshotHash([]byte(snapshot.UID))[:8]
	}
	return "/backup/snap-" + snapshot.Name + suffix + ".dump"
}

// buildPGDumpJob constructs a pg_dump Job that writes to a persistent PVC.
func (r *HankoSnapshotReconciler) buildPGDumpJob(jobName string, snapshot *hankoshv1alpha1.HankoSnapshot) *batchv1.Job {
	backoffLimit := int32(2)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: snapshot.Namespace,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyOnFailure,
					AutomountServiceAccountToken: boolPtr(false),
					EnableServiceLinks:           boolPtr(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   boolPtr(true),
						RunAsUser:      int64Ptr(70),
						RunAsGroup:     int64Ptr(70),
						FSGroup:        int64Ptr(70),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{
						{
							Name:                     "pgdump",
							Image:                    snapshot.Spec.BackupImage,
							ImagePullPolicy:          corev1.PullIfNotPresent,
							TerminationMessagePath:   "/dev/termination-log",
							TerminationMessagePolicy: corev1.TerminationMessageReadFile,
							Command: []string{
								"pg_dump",
								"--format=custom",
								"--no-acl",
								"--no-owner",
								"--file=" + snapshotDumpPath(snapshot),
							},
							Env: snapshotBackupEnv(snapshot.Spec.BackupSecretRef),
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								ReadOnlyRootFilesystem:   boolPtr(true),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "backup", MountPath: "/backup"},
								{Name: "tmp", MountPath: "/tmp"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "backup",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: snapshot.Spec.BackupPVC,
								},
							},
						},
						{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					},
				},
			},
		},
	}
}

func snapshotBackupEnv(secretName string) []corev1.EnvVar {
	keys := []string{"PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPORT", "PGSSLMODE"}
	env := make([]corev1.EnvVar, 0, len(keys))
	for i, key := range keys {
		env = append(env, corev1.EnvVar{Name: key, ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
				Key:                  key, Optional: boolPtr(i >= 4),
			},
		}})
	}
	return env
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
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoSnapshot{}, builder.WithPredicates(generationOrReconcileRequestChanged())).
		Owns(&corev1.ConfigMap{}).
		Owns(&batchv1.Job{}).
		Complete(observeReconciler("HankoSnapshot", &lifecycleApprovalGuard{Client: r.Client, reader: r.APIReader, inner: r, snapshot: true}))
}
