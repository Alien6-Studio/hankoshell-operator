package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

const (
	themeFinalizer                      = "hanko.sh/theme-cleanup"
	themeLabel                          = "hanko.sh/theme"
	defaultKeycloakDeploymentName       = "keycloak"
	keycloakProvidersPath               = "/opt/keycloak/providers/"
	themeBuildUserID              int64 = 10001
	themeBuildGroupID             int64 = 10001
	themePVCGroupID               int64 = 1000
)

// HankoThemeReconciler reconciles HankoTheme objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankothemes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankothemes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankothemes/finalizers,verbs=update
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications,verbs=get;list;watch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;patch
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch
type HankoThemeReconciler struct {
	client.Client
	Scheme                 *runtime.Scheme
	KeycloakDeploymentName string
	ImageValidator         *imagevalidator.Validator
	Recorder               events.EventRecorder
	Now                    func() time.Time
}

func (r *HankoThemeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var theme hankoshv1alpha1.HankoTheme
	if err := r.Get(ctx, req.NamespacedName, &theme); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !theme.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &theme)
	}

	build, result, err := r.prepareThemeBuild(ctx, &theme)
	if err != nil || build == nil {
		return result, err
	}
	var job batchv1.Job
	err = r.Get(ctx, types.NamespacedName{Name: build.jobName, Namespace: theme.Namespace}, &job)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}
	if err == nil {
		return r.reconcileExistingThemeBuild(ctx, &theme, &job, build)
	}
	if themeBuildInstalled(&theme, build) {
		return ctrl.Result{RequeueAfter: requeueInterval}, nil
	}
	wait, err := r.stopThemeJobsExcept(ctx, &theme, build.jobName, "stop stale theme Job")
	if err != nil {
		return ctrl.Result{}, err
	}
	if wait {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return r.submitThemeBuild(ctx, &theme, build)
}

type themeBuildState struct {
	jarName  string
	revision string
	jobName  string
	jarPath  string
}

func (r *HankoThemeReconciler) prepareThemeBuild(ctx context.Context, theme *hankoshv1alpha1.HankoTheme) (*themeBuildState, ctrl.Result, error) {
	jarName, err := themeJarName(theme)
	if err != nil {
		result, failErr := r.failTheme(ctx, theme, "InvalidJarName", err)
		return nil, result, failErr
	}
	if err := r.ImageValidator.ValidateWorkloadImage(imagevalidator.ThemeBuilder, theme.Spec.BuildImage); err != nil {
		result, failErr := r.failTheme(ctx, theme, "UntrustedImageRef", err)
		return nil, result, failErr
	}
	var pvc corev1.PersistentVolumeClaim
	if err := r.Get(ctx, types.NamespacedName{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}, &pvc); err != nil {
		if apierrors.IsNotFound(err) {
			cause := fmt.Errorf("keycloak theme PVC %q does not exist in namespace %q", theme.Spec.KeycloakPVC, theme.Namespace)
			result, failErr := r.failTheme(ctx, theme, "PVCUnavailable", cause)
			return nil, result, failErr
		}
		return nil, ctrl.Result{}, fmt.Errorf("get Keycloak theme PVC %q: %w", theme.Spec.KeycloakPVC, err)
	}
	if !controllerutil.ContainsFinalizer(theme, themeFinalizer) {
		controllerutil.AddFinalizer(theme, themeFinalizer)
		if err := r.Update(ctx, theme); err != nil {
			return nil, ctrl.Result{}, fmt.Errorf("add HankoTheme finalizer: %w", err)
		}
	}
	hash := themeSpecHash(theme.Spec)
	return &themeBuildState{
		jarName:  jarName,
		revision: themeRevision(theme, hash),
		jobName:  themeBuildJobName(theme, hash),
		jarPath:  keycloakProvidersPath + jarName,
	}, ctrl.Result{}, nil
}

func themeBuildInstalled(theme *hankoshv1alpha1.HankoTheme, build *themeBuildState) bool {
	return theme.Status.Phase == "Ready" &&
		theme.Status.ObservedGeneration == theme.Generation &&
		theme.Status.BuildJob == build.jobName &&
		theme.Status.JarPath == build.jarPath
}

func (r *HankoThemeReconciler) reconcileExistingThemeBuild(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, job *batchv1.Job, build *themeBuildState) (ctrl.Result, error) {
	if isJobComplete(job) {
		return r.reconcileCompletedThemeBuild(ctx, theme, build)
	}
	if isJobFailed(job) {
		return r.failTheme(ctx, theme, "JobFailed", fmt.Errorf("theme build Job %q failed; inspect its logs", build.jobName))
	}
	if theme.Status.Phase != "Building" || theme.Status.BuildJob != build.jobName {
		patch := client.MergeFrom(theme.DeepCopy())
		theme.Status.Phase = "Building"
		theme.Status.BuildJob = build.jobName
		setCondition(&theme.Status.Conditions, "Built", metav1.ConditionFalse, "BuildRunning", "theme build Job is running")
		if err := r.Status().Patch(ctx, theme, patch); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *HankoThemeReconciler) reconcileCompletedThemeBuild(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, build *themeBuildState) (ctrl.Result, error) {
	if themeBuildInstalled(theme, build) {
		return ctrl.Result{RequeueAfter: requeueInterval}, nil
	}
	if result, handled, err := r.prunePreviousThemeArtifact(ctx, theme, build); err != nil || handled {
		return result, err
	}
	restartToken := fmt.Sprintf("install:%s:%s", theme.Name, build.revision)
	ready, err := r.reconcileKeycloakRestart(ctx, theme.Namespace, theme.Name, restartToken)
	if err != nil {
		return r.failTheme(ctx, theme, "KeycloakRestartFailed", err)
	}
	if !ready {
		return r.markThemeInstalling(ctx, theme, build.jobName)
	}
	return r.markThemeInstalled(ctx, theme, build)
}

func (r *HankoThemeReconciler) prunePreviousThemeArtifact(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, build *themeBuildState) (ctrl.Result, bool, error) {
	oldJarName, err := previousThemeJarName(theme.Status.JarPath, build.jarName)
	if err != nil {
		result, failErr := r.failTheme(ctx, theme, "InvalidInstalledJarPath", err)
		return result, true, failErr
	}
	oldPVC := installedThemePVC(theme)
	if oldJarName == "" && theme.Status.JarPath != "" && oldPVC != "" && oldPVC != theme.Spec.KeycloakPVC {
		oldJarName = build.jarName
	}
	if oldJarName == "" {
		return ctrl.Result{}, false, nil
	}
	ready, err := r.reconcilePruneJob(ctx, theme, oldJarName, oldPVC, installedThemeBuildImage(theme), build.revision)
	if err != nil {
		result, failErr := r.failTheme(ctx, theme, "PreviousJarCleanupFailed", err)
		return result, true, failErr
	}
	if !ready {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, true, nil
	}
	return ctrl.Result{}, false, nil
}

func (r *HankoThemeReconciler) markThemeInstalling(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, jobName string) (ctrl.Result, error) {
	patch := client.MergeFrom(theme.DeepCopy())
	theme.Status.Phase = "Installing"
	theme.Status.BuildJob = jobName
	setCondition(&theme.Status.Conditions, "Built", metav1.ConditionFalse, "KeycloakRestarting",
		"theme JAR built; waiting for the restarted Keycloak deployment to become available")
	if err := r.Status().Patch(ctx, theme, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *HankoThemeReconciler) markThemeInstalled(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, build *themeBuildState) (ctrl.Result, error) {
	now := metav1.NewTime(r.now().UTC())
	patch := client.MergeFrom(theme.DeepCopy())
	theme.Status.Phase = "Ready"
	theme.Status.JarPath = build.jarPath
	theme.Status.BuildJob = build.jobName
	theme.Status.LastBuilt = &now
	theme.Status.LastReconciled = &now
	theme.Status.ObservedGeneration = theme.Generation
	theme.Status.InstalledPVC = theme.Spec.KeycloakPVC
	theme.Status.InstalledBuildImage = theme.Spec.BuildImage
	theme.Status.InstalledImagePullSecrets = append([]corev1.LocalObjectReference(nil), theme.Spec.ImagePullSecrets...)
	setCondition(&theme.Status.Conditions, "Built", metav1.ConditionTrue, "Installed",
		fmt.Sprintf("theme JAR %s installed and Keycloak restarted", build.jarName))
	if err := r.Status().Patch(ctx, theme, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("theme build installed", "theme", theme.Name, "jar", build.jarPath)
	if r.Recorder != nil {
		r.Recorder.Eventf(theme, nil, corev1.EventTypeNormal, "ThemeInstalled", "Reconcile", "%s", "theme JAR installed and Keycloak restarted")
	}
	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

func (r *HankoThemeReconciler) stopThemeJobsExcept(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, keepName, action string) (bool, error) {
	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs, client.InNamespace(theme.Namespace), client.MatchingLabels{themeLabel: theme.Name}); err != nil {
		return false, fmt.Errorf("list theme Jobs before %s: %w", action, err)
	}
	wait := false
	foreground := metav1.DeletePropagationForeground
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if job.Name == keepName {
			continue
		}
		wait = true
		if job.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &foreground}); client.IgnoreNotFound(err) != nil {
				return false, fmt.Errorf("%s %q: %w", action, job.Name, err)
			}
		}
	}
	return wait, nil
}

func (r *HankoThemeReconciler) submitThemeBuild(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, build *themeBuildState) (ctrl.Result, error) {
	if err := r.ImageValidator.VerifyImage(ctx, imagevalidator.ThemeBuilder, theme.Spec.BuildImage); err != nil {
		return r.failTheme(ctx, theme, "UntrustedImageRef", err)
	}
	job := r.buildJob(theme, build.jobName)
	if err := controllerutil.SetControllerReference(theme, job, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Create(ctx, job); err != nil {
		return r.failTheme(ctx, theme, "JobCreateFailed", err)
	}
	now := metav1.NewTime(r.now().UTC())
	patch := client.MergeFrom(theme.DeepCopy())
	theme.Status.Phase = "Building"
	theme.Status.BuildJob = build.jobName
	theme.Status.LastReconciled = &now
	setCondition(&theme.Status.Conditions, "Built", metav1.ConditionFalse, "BuildSubmitted", "theme build Job submitted")
	if err := r.Status().Patch(ctx, theme, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("submitted theme build Job", "theme", theme.Name, "job", build.jobName)
	if r.Recorder != nil {
		r.Recorder.Eventf(theme, nil, corev1.EventTypeNormal, "ThemeBuildSubmitted", "Reconcile", "%s", "theme build Job submitted")
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *HankoThemeReconciler) reconcileDelete(ctx context.Context, theme *hankoshv1alpha1.HankoTheme) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(theme, themeFinalizer) {
		return ctrl.Result{}, nil
	}
	users, err := r.themeUsers(ctx, theme)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(users) > 0 {
		return r.failTheme(ctx, theme, "ThemeInUse", fmt.Errorf("theme is still referenced by: %s", strings.Join(users, ", ")))
	}
	if result, handled, err := r.removeUnusedInvalidTheme(ctx, theme); err != nil || handled {
		return result, err
	}
	jarName, err := installedThemeJarName(theme)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result, handled, err := r.ensureInstalledThemePVC(ctx, theme); err != nil || handled {
		return result, err
	}

	revision := themeRevision(theme, themeSpecHash(theme.Spec))
	jobName := themeJobName("hanko-theme-cleanup", theme.Name, revision)
	wait, err := r.stopThemeJobsExcept(ctx, theme, jobName, "stop theme Job before cleanup")
	if err != nil {
		return ctrl.Result{}, err
	}
	if wait {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if result, handled, err := r.reconcileThemeCleanupJob(ctx, theme, jobName, jarName); err != nil || handled {
		return result, err
	}
	restartToken := fmt.Sprintf("remove:%s:%s", theme.Name, revision)
	ready, err := r.reconcileKeycloakRestart(ctx, theme.Namespace, theme.Name, restartToken)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("restart Keycloak after theme cleanup: %w", err)
	}
	if !ready {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	controllerutil.RemoveFinalizer(theme, themeFinalizer)
	if err := r.Update(ctx, theme); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove HankoTheme finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *HankoThemeReconciler) themeUsers(ctx context.Context, theme *hankoshv1alpha1.HankoTheme) ([]string, error) {
	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(theme.Namespace)); err != nil {
		return nil, fmt.Errorf("list applications using theme %q: %w", theme.Name, err)
	}
	users := make([]string, 0)
	for _, application := range applications.Items {
		if application.Spec.Theme == theme.Name && application.DeletionTimestamp.IsZero() {
			users = append(users, "HankoApplication/"+application.Name)
		}
	}
	var realms hankoshv1alpha1.HankoRealmList
	if err := r.List(ctx, &realms, client.InNamespace(theme.Namespace)); err != nil {
		return nil, fmt.Errorf("list realms using theme %q: %w", theme.Name, err)
	}
	for _, realm := range realms.Items {
		if realm.Spec.LoginTheme == theme.Name && realm.DeletionTimestamp.IsZero() {
			users = append(users, "HankoRealm/"+realm.Name)
		}
	}
	return users, nil
}

func (r *HankoThemeReconciler) removeUnusedInvalidTheme(ctx context.Context, theme *hankoshv1alpha1.HankoTheme) (ctrl.Result, bool, error) {
	if theme.Status.JarPath != "" || theme.Status.BuildJob != "" {
		return ctrl.Result{}, false, nil
	}
	_, jarErr := themeJarName(theme)
	imageErr := r.ImageValidator.ValidateWorkloadImage(imagevalidator.ThemeBuilder, theme.Spec.BuildImage)
	if jarErr == nil && imageErr == nil {
		return ctrl.Result{}, false, nil
	}
	controllerutil.RemoveFinalizer(theme, themeFinalizer)
	if err := r.Update(ctx, theme); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("remove unused HankoTheme finalizer: %w", err)
	}
	return ctrl.Result{}, true, nil
}

func (r *HankoThemeReconciler) ensureInstalledThemePVC(ctx context.Context, theme *hankoshv1alpha1.HankoTheme) (ctrl.Result, bool, error) {
	pvcName := installedThemePVC(theme)
	var pvc corev1.PersistentVolumeClaim
	err := r.Get(ctx, types.NamespacedName{Name: pvcName, Namespace: theme.Namespace}, &pvc)
	if err == nil {
		return ctrl.Result{}, false, nil
	}
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, true, fmt.Errorf("get Keycloak theme PVC %q during deletion: %w", pvcName, err)
	}
	controllerutil.RemoveFinalizer(theme, themeFinalizer)
	if err := r.Update(ctx, theme); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("remove HankoTheme finalizer after PVC removal: %w", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(theme, nil, corev1.EventTypeWarning, "ThemeCleanupSkipped", "Reconcile", "%s", "theme PVC no longer exists; cleanup skipped")
	}
	return ctrl.Result{}, true, nil
}

func (r *HankoThemeReconciler) reconcileThemeCleanupJob(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, jobName, jarName string) (ctrl.Result, bool, error) {
	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: theme.Namespace}, &job)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, true, err
	}
	if err != nil {
		if verifyErr := r.ImageValidator.VerifyImage(ctx, imagevalidator.ThemeBuilder, installedThemeBuildImage(theme)); verifyErr != nil {
			result, failErr := r.failTheme(ctx, theme, "UntrustedImageRef", verifyErr)
			return result, true, failErr
		}
		job = *r.cleanupJob(theme, jobName, jarName)
		// A deleting owner must not own this Job: garbage collection could
		// remove it before it deletes the provider artifact.
		if err := r.Create(ctx, &job); err != nil {
			return ctrl.Result{}, true, fmt.Errorf("create theme cleanup Job: %w", err)
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, true, nil
	}
	if isJobFailed(&job) {
		result, failErr := r.failTheme(ctx, theme, "CleanupFailed", fmt.Errorf("theme cleanup Job %q failed", jobName))
		return result, true, failErr
	}
	if !isJobComplete(&job) {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, true, nil
	}
	return ctrl.Result{}, false, nil
}
func (r *HankoThemeReconciler) failTheme(ctx context.Context, theme *hankoshv1alpha1.HankoTheme, reason string, cause error) (ctrl.Result, error) {
	patch := client.MergeFrom(theme.DeepCopy())
	theme.Status.Phase = "Error"
	setCondition(&theme.Status.Conditions, "Built", metav1.ConditionFalse, reason, cause.Error())
	if err := r.Status().Patch(ctx, theme, patch); err != nil {
		return ctrl.Result{}, err
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(theme, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", cause.Error())
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, nil
}

func (r *HankoThemeReconciler) reconcilePruneJob(
	ctx context.Context,
	theme *hankoshv1alpha1.HankoTheme,
	oldJarName, oldPVC, oldBuildImage, revision string,
) (bool, error) {
	if oldPVC != "" {
		var pvc corev1.PersistentVolumeClaim
		if err := r.Get(ctx, types.NamespacedName{Name: oldPVC, Namespace: theme.Namespace}, &pvc); err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("get previous theme PVC %q: %w", oldPVC, err)
		}
	}
	jobName := themeJobName("hanko-theme-prune", theme.Name, revision)
	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: theme.Namespace}, &job)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	if apierrors.IsNotFound(err) {
		buildImage := oldBuildImage
		if buildImage == "" {
			buildImage = theme.Spec.BuildImage
		}
		if err := r.ImageValidator.VerifyImage(ctx, imagevalidator.ThemeBuilder, buildImage); err != nil {
			return false, err
		}
		job = *r.cleanupJobForStorage(theme, jobName, oldJarName, oldPVC, oldBuildImage, installedThemeImagePullSecrets(theme))
		if err := controllerutil.SetControllerReference(theme, &job, r.Scheme); err != nil {
			return false, err
		}
		if err := r.Create(ctx, &job); err != nil {
			return false, fmt.Errorf("create previous JAR cleanup Job: %w", err)
		}
		return false, nil
	}
	if isJobFailed(&job) {
		return false, fmt.Errorf("previous JAR cleanup Job %q failed", jobName)
	}
	return isJobComplete(&job), nil
}

func (r *HankoThemeReconciler) buildJob(theme *hankoshv1alpha1.HankoTheme, name string) *batchv1.Job {
	jarName, _ := themeJarName(theme)
	env := []corev1.EnvVar{
		{Name: "THEME_SLUG", Value: theme.Name},
		{Name: "THEME_PRIMARY_COLOR", Value: defaultString(theme.Spec.PrimaryColor, "#22d3ee")},
		{Name: "THEME_BACKGROUND_COLOR", Value: defaultString(theme.Spec.BackgroundColor, "oklch(0.16 0.012 210)")},
		{Name: "THEME_FOREGROUND_COLOR", Value: defaultString(theme.Spec.ForegroundColor, "oklch(0.94 0.008 210)")},
		{Name: "THEME_FONT_FAMILY", Value: defaultString(theme.Spec.FontFamily, "Geist, sans-serif")},
		{Name: "THEME_LOGO_URL", Value: theme.Spec.LogoURL},
		{Name: "THEME_HEADLINE", Value: defaultString(theme.Spec.Headline, "Sign in")},
		{Name: "THEME_SUBLINE", Value: theme.Spec.Subline},
		{Name: "THEME_JAR_NAME", Value: jarName},
	}
	return r.themeJob(theme, name, theme.Spec.KeycloakPVC, theme.Spec.ImagePullSecrets, corev1.Container{
		Name:    "builder",
		Image:   theme.Spec.BuildImage,
		Command: []string{"/bin/sh", "/build-theme.sh"},
		Env:     env,
	})
}

func (r *HankoThemeReconciler) cleanupJob(theme *hankoshv1alpha1.HankoTheme, name, jarName string) *batchv1.Job {
	return r.cleanupJobForStorage(
		theme, name, jarName, installedThemePVC(theme), installedThemeBuildImage(theme), installedThemeImagePullSecrets(theme),
	)
}

func (r *HankoThemeReconciler) cleanupJobForStorage(
	theme *hankoshv1alpha1.HankoTheme,
	name, jarName, pvcName, buildImage string,
	imagePullSecrets []corev1.LocalObjectReference,
) *batchv1.Job {
	if pvcName == "" {
		pvcName = theme.Spec.KeycloakPVC
	}
	if buildImage == "" {
		buildImage = theme.Spec.BuildImage
	}
	return r.themeJob(theme, name, pvcName, imagePullSecrets, corev1.Container{
		Name:    "cleanup",
		Image:   buildImage,
		Command: []string{"/bin/rm"},
		Args:    []string{"-f", "--", "/output/" + jarName},
	})
}

func (r *HankoThemeReconciler) themeJob(
	theme *hankoshv1alpha1.HankoTheme,
	name, pvcName string,
	imagePullSecrets []corev1.LocalObjectReference,
	container corev1.Container,
) *batchv1.Job {
	ttl := int32(3600)
	backoff := int32(1)
	deadline := int64(1200)
	fsPolicy := corev1.FSGroupChangeOnRootMismatch
	container.ImagePullPolicy = corev1.PullIfNotPresent
	container.SecurityContext = &corev1.SecurityContext{
		AllowPrivilegeEscalation: boolPtr(false),
		RunAsNonRoot:             boolPtr(true),
		RunAsUser:                int64Ptr(themeBuildUserID),
		RunAsGroup:               int64Ptr(themeBuildGroupID),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	container.VolumeMounts = []corev1.VolumeMount{{Name: "theme-providers", MountPath: "/output"}}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: theme.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "hanko-operator",
				themeLabel:                     theme.Name,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   &deadline,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
					"app.kubernetes.io/managed-by": "hanko-operator",
					themeLabel:                     theme.Name,
				}},
				Spec: corev1.PodSpec{
					RestartPolicy:    corev1.RestartPolicyNever,
					ImagePullSecrets: append([]corev1.LocalObjectReference(nil), imagePullSecrets...),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:        boolPtr(true),
						RunAsUser:           int64Ptr(themeBuildUserID),
						RunAsGroup:          int64Ptr(themeBuildGroupID),
						FSGroup:             int64Ptr(themePVCGroupID),
						FSGroupChangePolicy: &fsPolicy,
						SeccompProfile:      &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Affinity: &corev1.Affinity{PodAffinity: &corev1.PodAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
							LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": r.keycloakDeploymentName()}},
							TopologyKey:   "kubernetes.io/hostname",
						}},
					}},
					Containers: []corev1.Container{container},
					Volumes: []corev1.Volume{{
						Name: "theme-providers",
						VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcName,
						}},
					}},
				},
			},
		},
	}
}

func (r *HankoThemeReconciler) reconcileKeycloakRestart(ctx context.Context, namespace, themeName, token string) (bool, error) {
	deploymentName := r.keycloakDeploymentName()
	annotationKey := themeRestartAnnotationKey(themeName)
	var deploy appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, &deploy); err != nil {
		return false, fmt.Errorf("get Keycloak deployment %q: %w", deploymentName, err)
	}
	if deploy.Spec.Template.Annotations != nil && deploy.Spec.Template.Annotations[annotationKey] == token {
		return deploymentRolloutReady(&deploy), nil
	}
	patch := client.MergeFrom(deploy.DeepCopy())
	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = make(map[string]string)
	}
	// The token identifies the desired installed state. Retrying after a status
	// patch failure therefore produces an empty Deployment patch instead of a
	// second rolling restart.
	deploy.Spec.Template.Annotations[annotationKey] = token
	if err := r.Patch(ctx, &deploy, patch); err != nil {
		return false, err
	}
	return false, nil
}

func deploymentRolloutReady(deploy *appsv1.Deployment) bool {
	desired := int32(1)
	if deploy.Spec.Replicas != nil {
		desired = *deploy.Spec.Replicas
	}
	return deploy.Status.ObservedGeneration >= deploy.Generation &&
		deploy.Status.UpdatedReplicas == desired &&
		deploy.Status.AvailableReplicas == desired &&
		deploy.Status.UnavailableReplicas == 0
}

func themeRestartAnnotationKey(themeName string) string {
	hash := sha256.Sum256([]byte(themeName))
	return "hanko.sh/theme-restart-" + hex.EncodeToString(hash[:])[:12]
}

func (r *HankoThemeReconciler) keycloakDeploymentName() string {
	if r.KeycloakDeploymentName != "" {
		return r.KeycloakDeploymentName
	}
	return defaultKeycloakDeploymentName
}

func (r *HankoThemeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoTheme{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}

func (r *HankoThemeReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func themeJarName(theme *hankoshv1alpha1.HankoTheme) (string, error) {
	name := theme.Spec.JarName
	if name == "" {
		name = theme.Name + "-theme.jar"
	}
	if err := validateThemeJarName(name); err != nil {
		return "", err
	}
	return name, nil
}

func installedThemePVC(theme *hankoshv1alpha1.HankoTheme) string {
	if theme.Status.InstalledPVC != "" {
		return theme.Status.InstalledPVC
	}
	return theme.Spec.KeycloakPVC
}

func installedThemeBuildImage(theme *hankoshv1alpha1.HankoTheme) string {
	if theme.Status.InstalledBuildImage != "" {
		return theme.Status.InstalledBuildImage
	}
	return theme.Spec.BuildImage
}

func installedThemeImagePullSecrets(theme *hankoshv1alpha1.HankoTheme) []corev1.LocalObjectReference {
	if theme.Status.InstalledImagePullSecrets != nil {
		return append([]corev1.LocalObjectReference(nil), theme.Status.InstalledImagePullSecrets...)
	}
	return append([]corev1.LocalObjectReference(nil), theme.Spec.ImagePullSecrets...)
}

func installedThemeJarName(theme *hankoshv1alpha1.HankoTheme) (string, error) {
	if theme.Status.JarPath == "" {
		return themeJarName(theme)
	}
	if !strings.HasPrefix(theme.Status.JarPath, keycloakProvidersPath) {
		return "", fmt.Errorf("installed JAR path %q is outside %s", theme.Status.JarPath, keycloakProvidersPath)
	}
	name := strings.TrimPrefix(theme.Status.JarPath, keycloakProvidersPath)
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("installed JAR path %q does not name a direct provider file", theme.Status.JarPath)
	}
	if err := validateThemeJarName(name); err != nil {
		return "", err
	}
	return name, nil
}

func themeJobName(prefix, themeName, hash string) string {
	suffix := "-" + hash
	base := prefix + "-" + themeName
	maxBase := 63 - len(suffix)
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + suffix
}

func themeBuildJobName(theme *hankoshv1alpha1.HankoTheme, specHash string) string {
	return themeJobName("hanko-theme", theme.Name, themeRevision(theme, specHash))
}

func themeRevision(theme *hankoshv1alpha1.HankoTheme, specHash string) string {
	revision := fmt.Sprintf("%s-%d", specHash[:8], theme.Generation)
	if theme.UID == "" {
		return revision
	}
	uidHash := sha256.Sum256([]byte(theme.UID))
	return fmt.Sprintf("%s-%s", revision, hex.EncodeToString(uidHash[:])[:8])
}

func previousThemeJarName(installedPath, desiredJarName string) (string, error) {
	if installedPath == "" || installedPath == keycloakProvidersPath+desiredJarName {
		return "", nil
	}
	if !strings.HasPrefix(installedPath, keycloakProvidersPath) {
		return "", fmt.Errorf("installed JAR path %q is outside %s", installedPath, keycloakProvidersPath)
	}
	name := strings.TrimPrefix(installedPath, keycloakProvidersPath)
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("installed JAR path %q does not name a direct provider file", installedPath)
	}
	if err := validateThemeJarName(name); err != nil {
		return "", err
	}
	return name, nil
}

func themeSpecHash(spec hankoshv1alpha1.HankoThemeSpec) string {
	b, _ := json.Marshal(spec)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func validateThemeJarName(name string) error {
	if !strings.HasSuffix(name, ".jar") || len(name) > 255 {
		return fmt.Errorf("jarName %q must be a .jar filename of at most 255 characters", name)
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return fmt.Errorf("jarName %q contains an invalid character", name)
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func boolPtr(value bool) *bool    { return &value }
func int64Ptr(value int64) *int64 { return &value }
