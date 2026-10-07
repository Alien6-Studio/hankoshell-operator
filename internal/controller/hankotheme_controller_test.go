package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func newThemeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add hankoShell scheme: %v", err)
	}
	return scheme
}

func newThemeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newThemeScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&hankoshv1alpha1.HankoTheme{}, &batchv1.Job{}, &appsv1.Deployment{}).
		Build()
}

func testKeycloakDeployment(namespace string) *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: namespace, Generation: 1},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
	}
}

func completeKeycloakRollout(t *testing.T, c client.Client, namespace string) {
	t.Helper()
	var deployment appsv1.Deployment
	key := types.NamespacedName{Name: "keycloak", Namespace: namespace}
	if err := c.Get(context.Background(), key, &deployment); err != nil {
		t.Fatalf("get Keycloak deployment: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.AvailableReplicas = 1
	deployment.Status.UnavailableReplicas = 0
	if err := c.Status().Update(context.Background(), &deployment); err != nil {
		t.Fatalf("complete Keycloak rollout: %v", err)
	}
}

func testTheme() *hankoshv1alpha1.HankoTheme {
	return &hankoshv1alpha1.HankoTheme{
		ObjectMeta: metav1.ObjectMeta{Name: "hanko", Namespace: "default", Generation: 1, UID: types.UID("theme-uid-1")},
		Spec: hankoshv1alpha1.HankoThemeSpec{
			PrimaryColor:    "#112233",
			BackgroundColor: "oklch(0.2 0.01 210)",
			ForegroundColor: "oklch(0.9 0.01 210)",
			FontFamily:      "Inter, sans-serif",
			LogoURL:         "https://assets.example/logo.svg",
			Headline:        "Welcome",
			Subline:         "Sign in to continue",
			BuildImage:      approvedThemeImage,
			KeycloakPVC:     "keycloak-providers",
			JarName:         "hanko-theme.jar",
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "registry-pull"},
			},
		},
	}
}

func envMap(env []corev1.EnvVar) map[string]string {
	out := make(map[string]string, len(env))
	for _, item := range env {
		out[item.Name] = item.Value
	}
	return out
}

func themeCondition(theme *hankoshv1alpha1.HankoTheme, conditionType string) *metav1.Condition {
	for i := range theme.Status.Conditions {
		if theme.Status.Conditions[i].Type == conditionType {
			return &theme.Status.Conditions[i]
		}
	}
	return nil
}

func TestThemeBuildJobMatchesBuilderContract(t *testing.T) {
	theme := testTheme()
	r := &HankoThemeReconciler{KeycloakDeploymentName: "keycloak"}
	job := r.buildJob(theme, "theme-job")

	if len(job.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("containers: got %d, want 1", len(job.Spec.Template.Spec.Containers))
	}
	builder := job.Spec.Template.Spec.Containers[0]
	if len(builder.Command) != 2 || builder.Command[0] != "/bin/sh" || builder.Command[1] != "/build-theme.sh" {
		t.Fatalf("builder command: got %v", builder.Command)
	}
	env := envMap(builder.Env)
	want := map[string]string{
		"THEME_SLUG":             "hanko",
		"THEME_PRIMARY_COLOR":    "#112233",
		"THEME_BACKGROUND_COLOR": "oklch(0.2 0.01 210)",
		"THEME_FOREGROUND_COLOR": "oklch(0.9 0.01 210)",
		"THEME_FONT_FAMILY":      "Inter, sans-serif",
		"THEME_LOGO_URL":         "https://assets.example/logo.svg",
		"THEME_HEADLINE":         "Welcome",
		"THEME_SUBLINE":          "Sign in to continue",
		"THEME_JAR_NAME":         "hanko-theme.jar",
	}
	for key, value := range want {
		if env[key] != value {
			t.Errorf("env %s: got %q, want %q", key, env[key], value)
		}
	}
	if len(builder.VolumeMounts) != 1 || builder.VolumeMounts[0].MountPath != "/output" {
		t.Fatalf("builder volume mounts: got %+v", builder.VolumeMounts)
	}
	if len(job.Spec.Template.Spec.ImagePullSecrets) != 1 || job.Spec.Template.Spec.ImagePullSecrets[0].Name != "registry-pull" {
		t.Fatalf("imagePullSecrets: got %+v", job.Spec.Template.Spec.ImagePullSecrets)
	}
	if job.Spec.Template.Labels["hanko.sh/theme"] != theme.Name {
		t.Fatalf("pod labels do not identify the managed theme: %+v", job.Spec.Template.Labels)
	}
	if job.Spec.Template.Spec.SecurityContext == nil || job.Spec.Template.Spec.SecurityContext.FSGroup == nil || *job.Spec.Template.Spec.SecurityContext.FSGroup != themePVCGroupID {
		t.Fatalf("pod FSGroup: got %+v", job.Spec.Template.Spec.SecurityContext)
	}
	if builder.SecurityContext == nil || builder.SecurityContext.RunAsUser == nil || *builder.SecurityContext.RunAsUser != themeBuildUserID {
		t.Fatalf("builder security context: got %+v", builder.SecurityContext)
	}
	terms := job.Spec.Template.Spec.Affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if len(terms) != 1 || terms[0].TopologyKey != "kubernetes.io/hostname" || terms[0].LabelSelector.MatchLabels["app"] != "keycloak" {
		t.Fatalf("Keycloak pod affinity: got %+v", terms)
	}
}

func TestThemeCleanupJobRemovesOnlyResolvedJar(t *testing.T) {
	theme := testTheme()
	r := &HankoThemeReconciler{KeycloakDeploymentName: "keycloak"}
	job := r.cleanupJob(theme, "cleanup-job", "hanko-theme.jar")
	cleanup := job.Spec.Template.Spec.Containers[0]
	if len(cleanup.Command) != 1 || cleanup.Command[0] != "/bin/rm" {
		t.Fatalf("cleanup command: got %v", cleanup.Command)
	}
	wantArgs := []string{"-f", "--", "/output/hanko-theme.jar"}
	if len(cleanup.Args) != len(wantArgs) {
		t.Fatalf("cleanup args: got %v, want %v", cleanup.Args, wantArgs)
	}
	for i := range wantArgs {
		if cleanup.Args[i] != wantArgs[i] {
			t.Fatalf("cleanup args: got %v, want %v", cleanup.Args, wantArgs)
		}
	}
}

func TestThemeReconcileMissingPVCReportsErrorWithoutJob(t *testing.T) {
	theme := testTheme()
	c := newThemeClient(t, theme)
	r := &HankoThemeReconciler{
		Client:         c,
		Scheme:         newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
		Recorder:       events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}, &got); err != nil {
		t.Fatalf("get theme: %v", err)
	}
	if got.Status.Phase != "Error" {
		t.Errorf("phase: got %q, want Error", got.Status.Phase)
	}
	built := themeCondition(&got, "Built")
	if built == nil || built.Reason != "PVCUnavailable" {
		t.Errorf("Built condition: got %+v, want PVCUnavailable", built)
	}
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("jobs: got %d, want 0", len(jobs.Items))
	}
}

func TestThemeReconcileCreatesBuildJob(t *testing.T) {
	theme := testTheme()
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	c := newThemeClient(t, theme, pvc)
	r := &HankoThemeReconciler{
		Client:         c,
		Scheme:         newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
		Recorder:       events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	jobName := themeBuildJobName(theme, themeSpecHash(theme.Spec))
	var job batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: jobName, Namespace: theme.Namespace}, &job); err != nil {
		t.Fatalf("get build job: %v", err)
	}
	if len(job.OwnerReferences) != 1 || job.OwnerReferences[0].Name != theme.Name {
		t.Errorf("owner references: got %+v", job.OwnerReferences)
	}
	var got hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}, &got); err != nil {
		t.Fatalf("get theme: %v", err)
	}
	if got.Status.Phase != "Building" || got.Status.BuildJob != jobName {
		t.Errorf("status: got phase=%q job=%q", got.Status.Phase, got.Status.BuildJob)
	}
}

func TestThemeSpecChangeStopsStaleBuildBeforeStartingNext(t *testing.T) {
	theme := testTheme()
	theme.Status.Phase = "Building"
	theme.Status.BuildJob = "stale-build"
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	stale := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:      theme.Status.BuildJob,
		Namespace: theme.Namespace,
		Labels:    map[string]string{"hanko.sh/theme": theme.Name},
	}}
	c := newThemeClient(t, theme, pvc, stale)
	r := &HankoThemeReconciler{
		Client:         c,
		Scheme:         newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}
	desiredJob := themeBuildJobName(theme, themeSpecHash(theme.Spec))

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	var next batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: desiredJob, Namespace: theme.Namespace}, &next); !apierrors.IsNotFound(err) {
		t.Fatalf("new build started before stale build stopped: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: desiredJob, Namespace: theme.Namespace}, &next); err != nil {
		t.Fatalf("get replacement build: %v", err)
	}
}

func TestThemeCompletedJobRestartsKeycloakOnlyOnce(t *testing.T) {
	theme := testTheme()
	jobName := themeBuildJobName(theme, themeSpecHash(theme.Spec))
	theme.Status.Phase = "Building"
	theme.Status.BuildJob = jobName
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: jobName, Namespace: theme.Namespace},
		Status:     batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}},
	}
	deployment := testKeycloakDeployment(theme.Namespace)
	c := newThemeClient(t, theme, pvc, job, deployment)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
		Recorder:               events.NewFakeRecorder(10),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	var firstDeployment appsv1.Deployment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "keycloak", Namespace: theme.Namespace}, &firstDeployment); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	restartKey := themeRestartAnnotationKey(theme.Name)
	firstRestart := firstDeployment.Spec.Template.Annotations[restartKey]
	if firstRestart == "" {
		t.Fatal("expected Keycloak restart annotation")
	}
	var installing hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), request.NamespacedName, &installing); err != nil {
		t.Fatalf("get installing theme: %v", err)
	}
	if installing.Status.Phase != "Installing" || installing.Status.ObservedGeneration == installing.Generation {
		t.Fatalf("theme became ready before rollout: phase=%q observed=%d generation=%d", installing.Status.Phase, installing.Status.ObservedGeneration, installing.Generation)
	}

	completeKeycloakRollout(t, c, theme.Namespace)
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	var ready hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), request.NamespacedName, &ready); err != nil {
		t.Fatalf("get ready theme: %v", err)
	}
	if ready.Status.Phase != "Ready" || ready.Status.ObservedGeneration != ready.Generation {
		t.Fatalf("ready status: got phase=%q observed=%d generation=%d", ready.Status.Phase, ready.Status.ObservedGeneration, ready.Generation)
	}
	if ready.Status.InstalledPVC != theme.Spec.KeycloakPVC || ready.Status.InstalledBuildImage != theme.Spec.BuildImage {
		t.Fatalf("installed source: pvc=%q image=%q", ready.Status.InstalledPVC, ready.Status.InstalledBuildImage)
	}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	var secondDeployment appsv1.Deployment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "keycloak", Namespace: theme.Namespace}, &secondDeployment); err != nil {
		t.Fatalf("get deployment after second reconcile: %v", err)
	}
	if got := secondDeployment.Spec.Template.Annotations[restartKey]; got != firstRestart {
		t.Errorf("restart annotation changed on idempotent reconcile: first=%q second=%q", firstRestart, got)
	}
}

func TestThemeBuildRevisionChangesWithGeneration(t *testing.T) {
	theme := testTheme()
	hash := themeSpecHash(theme.Spec)
	first := themeBuildJobName(theme, hash)
	theme.Generation = 2
	second := themeBuildJobName(theme, hash)
	if first == second {
		t.Fatalf("build Job name must change when a previous spec is reapplied: %q", first)
	}
}

func TestThemeRebuildNonceChangesBuildRevision(t *testing.T) {
	theme := testTheme()
	first := themeBuildJobName(theme, themeSpecHash(theme.Spec))
	theme.Spec.RebuildNonce = "retry-2"
	theme.Generation++
	second := themeBuildJobName(theme, themeSpecHash(theme.Spec))
	if first == second {
		t.Fatalf("rebuild nonce did not change Job name: %q", first)
	}
}

func TestThemeRevisionChangesWhenResourceIsRecreated(t *testing.T) {
	firstTheme := testTheme()
	secondTheme := firstTheme.DeepCopy()
	secondTheme.UID = types.UID("theme-uid-2")
	hash := themeSpecHash(firstTheme.Spec)
	first := themeRevision(firstTheme, hash)
	second := themeRevision(secondTheme, hash)
	if first == second {
		t.Fatalf("theme revision must change across delete/recreate: %q", first)
	}
}

func TestThemeCompletedBuildPrunesPreviousJarBeforeRestart(t *testing.T) {
	theme := testTheme()
	theme.Status.Phase = "Building"
	theme.Status.JarPath = keycloakProvidersPath + "legacy-theme.jar"
	revision := themeRevision(theme, themeSpecHash(theme.Spec))
	buildJobName := themeJobName("hanko-theme", theme.Name, revision)
	theme.Status.BuildJob = buildJobName
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	buildJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: buildJobName, Namespace: theme.Namespace},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
		}}},
	}
	deployment := testKeycloakDeployment(theme.Namespace)
	c := newThemeClient(t, theme, pvc, buildJob, deployment)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	pruneJobName := themeJobName("hanko-theme-prune", theme.Name, revision)
	var pruneJob batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: pruneJobName, Namespace: theme.Namespace}, &pruneJob); err != nil {
		t.Fatalf("get prune job: %v", err)
	}
	if got := pruneJob.Spec.Template.Spec.Containers[0].Args; len(got) != 3 || got[2] != "/output/legacy-theme.jar" {
		t.Fatalf("prune args: got %v", got)
	}
	var beforeRestart appsv1.Deployment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "keycloak", Namespace: theme.Namespace}, &beforeRestart); err != nil {
		t.Fatalf("get deployment before prune: %v", err)
	}
	if beforeRestart.Spec.Template.Annotations[themeRestartAnnotationKey(theme.Name)] != "" {
		t.Fatal("Keycloak restarted before the previous provider JAR was removed")
	}

	pruneJob.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if err := c.Status().Update(context.Background(), &pruneJob); err != nil {
		t.Fatalf("complete prune job: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	var installing hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), request.NamespacedName, &installing); err != nil {
		t.Fatalf("get installing theme: %v", err)
	}
	if installing.Status.Phase != "Installing" {
		t.Fatalf("phase before rollout: got %q, want Installing", installing.Status.Phase)
	}
	completeKeycloakRollout(t, c, theme.Namespace)
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	var ready hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), request.NamespacedName, &ready); err != nil {
		t.Fatalf("get ready theme: %v", err)
	}
	if ready.Status.Phase != "Ready" || ready.Status.JarPath != keycloakProvidersPath+theme.Spec.JarName {
		t.Fatalf("ready status: phase=%q jar=%q", ready.Status.Phase, ready.Status.JarPath)
	}
}

func TestThemePVCChangePrunesArtifactFromPreviouslyInstalledClaim(t *testing.T) {
	theme := testTheme()
	theme.Spec.KeycloakPVC = "new-providers"
	theme.Status.Phase = "Building"
	theme.Status.JarPath = keycloakProvidersPath + theme.Spec.JarName
	theme.Status.InstalledPVC = "old-providers"
	theme.Status.InstalledBuildImage = previousThemeImage
	revision := themeRevision(theme, themeSpecHash(theme.Spec))
	buildJobName := themeJobName("hanko-theme", theme.Name, revision)
	theme.Status.BuildJob = buildJobName
	newPVC := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	oldPVC := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Status.InstalledPVC, Namespace: theme.Namespace}}
	buildJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: buildJobName, Namespace: theme.Namespace},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
		}}},
	}
	c := newThemeClient(t, theme, newPVC, oldPVC, buildJob, testKeycloakDeployment(theme.Namespace))
	r := &HankoThemeReconciler{
		Client: c, Scheme: newThemeScheme(t), KeycloakDeploymentName: "keycloak",
		ImageValidator: approvedFixtureValidator(t),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	pruneName := themeJobName("hanko-theme-prune", theme.Name, revision)
	var prune batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: pruneName, Namespace: theme.Namespace}, &prune); err != nil {
		t.Fatalf("get prune job: %v", err)
	}
	claim := prune.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName
	image := prune.Spec.Template.Spec.Containers[0].Image
	if claim != "old-providers" || image != theme.Status.InstalledBuildImage {
		t.Fatalf("prune source: pvc=%q image=%q", claim, image)
	}
}

func TestThemeCleanupJobSurvivesDeletingOwner(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.DeletionTimestamp = &now
	theme.Finalizers = []string{themeFinalizer}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	c := newThemeClient(t, theme, pvc)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	jobName := themeJobName("hanko-theme-cleanup", theme.Name, themeRevision(theme, themeSpecHash(theme.Spec)))
	var job batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: jobName, Namespace: theme.Namespace}, &job); err != nil {
		t.Fatalf("get cleanup job: %v", err)
	}
	if len(job.OwnerReferences) != 0 {
		t.Fatalf("cleanup job must not reference deleting theme: got %+v", job.OwnerReferences)
	}
}

func TestThemeDeletionStopsPriorJobsBeforeCleanup(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.DeletionTimestamp = &now
	theme.Finalizers = []string{themeFinalizer}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	buildJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:      "active-theme-build",
		Namespace: theme.Namespace,
		Labels:    map[string]string{"hanko.sh/theme": theme.Name},
	}}
	c := newThemeClient(t, theme, pvc, buildJob)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	cleanupJobName := themeJobName("hanko-theme-cleanup", theme.Name, themeRevision(theme, themeSpecHash(theme.Spec)))
	var cleanup batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Name: cleanupJobName, Namespace: theme.Namespace}, &cleanup); !apierrors.IsNotFound(err) {
		t.Fatalf("cleanup must wait for prior Jobs to stop, got error %v", err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: cleanupJobName, Namespace: theme.Namespace}, &cleanup); err != nil {
		t.Fatalf("get cleanup job: %v", err)
	}
}

func TestThemeDeletionDoesNotStickWhenPVCIsGone(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.DeletionTimestamp = &now
	theme.Finalizers = []string{themeFinalizer}
	c := newThemeClient(t, theme)
	r := &HankoThemeReconciler{
		Client:         c,
		Scheme:         newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoTheme
	err := c.Get(context.Background(), request.NamespacedName, &got)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get theme: %v", err)
	}
	if err == nil && controllerutil.ContainsFinalizer(&got, themeFinalizer) {
		t.Fatal("cleanup finalizer remained after its PVC disappeared")
	}
}

func TestThemeDeletionDropsLegacyFinalizerForUnbuiltInvalidSpec(t *testing.T) {
	theme := testTheme()
	theme.Spec.BuildImage = "untrusted.example/theme-builder:latest"
	now := metav1.Now()
	theme.DeletionTimestamp = &now
	theme.Finalizers = []string{themeFinalizer}
	c := newThemeClient(t, theme)
	r := &HankoThemeReconciler{
		Client: c, Scheme: newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoTheme
	err := c.Get(context.Background(), request.NamespacedName, &got)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get theme: %v", err)
	}
	if err == nil && controllerutil.ContainsFinalizer(&got, themeFinalizer) {
		t.Fatal("invalid unbuilt theme retained its cleanup finalizer")
	}
}

func TestThemeRestartsDoNotOverwriteOtherThemeTokens(t *testing.T) {
	deployment := testKeycloakDeployment("default")
	c := newThemeClient(t, deployment)
	r := &HankoThemeReconciler{Client: c, KeycloakDeploymentName: "keycloak"}
	ctx := context.Background()

	if ready, err := r.reconcileKeycloakRestart(ctx, "default", "theme-a", "install:a:1"); err != nil || ready {
		t.Fatalf("theme-a first restart = (%v, %v)", ready, err)
	}
	if ready, err := r.reconcileKeycloakRestart(ctx, "default", "theme-b", "install:b:1"); err != nil || ready {
		t.Fatalf("theme-b first restart = (%v, %v)", ready, err)
	}
	var got appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Name: "keycloak", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Template.Annotations[themeRestartAnnotationKey("theme-a")] != "install:a:1" ||
		got.Spec.Template.Annotations[themeRestartAnnotationKey("theme-b")] != "install:b:1" {
		t.Fatalf("restart annotations overwrite each other: %+v", got.Spec.Template.Annotations)
	}

	completeKeycloakRollout(t, c, "default")
	for _, tc := range []struct{ name, token string }{{"theme-a", "install:a:1"}, {"theme-b", "install:b:1"}} {
		ready, err := r.reconcileKeycloakRestart(ctx, "default", tc.name, tc.token)
		if err != nil || !ready {
			t.Fatalf("%s completed restart = (%v, %v)", tc.name, ready, err)
		}
	}
}

func TestThemeCompletedCleanupRemovesFinalizerAndRestartsKeycloak(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.DeletionTimestamp = &now
	theme.Finalizers = []string{themeFinalizer}
	revision := themeRevision(theme, themeSpecHash(theme.Spec))
	jobName := themeJobName("hanko-theme-cleanup", theme.Name, revision)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: theme.Namespace,
			Labels:    map[string]string{"hanko.sh/theme": theme.Name},
		},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
		}}},
	}
	deployment := testKeycloakDeployment(theme.Namespace)
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: theme.Spec.KeycloakPVC, Namespace: theme.Namespace}}
	c := newThemeClient(t, theme, job, deployment, pvc)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
	}

	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var gotDeployment appsv1.Deployment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "keycloak", Namespace: theme.Namespace}, &gotDeployment); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	wantToken := "remove:" + theme.Name + ":" + revision
	if got := gotDeployment.Spec.Template.Annotations[themeRestartAnnotationKey(theme.Name)]; got != wantToken {
		t.Fatalf("restart token: got %q, want %q", got, wantToken)
	}
	var waiting hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), request.NamespacedName, &waiting); err != nil {
		t.Fatalf("get deleting theme: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&waiting, themeFinalizer) {
		t.Fatal("theme finalizer removed before Keycloak rollout completed")
	}

	completeKeycloakRollout(t, c, theme.Namespace)
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}

	var deleted hankoshv1alpha1.HankoTheme
	err := c.Get(context.Background(), request.NamespacedName, &deleted)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get deleted theme: %v", err)
	}
	if err == nil && controllerutil.ContainsFinalizer(&deleted, themeFinalizer) {
		t.Fatalf("theme cleanup finalizer was not removed")
	}
}

func TestThemeDeletionIsBlockedWhileApplicationReferencesIt(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.Finalizers = []string{themeFinalizer}
	theme.DeletionTimestamp = &now
	app := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: theme.Namespace},
		Spec:       hankoshv1alpha1.HankoApplicationSpec{Theme: theme.Name},
	}
	c := newThemeClient(t, theme, app)
	r := &HankoThemeReconciler{
		Client:                 c,
		Scheme:                 newThemeScheme(t),
		KeycloakDeploymentName: "keycloak",
		ImageValidator:         approvedFixtureValidator(t),
		Recorder:               events.NewFakeRecorder(10),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}, &got); err != nil {
		t.Fatalf("get theme: %v", err)
	}
	if !containsString(got.Finalizers, themeFinalizer) {
		t.Fatal("theme cleanup finalizer was removed while still referenced")
	}
	built := themeCondition(&got, "Built")
	if got.Status.Phase != "Error" || built == nil || built.Reason != "ThemeInUse" {
		t.Fatalf("deletion status: phase=%q condition=%+v", got.Status.Phase, built)
	}
}

func TestThemeDeletionIsBlockedWhileRealmReferencesIt(t *testing.T) {
	theme := testTheme()
	now := metav1.Now()
	theme.Finalizers = []string{themeFinalizer}
	theme.DeletionTimestamp = &now
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6", Namespace: theme.Namespace},
		Spec:       hankoshv1alpha1.HankoRealmSpec{LoginTheme: theme.Name},
	}
	c := newThemeClient(t, theme, realm)
	r := &HankoThemeReconciler{
		Client:         c,
		Scheme:         newThemeScheme(t),
		ImageValidator: approvedFixtureValidator(t),
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got hankoshv1alpha1.HankoTheme
	if err := c.Get(context.Background(), types.NamespacedName{Name: theme.Name, Namespace: theme.Namespace}, &got); err != nil {
		t.Fatalf("get theme: %v", err)
	}
	condition := themeCondition(&got, "Built")
	if !containsString(got.Finalizers, themeFinalizer) || condition == nil || condition.Reason != "ThemeInUse" {
		t.Fatalf("deletion was not blocked: finalizers=%v condition=%+v", got.Finalizers, condition)
	}
}

func TestExistingThemeBuildReportsRunningAndFailedJobs(t *testing.T) {
	for _, test := range []struct {
		name       string
		conditions []batchv1.JobCondition
		wantPhase  string
		wantReason string
	}{
		{name: "running", wantPhase: "Building", wantReason: "BuildRunning"},
		{
			name: "failed",
			conditions: []batchv1.JobCondition{{
				Type: batchv1.JobFailed, Status: corev1.ConditionTrue,
			}},
			wantPhase: "Error", wantReason: "JobFailed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			theme := testTheme()
			build := &themeBuildState{jobName: "current-build", jarPath: keycloakProvidersPath + theme.Spec.JarName}
			job := &batchv1.Job{Status: batchv1.JobStatus{Conditions: test.conditions}}
			k8sClient := newThemeClient(t, theme)
			reconciler := &HankoThemeReconciler{Client: k8sClient, Recorder: events.NewFakeRecorder(2)}

			result, err := reconciler.reconcileExistingThemeBuild(context.Background(), theme, job, build)
			if err != nil || result.RequeueAfter <= 0 {
				t.Fatalf("existing %s build result=%v err=%v", test.name, result, err)
			}
			var actual hankoshv1alpha1.HankoTheme
			if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(theme), &actual); err != nil {
				t.Fatal(err)
			}
			condition := themeCondition(&actual, "Built")
			if actual.Status.Phase != test.wantPhase || condition == nil || condition.Reason != test.wantReason {
				t.Fatalf("existing %s build status=%#v", test.name, actual.Status)
			}
		})
	}
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
