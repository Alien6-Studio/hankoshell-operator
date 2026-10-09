package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func controllerTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for name, add := range map[string]func(*runtime.Scheme) error{
		"apps": appsv1.AddToScheme, "batch": batchv1.AddToScheme, "core": corev1.AddToScheme,
		"networking": networkingv1.AddToScheme, "policy": policyv1.AddToScheme,
		"hanko": hankoshv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("add %s types to scheme: %v", name, err)
		}
	}
	return scheme
}

func controllerTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	for _, object := range objects {
		_, app := object.(*hankoshv1alpha1.HankoApplication)
		_, account := object.(*hankoshv1alpha1.HankoServiceAccount)
		if (app || account) && object.GetUID() == "" {
			object.SetUID(types.UID("fixture-" + object.GetNamespace() + "-" + object.GetName()))
		}
	}
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(
			&hankoshv1alpha1.HankoApplication{},
			&hankoshv1alpha1.HankoImport{},
			&hankoshv1alpha1.HankoSnapshot{},
			&hankoshv1alpha1.HankoOperation{},
			&hankoshv1alpha1.HankoKeycloakInstance{},
			&hankoshv1alpha1.HankoRealm{},
			&hankoshv1alpha1.HankoServiceAccount{},
			&hankoshv1alpha1.HankoTenant{},
		).
		WithObjects(objects...).Build()
}

func managedTestInstance(namespace, name string) *hankoshv1alpha1.HankoKeycloakInstance {
	replicas := int32(2)
	return &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			Mode:     "managed",
			AdminRef: corev1.LocalObjectReference{Name: "admin"},
			Managed: &hankoshv1alpha1.ManagedKeycloakSpec{
				TLSSecretRef: "serving-tls",
				Image:        approvedKeycloakImage, Replicas: &replicas,
				Database: corev1.LocalObjectReference{Name: "database"}, ThemePVC: "themes",
			},
		},
	}
}

func TestSnapshotReconcileConfigOnly(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	snapshot := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: instance.Name},
	}
	k8sClient := controllerTestClient(scheme, instance, snapshot)
	reconciler := &HankoSnapshotReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: snapshot.Name, Namespace: snapshot.Namespace}}); err != nil {
		t.Fatalf("reconcile config-only snapshot: %v", err)
	}
	var actual hankoshv1alpha1.HankoSnapshot
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(snapshot), &actual); err != nil {
		t.Fatalf("get reconciled snapshot: %v", err)
	}
	if actual.Status.Phase != "Done" || actual.Status.ConfigMapRef != "snap-config-config" {
		t.Fatalf("unexpected snapshot status: %#v", actual.Status)
	}
	var configMap corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: actual.Status.ConfigMapRef, Namespace: snapshot.Namespace}, &configMap); err != nil {
		t.Fatalf("get snapshot config map: %v", err)
	}
	if configMap.Data["snapshot.json"] == "" {
		t.Fatal("snapshot config map must contain serialized configuration")
	}
}

func TestSnapshotReconcileCreatesHardenedDataJob(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	snapshot := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoSnapshotSpec{
			InstanceRef: instance.Name, IncludeData: true, BackupPVC: "backups",
			BackupImage: approvedBackupImage, BackupSecretRef: "backup-credentials",
		},
	}
	k8sClient := controllerTestClient(scheme, instance, snapshot, snapshotBackupSecret(snapshot))
	reconciler := &HankoSnapshotReconciler{Client: k8sClient, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)})
	if err != nil {
		t.Fatalf("reconcile data snapshot: %v", err)
	}
	if result.RequeueAfter != requeueOnError {
		t.Fatalf("unexpected job requeue: %s", result.RequeueAfter)
	}
	var job batchv1.Job
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: "snap-data-pgdump", Namespace: snapshot.Namespace}, &job); err != nil {
		t.Fatalf("get pg_dump job: %v", err)
	}
	container := job.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("pg_dump job must forbid privilege escalation")
	}
	if job.Spec.Template.Spec.SecurityContext == nil || job.Spec.Template.Spec.SecurityContext.RunAsNonRoot == nil || !*job.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
		t.Fatal("pg_dump job must run as non-root")
	}
}

func TestSnapshotReconcileFailsClosedWithoutInstance(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	snapshot := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "test"},
		Spec:       hankoshv1alpha1.HankoSnapshotSpec{InstanceRef: "absent"},
	}
	k8sClient := controllerTestClient(scheme, snapshot)
	reconciler := &HankoSnapshotReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(snapshot)}); err != nil {
		t.Fatalf("missing instance should be reported in status: %v", err)
	}
	var actual hankoshv1alpha1.HankoSnapshot
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(snapshot), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Status.Phase != "Failed" {
		t.Fatalf("expected failed snapshot, got %q", actual.Status.Phase)
	}
}

func TestSnapshotDataJobTerminalStatePrecedence(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	for _, testCase := range []struct {
		name          string
		conditions    []batchv1.JobCondition
		handled       bool
		expectedPhase string
	}{
		{name: "pending", handled: true},
		{name: "failed", conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}, handled: true, expectedPhase: "Failed"},
		{name: "complete", conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}},
		{name: "complete wins over stale failure", conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}, {Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot := &hankoshv1alpha1.HankoSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "terminal", Namespace: "test"},
				Spec: hankoshv1alpha1.HankoSnapshotSpec{
					InstanceRef: instance.Name, IncludeData: true, BackupPVC: "backups",
					BackupImage: approvedBackupImage, BackupSecretRef: "backup-credentials",
				},
			}
			reconciler := &HankoSnapshotReconciler{Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
			job := snapshotOwnedJob(t, reconciler, snapshot)
			job.Status.Conditions = testCase.conditions
			k8sClient := controllerTestClient(scheme, snapshot, job, snapshotBackupSecret(snapshot))
			reconciler.Client = k8sClient
			result, handled := reconciler.reconcileSnapshotData(ctx, snapshot, instance, client.MergeFrom(snapshot.DeepCopy()))
			if handled != testCase.handled {
				t.Fatalf("handled=%t, want %t", handled, testCase.handled)
			}
			if testCase.handled && testCase.expectedPhase != "Failed" && result.RequeueAfter != requeueOnError {
				t.Fatalf("pending result=%v", result)
			}
			if testCase.expectedPhase != "" && snapshot.Status.Phase != testCase.expectedPhase {
				t.Fatalf("snapshot phase=%q, want %q", snapshot.Status.Phase, testCase.expectedPhase)
			}
		})
	}
}

func TestOperationReconcileLifecycleBookends(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	t.Run("dry run", func(t *testing.T) {
		operation := &hankoshv1alpha1.HankoOperation{
			ObjectMeta: metav1.ObjectMeta{Name: "dry", Namespace: "test"},
			Spec:       hankoshv1alpha1.HankoOperationSpec{Type: hankoshv1alpha1.OperationUpgrade, DryRun: true},
		}
		k8sClient := controllerTestClient(scheme, operation)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil {
			t.Fatal(err)
		}
		var actual hankoshv1alpha1.HankoOperation
		_ = k8sClient.Get(ctx, client.ObjectKeyFromObject(operation), &actual)
		if actual.Status.Phase != "Done" || len(actual.Status.Steps) != 4 {
			t.Fatalf("unexpected dry-run status: %#v", actual.Status)
		}
	})
	t.Run("initializes steps", func(t *testing.T) {
		operation := &hankoshv1alpha1.HankoOperation{
			ObjectMeta: metav1.ObjectMeta{Name: "init", Namespace: "test"},
			Spec:       hankoshv1alpha1.HankoOperationSpec{Type: hankoshv1alpha1.OperationClone},
		}
		k8sClient := controllerTestClient(scheme, operation)
		reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)})
		if err != nil || result.RequeueAfter != requeueOnError {
			t.Fatalf("initialize operation: result=%v err=%v", result, err)
		}
	})
}

func TestOperationStepHandlers(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "source")
	instance.Status.Phase = "Ready"
	snapshot := &hankoshv1alpha1.HankoSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "op-work-snap", Namespace: "test"},
		Status:     hankoshv1alpha1.HankoSnapshotStatus{Phase: "Done"},
	}
	importOperation := &hankoshv1alpha1.HankoImport{
		ObjectMeta: metav1.ObjectMeta{Name: "op-work-import", Namespace: "test"},
		Status:     hankoshv1alpha1.HankoImportStatus{Phase: "Done"},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 2},
	}
	k8sClient := controllerTestClient(scheme, instance, snapshot, importOperation, deployment)
	reconciler := &HankoOperationReconciler{Client: k8sClient, Scheme: scheme}
	now := metav1.Now()
	operation := &hankoshv1alpha1.HankoOperation{
		ObjectMeta: metav1.ObjectMeta{Name: "work", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoOperationSpec{
			InstanceRef: instance.Name,
			Upgrade:     &hankoshv1alpha1.UpgradeSpec{ToImage: instance.Spec.Managed.Image},
			DBSwitch:    &hankoshv1alpha1.DBSwitchSpec{NewDatabaseSecretRef: "database-v2"},
			Clone:       &hankoshv1alpha1.CloneSpec{TargetName: "clone"},
		},
	}

	steps := []string{"Snapshot", "UpdateImage", "UpdateDatabase", "CreateTarget", "ImportConfig", "WaitRollout", "Validate"}
	for _, name := range steps {
		t.Run(name, func(t *testing.T) {
			step := &hankoshv1alpha1.OperationStep{Name: name, Status: "Pending"}
			if _, _, err := reconciler.advanceStep(ctx, operation, instance, step, &now); err != nil {
				t.Fatalf("advance %s: %v", name, err)
			}
			if step.Status == "Pending" {
				t.Fatalf("step %s did not advance", name)
			}
		})
	}
}

func TestManagedInstanceInfrastructureIsHardened(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	k8sClient := controllerTestClient(scheme, append([]client.Object{instance}, managedTestSecrets(t, instance)...)...)
	reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme, ImageValidator: approvedFixtureValidator(t)}
	patch := client.MergeFrom(instance.DeepCopy())
	if _, handled, err := reconciler.reconcileManagedInstance(ctx, instance, patch); err != nil || handled {
		t.Fatalf("reconcile managed instance: handled=%v err=%v", handled, err)
	}
	if err := reconciler.ensureManagedInstancePolicies(ctx, instance); err != nil {
		t.Fatalf("ensure managed policies: %v", err)
	}

	var deployment appsv1.Deployment
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, &deployment); err != nil {
		t.Fatalf("get managed deployment: %v", err)
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("managed Keycloak must use a read-only root filesystem")
	}
	if container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("managed Keycloak must forbid privilege escalation")
	}
	var service corev1.Service
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, &service); err != nil {
		t.Fatalf("get managed service: %v", err)
	}
	if service.Labels["hanko.sh/managed"] != "true" || service.Annotations["hanko.sh/kind"] != "keycloak" {
		t.Fatalf("managed service missing autodiscover metadata: labels=%v annotations=%v", service.Labels, service.Annotations)
	}
	var networkPolicy networkingv1.NetworkPolicy
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: instance.Name + "-isolation", Namespace: instance.Namespace}, &networkPolicy); err != nil {
		t.Fatalf("get network policy: %v", err)
	}
	var disruptionBudget policyv1.PodDisruptionBudget
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, &disruptionBudget); err != nil {
		t.Fatalf("get disruption budget: %v", err)
	}
}

func TestManagedServiceAutodiscoverMetadataIsReconciled(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := managedTestInstance("test", "keycloak")
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "stale"},
			Ports:    []corev1.ServicePort{{Name: "legacy", Port: 80}},
		},
	}
	k8sClient := controllerTestClient(scheme, append([]client.Object{instance, service}, managedTestSecrets(t, instance)...)...)
	reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}

	if err := reconciler.ensureService(ctx, instance); err != nil {
		t.Fatalf("ensure service: %v", err)
	}
	var actual corev1.Service
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &actual); err != nil {
		t.Fatalf("get service: %v", err)
	}
	if actual.Labels["hanko.sh/managed"] != "true" || actual.Annotations["hanko.sh/kind"] != "keycloak" {
		t.Fatalf("autodiscover metadata not reconciled: labels=%v annotations=%v", actual.Labels, actual.Annotations)
	}
	if actual.Annotations["hanko.sh/endpoint-template"] != "https://localhost:8443" {
		t.Fatal("managed discovery lost the verified endpoint")
	}
	if actual.Spec.Selector["app"] != instance.Name || len(actual.Spec.Ports) != 1 || actual.Spec.Ports[0].Port != 8443 {
		t.Fatalf("managed service routing not reconciled: %#v", actual.Spec)
	}
}

func TestAdoptedServiceAutodiscoverMetadataPreservesRouting(t *testing.T) {
	ctx := context.Background()
	scheme := controllerTestScheme(t)
	instance := &hankoshv1alpha1.HankoKeycloakInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "test"},
		Spec: hankoshv1alpha1.HankoKeycloakInstanceSpec{
			Mode: "adopted",
			Adopted: &hankoshv1alpha1.AdoptedKeycloakSpec{
				DeploymentRef:    "external-keycloak",
				ServiceRef:       "external-keycloak",
				PublishDiscovery: true,
			},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "external-keycloak", Namespace: "test"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": "external-keycloak"},
			Ports:    []corev1.ServicePort{{Name: "https", Port: 8443}},
		},
	}
	k8sClient := controllerTestClient(scheme, instance, service)
	reconciler := &HankoKeycloakInstanceReconciler{Client: k8sClient, Scheme: scheme}

	if err := reconciler.labelAdoptedService(ctx, instance); err != nil {
		t.Fatalf("label adopted service: %v", err)
	}
	if err := reconciler.labelAdoptedService(ctx, instance); err != nil {
		t.Fatalf("idempotent adopted service labeling: %v", err)
	}
	var actual corev1.Service
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &actual); err != nil {
		t.Fatalf("get adopted service: %v", err)
	}
	if actual.Labels["hanko.sh/managed"] != "true" || actual.Annotations["hanko.sh/kind"] != "keycloak" {
		t.Fatalf("adopted service missing autodiscover metadata: labels=%v annotations=%v", actual.Labels, actual.Annotations)
	}
	if actual.Spec.Selector["app.kubernetes.io/name"] != "external-keycloak" || len(actual.Spec.Ports) != 1 || actual.Spec.Ports[0].Port != 8443 {
		t.Fatalf("adopted service routing was modified: %#v", actual.Spec)
	}

	instance.Spec.Adopted.ServiceRef = "missing"
	if err := reconciler.labelAdoptedService(ctx, instance); err == nil {
		t.Fatal("expected missing adopted service to fail")
	}
}
