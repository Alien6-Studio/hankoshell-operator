package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"maps"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// Autodiscover labels/annotations let hanko-api's k8s-autodiscover worker project a
// Keycloak Service into the managed_services catalog automatically, so operator-managed
// (and adopted) Keycloak instances show up in the dashboard's Backend IAM list without a
// manual registration step. Contract: packages/api/internal/managed/autodiscover.
var (
	autodiscoverLabels = map[string]string{
		"hanko.sh/managed": "true",
	}
	autodiscoverAnnotations = map[string]string{
		"hanko.sh/kind": "keycloak",
	}
)

// HankoKeycloakInstanceReconciler reconciles HankoKeycloakInstance objects.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
type HankoKeycloakInstanceReconciler struct {
	client.Client
	Scheme                  *runtime.Scheme
	ImageValidator          *imagevalidator.Validator
	Recorder                events.EventRecorder
	CredentialRotationAudit CredentialRotationAuditor
	ServiceAccountMaxAge    time.Duration
	RequireHTTPS            bool
	Now                     func() time.Time
}

func (r *HankoKeycloakInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var instance hankoshv1alpha1.HankoKeycloakInstance
	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(instance.DeepCopy())
	kc, err := r.buildKCClient(ctx, &instance)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to build Keycloak client from AdminRef")
		r.setInstanceFailure(ctx, &instance, patch, "Error", "SecretError", err.Error(), "patch status after admin secret error")
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}
	if result, handled, err := r.reconcileInstanceMode(ctx, &instance, patch); err != nil || handled {
		return result, err
	}
	if result, handled, err := r.reconcileServiceAccountCredential(ctx, &instance, kc, patch); err != nil || handled {
		return result, err
	}

	instance.Status.Phase = "Probing"
	if err := r.Status().Patch(ctx, &instance, patch); err != nil {
		log.FromContext(ctx).Error(err, "patch status to Probing")
	}
	patch = client.MergeFrom(instance.DeepCopy())
	version, realms, handled := r.probeKeycloakInstance(ctx, &instance, kc, patch)
	if handled {
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}
	setCondition(&instance.Status.Conditions, "AdminAPIReachable", metav1.ConditionTrue, "ProbeSucceeded", "Keycloak Admin API is reachable")
	if err := r.hardenKeycloakInstance(ctx, &instance, kc); err != nil {
		instance.Status.Phase = "Degraded"
		if patchErr := r.Status().Patch(ctx, &instance, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: requeueOnError}, nil
	}
	return r.completeKeycloakInstance(ctx, &instance, kc, patch, version, len(realms))
}

func (r *HankoKeycloakInstanceReconciler) setInstanceFailure(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch, phase, reason, message, logMessage string) {
	instance.Status.Phase = phase
	setCondition(&instance.Status.Conditions, "AdminAPIReachable", metav1.ConditionFalse, reason, message)
	if err := r.Status().Patch(ctx, instance, patch); err != nil {
		log.FromContext(ctx).Error(err, logMessage)
	}
}

func (r *HankoKeycloakInstanceReconciler) reconcileInstanceMode(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch) (ctrl.Result, bool, error) {
	switch instance.Spec.Mode {
	case "managed":
		return r.reconcileManagedInstance(ctx, instance, patch)
	case "adopted":
		return r.reconcileAdoptedInstance(ctx, instance, patch)
	default:
		return ctrl.Result{}, false, nil
	}
}

func (r *HankoKeycloakInstanceReconciler) reconcileManagedInstance(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch) (ctrl.Result, bool, error) {
	if _, err := r.managedServerTransport(ctx, instance); err != nil {
		setCondition(&instance.Status.Conditions, "ManagedTransportConfigured", metav1.ConditionFalse, "TransportError", err.Error())
		r.setInstanceFailure(ctx, instance, patch, "Error", "TransportError", err.Error(), "patch status after managed transport error")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	setCondition(&instance.Status.Conditions, "ManagedTransportConfigured", metav1.ConditionTrue, "Configured", "Managed listener and serving certificate match the AdminRef endpoint")
	// Install isolation before creating or updating pods. A failed policy write
	// must never be followed by a rollout or a Ready status.
	if err := r.ensureManagedInstancePolicies(ctx, instance); err != nil {
		setCondition(&instance.Status.Conditions, "InfrastructureProtected", metav1.ConditionFalse, "PolicyError", err.Error())
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "PolicyError", err.Error(), "patch status after infrastructure policy error")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	setCondition(&instance.Status.Conditions, "InfrastructureProtected", metav1.ConditionTrue, "PoliciesApplied", "NetworkPolicy and replica-appropriate disruption protection applied")
	if err := r.ensureDeployment(ctx, instance); err != nil {
		if stderrors.Is(err, imagevalidator.ErrVerificationDenied) {
			r.setInstanceFailure(ctx, instance, patch, "Error", "UntrustedImageRef", err.Error(), "patch status after image verification failure")
			return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
		}
		log.FromContext(ctx).Error(err, "failed to ensure Keycloak Deployment")
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "DeploymentError", err.Error(), "patch status after deployment error")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	if err := r.ensureService(ctx, instance); err != nil {
		log.FromContext(ctx).Error(err, "failed to ensure Keycloak Service")
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "ServiceError", err.Error(), "patch status after service error")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	return ctrl.Result{}, false, nil
}

func (r *HankoKeycloakInstanceReconciler) reconcileAdoptedInstance(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, patch client.Patch) (ctrl.Result, bool, error) {
	if instance.Spec.Adopted == nil {
		r.setInstanceFailure(ctx, instance, patch, "Error", "MissingAdoptedSpec", "mode=adopted but spec.adopted is nil", "patch status after missing adopted spec")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	var deployment appsv1.Deployment
	name := instance.Spec.Adopted.DeploymentRef
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: instance.Namespace}, &deployment)
	if errors.IsNotFound(err) {
		message := fmt.Sprintf("adopted deployment %q not found", name)
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "DeploymentNotFound", message, "patch status after adopted deployment not found")
		return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, true, fmt.Errorf("get adopted deployment %q: %w", name, err)
	}
	if instance.Spec.Adopted.PublishDiscovery {
		if instance.Spec.Adopted.ServiceRef == "" {
			r.setInstanceFailure(ctx, instance, patch, "Error", "MissingDiscoveryService", "publishDiscovery requires spec.adopted.serviceRef", "patch status after missing discovery Service")
			return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
		}
		if err := r.labelAdoptedService(ctx, instance); err != nil {
			log.FromContext(ctx).Error(err, "failed to label adopted Keycloak Service for autodiscover")
			r.setInstanceFailure(ctx, instance, patch, "Degraded", "DiscoveryError", err.Error(), "patch status after discovery error")
			return ctrl.Result{RequeueAfter: requeueOnError}, true, nil
		}
	}
	return ctrl.Result{}, false, nil
}

// labelAdoptedService applies the autodiscover labels/annotations to an existing,
// admin-owned Service referenced by spec.adopted.serviceRef, without touching its
// selector or ports — unlike ensureService, the operator does not own this Service.
func (r *HankoKeycloakInstanceReconciler) labelAdoptedService(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance) error {
	if instance.Spec.Adopted == nil || !instance.Spec.Adopted.PublishDiscovery {
		return nil
	}
	var svc corev1.Service
	name := instance.Spec.Adopted.ServiceRef
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: instance.Namespace}, &svc); err != nil {
		return fmt.Errorf("get adopted Service %q: %w", name, err)
	}
	if svc.Labels["hanko.sh/managed"] == "true" && svc.Annotations["hanko.sh/kind"] == "keycloak" {
		return nil
	}
	patchBase := client.MergeFrom(svc.DeepCopy())
	if svc.Labels == nil {
		svc.Labels = map[string]string{}
	}
	if svc.Annotations == nil {
		svc.Annotations = map[string]string{}
	}
	maps.Copy(svc.Labels, autodiscoverLabels)
	maps.Copy(svc.Annotations, autodiscoverAnnotations)
	return r.Patch(ctx, &svc, patchBase)
}

func (r *HankoKeycloakInstanceReconciler) probeKeycloakInstance(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, kc *keycloak.Client, patch client.Patch) (string, []keycloak.Realm, bool) {
	version, err := kc.ServerVersion(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "Keycloak Admin API probe failed (ServerVersion)")
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "ProbeError", err.Error(), "patch status after probe error")
		return "", nil, true
	}
	realms, err := kc.ListRealms(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "Keycloak Admin API probe failed (ListRealms)")
		r.setInstanceFailure(ctx, instance, patch, "Degraded", "ProbeError", err.Error(), "patch status after list realms error")
		return "", nil, true
	}
	return version, realms, false
}

func (r *HankoKeycloakInstanceReconciler) hardenKeycloakInstance(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, kc *keycloak.Client) error {
	if !instance.Spec.HardenMasterRealm {
		setCondition(&instance.Status.Conditions, "MasterRealmHardened", metav1.ConditionFalse, "NotRequested", "Master realm hardening is administrator-managed")
		return nil
	}
	if err := kc.HardenMasterRealm(ctx); err != nil {
		log.FromContext(ctx).Error(err, "failed to harden master realm")
		setCondition(&instance.Status.Conditions, "MasterRealmHardened", metav1.ConditionFalse, "HardenFailed", err.Error())
		return err
	}
	setCondition(&instance.Status.Conditions, "MasterRealmHardened", metav1.ConditionTrue, "Hardened", "master realm security baseline applied")
	return nil
}

func (r *HankoKeycloakInstanceReconciler) ensureManagedInstancePolicies(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance) error {
	if instance.Spec.Mode != "managed" {
		return nil
	}
	if err := r.ensureNetworkPolicy(ctx, instance); err != nil {
		return err
	}
	return r.ensurePDB(ctx, instance)
}

func (r *HankoKeycloakInstanceReconciler) completeKeycloakInstance(ctx context.Context, instance *hankoshv1alpha1.HankoKeycloakInstance, kc *keycloak.Client, patch client.Patch, version string, realmCount int) (ctrl.Result, error) {
	now := metav1.Now()
	instance.Status.Phase = "Ready"
	instance.Status.KeycloakVersion = version
	instance.Status.AdminAPIURL = kc.BaseURL()
	instance.Status.RealmCount = realmCount
	instance.Status.LastProbed = &now
	instance.Status.LastReconciled = &now
	setCondition(&instance.Status.Conditions, "AdminAPIReachable", metav1.ConditionTrue, "ProbeSucceeded", "Keycloak Admin API is reachable")
	if err := r.Status().Patch(ctx, instance, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch HankoKeycloakInstance status: %w", err)
	}
	log.FromContext(ctx).Info("reconciled HankoKeycloakInstance", "mode", instance.Spec.Mode, "version", version, "realms", realmCount)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

// buildKCClient reads the AdminRef Secret and constructs a keycloak.Client.
func (r *HankoKeycloakInstanceReconciler) buildKCClient(ctx context.Context, ki *hankoshv1alpha1.HankoKeycloakInstance) (*keycloak.Client, error) {
	return buildKCClientForInstance(ctx, r.Client, ki, r.RequireHTTPS)
}

// ensureDeployment creates or updates the Keycloak Deployment for mode=managed.
func (r *HankoKeycloakInstanceReconciler) ensureDeployment(ctx context.Context, ki *hankoshv1alpha1.HankoKeycloakInstance) error {
	log := log.FromContext(ctx)

	managed := ki.Spec.Managed
	if managed == nil {
		return fmt.Errorf("mode=managed but spec.managed is nil")
	}
	if err := r.ImageValidator.VerifyImage(ctx, imagevalidator.Keycloak, managed.Image); err != nil {
		return err
	}
	transport, err := r.managedServerTransport(ctx, ki)
	if err != nil {
		return err
	}

	replicas := int32(1)
	if managed.Replicas != nil {
		replicas = *managed.Replicas
	}

	falseVal := false
	trueVal := true
	runAsUser := int64(1000)

	container := corev1.Container{
		Name:  "keycloak",
		Image: managed.Image,
		Args:  append([]string{"start", "--optimized"}, transport.args...),
		EnvFrom: []corev1.EnvFromSource{
			{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: ki.Spec.AdminRef,
				},
			},
			{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: managed.Database,
				},
			},
		},
		Ports: []corev1.ContainerPort{
			{Name: transport.name, ContainerPort: transport.port, Protocol: corev1.ProtocolTCP},
			{Name: "management", ContainerPort: 9000, Protocol: corev1.ProtocolTCP},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/health/ready",
					Port: intstr.FromInt32(9000),
				},
			},
			InitialDelaySeconds: 30,
			PeriodSeconds:       10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/health/live",
					Port: intstr.FromInt32(9000),
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       20,
		},
		Resources: managed.Resources,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &falseVal,
			ReadOnlyRootFilesystem:   &trueVal,
			RunAsNonRoot:             &trueVal,
			RunAsUser:                &runAsUser,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
	}

	// Keycloak needs writable /tmp and /opt/keycloak/data even with a read-only root filesystem.
	volumes := []corev1.Volume{
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "kc-data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	container.VolumeMounts = []corev1.VolumeMount{
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "kc-data", MountPath: "/opt/keycloak/data"},
	}
	if managed.TLSSecretRef != "" {
		mode := int32(0440)
		volumes = append(volumes, corev1.Volume{Name: "serving-tls", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: managed.TLSSecretRef, DefaultMode: &mode,
				Items: []corev1.KeyToPath{{Key: corev1.TLSCertKey, Path: "tls.crt"}, {Key: corev1.TLSPrivateKeyKey, Path: "tls.key"}}},
		}})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "serving-tls", MountPath: managedTLSMount, ReadOnly: true})
	}

	if managed.ThemePVC != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "themes",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: managed.ThemePVC,
				},
			},
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "themes",
			MountPath: "/opt/keycloak/providers",
		})
	}

	labels := map[string]string{"app": ki.Name}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ki.Name,
			Namespace: ki.Namespace,
		},
	}

	if err := controllerutil.SetControllerReference(ki, dep, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference on Deployment: %w", err)
	}

	var existing appsv1.Deployment
	err = r.Get(ctx, types.NamespacedName{Name: ki.Name, Namespace: ki.Namespace}, &existing)
	if errors.IsNotFound(err) {
		podSpec := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &trueVal,
				RunAsUser:    &runAsUser,
				FSGroup:      &runAsUser,
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{container},
			Volumes:    volumes,
		}
		if replicas > 1 {
			podSpec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "kubernetes.io/hostname",
				WhenUnsatisfiable: corev1.DoNotSchedule,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
			}}
		}
		dep.Spec = appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       podSpec,
			},
		}
		if createErr := r.Create(ctx, dep); createErr != nil {
			return fmt.Errorf("create Keycloak Deployment: %w", createErr)
		}
		log.Info("created Keycloak Deployment", "deployment", dep.Name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Keycloak Deployment: %w", err)
	}

	// Patch the existing Deployment — includes TopologySpreadConstraints so that
	// changes to replica count are reflected in scheduling constraints.
	patchBase := client.MergeFrom(existing.DeepCopy())
	existing.Spec.Replicas = &replicas
	existing.Spec.Template.Spec.Containers = []corev1.Container{container}
	existing.Spec.Template.Spec.Volumes = volumes
	existing.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: &trueVal,
		RunAsUser:    &runAsUser,
		FSGroup:      &runAsUser,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	if replicas > 1 {
		existing.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
			MaxSkew:           1,
			TopologyKey:       "kubernetes.io/hostname",
			WhenUnsatisfiable: corev1.DoNotSchedule,
			LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
		}}
	} else {
		existing.Spec.Template.Spec.TopologySpreadConstraints = nil
	}
	if patchErr := r.Patch(ctx, &existing, patchBase); patchErr != nil {
		return fmt.Errorf("patch Keycloak Deployment: %w", patchErr)
	}
	log.Info("patched Keycloak Deployment", "deployment", existing.Name)
	return nil
}

// ensureService creates or updates the ClusterIP Service for the Keycloak Deployment.
func (r *HankoKeycloakInstanceReconciler) ensureService(ctx context.Context, ki *hankoshv1alpha1.HankoKeycloakInstance) error {
	log := log.FromContext(ctx)
	transport, err := r.managedServerTransport(ctx, ki)
	if err != nil {
		return err
	}

	labels := map[string]string{"app": ki.Name}
	annotations := maps.Clone(autodiscoverAnnotations)
	annotations["hanko.sh/endpoint-template"] = transport.endpoint

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ki.Name,
			Namespace:   ki.Namespace,
			Labels:      autodiscoverLabels,
			Annotations: annotations,
		},
	}

	if err := controllerutil.SetControllerReference(ki, svc, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference on Service: %w", err)
	}

	var existing corev1.Service
	err = r.Get(ctx, types.NamespacedName{Name: ki.Name, Namespace: ki.Namespace}, &existing)
	if errors.IsNotFound(err) {
		svc.Spec = corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       transport.name,
					Port:       transport.port,
					TargetPort: intstr.FromInt32(transport.port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		}
		if createErr := r.Create(ctx, svc); createErr != nil {
			return fmt.Errorf("create Keycloak Service: %w", createErr)
		}
		log.Info("created Keycloak Service", "service", svc.Name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Keycloak Service: %w", err)
	}

	// Patch the existing Service.
	patchBase := client.MergeFrom(existing.DeepCopy())
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	maps.Copy(existing.Labels, autodiscoverLabels)
	maps.Copy(existing.Annotations, annotations)
	existing.Spec.Selector = labels
	existing.Spec.Ports = []corev1.ServicePort{
		{
			Name:       transport.name,
			Port:       transport.port,
			TargetPort: intstr.FromInt32(transport.port),
			Protocol:   corev1.ProtocolTCP,
		},
	}
	if patchErr := r.Patch(ctx, &existing, patchBase); patchErr != nil {
		return fmt.Errorf("patch Keycloak Service: %w", patchErr)
	}
	log.Info("patched Keycloak Service", "service", existing.Name)
	return nil
}

// ensureNetworkPolicy creates or updates the NetworkPolicy that isolates the managed
// Keycloak pod. The policy mirrors networkpolicy.yaml but uses the instance's own
// label selector, which may differ from the hardcoded "app: keycloak" in the static manifest.
func (r *HankoKeycloakInstanceReconciler) ensureNetworkPolicy(ctx context.Context, ki *hankoshv1alpha1.HankoKeycloakInstance) error {
	log := log.FromContext(ctx)
	transport, err := managedListener(ki, r.RequireHTTPS)
	if err != nil {
		return err
	}
	labels := map[string]string{"app": ki.Name}
	tcpProto := corev1.ProtocolTCP

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ki.Name + "-isolation",
			Namespace: ki.Namespace,
		},
	}
	if err := controllerutil.SetControllerReference(ki, np, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference on NetworkPolicy: %w", err)
	}

	desired := networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: labels},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				// hanko-api and hanko-operator — Admin API
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "hanko-api"}}},
					{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "hanko-operator"}}},
				},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcpProto, Port: &intstr.IntOrString{Type: intstr.Int, IntVal: transport.port}}},
			},
			{
				// Traefik (kube-system) — admin console, IP allowlist enforced at ingress level
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "traefik"}},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcpProto, Port: &intstr.IntOrString{Type: intstr.Int, IntVal: transport.port}}},
			},
		},
	}

	var existing networkingv1.NetworkPolicy
	if err := r.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, &existing); errors.IsNotFound(err) {
		np.Spec = desired
		if err := r.Create(ctx, np); err != nil {
			return fmt.Errorf("create NetworkPolicy: %w", err)
		}
		log.Info("created NetworkPolicy", "name", np.Name)
		return nil
	} else if err != nil {
		return fmt.Errorf("get NetworkPolicy: %w", err)
	}
	patchBase := client.MergeFrom(existing.DeepCopy())
	existing.Spec = desired
	if err := r.Patch(ctx, &existing, patchBase); err != nil {
		return fmt.Errorf("patch NetworkPolicy: %w", err)
	}
	return nil
}

// ensurePDB creates or updates a PodDisruptionBudget for the managed Keycloak Deployment.
// A PDB is only created when replicas >= 2; a single-replica deployment should not have
// a PDB as it would prevent all node drains.
func (r *HankoKeycloakInstanceReconciler) ensurePDB(ctx context.Context, ki *hankoshv1alpha1.HankoKeycloakInstance) error {
	log := log.FromContext(ctx)
	if ki.Spec.Managed == nil {
		return nil
	}
	replicas := int32(1)
	if ki.Spec.Managed.Replicas != nil {
		replicas = *ki.Spec.Managed.Replicas
	}
	if replicas < 2 {
		// Delete PDB if it exists — a single-replica deployment must not have a PDB
		// as it would block all node drains.
		var existingPDB policyv1.PodDisruptionBudget
		if err := r.Get(ctx, types.NamespacedName{Name: ki.Name, Namespace: ki.Namespace}, &existingPDB); err == nil {
			if delErr := r.Delete(ctx, &existingPDB); delErr != nil && !errors.IsNotFound(delErr) {
				return fmt.Errorf("delete stale PodDisruptionBudget: %w", delErr)
			}
			log.Info("deleted stale PodDisruptionBudget", "name", ki.Name)
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("get stale PodDisruptionBudget: %w", err)
		}
		return nil
	}

	minAvailable := intstr.FromInt32(1)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ki.Name,
			Namespace: ki.Namespace,
		},
	}
	if err := controllerutil.SetControllerReference(ki, pdb, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference on PDB: %w", err)
	}

	desired := policyv1.PodDisruptionBudgetSpec{
		MinAvailable: &minAvailable,
		Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": ki.Name}},
	}

	var existing policyv1.PodDisruptionBudget
	if err := r.Get(ctx, types.NamespacedName{Name: pdb.Name, Namespace: pdb.Namespace}, &existing); errors.IsNotFound(err) {
		pdb.Spec = desired
		if err := r.Create(ctx, pdb); err != nil {
			return fmt.Errorf("create PodDisruptionBudget: %w", err)
		}
		log.Info("created PodDisruptionBudget", "name", pdb.Name)
		return nil
	} else if err != nil {
		return fmt.Errorf("get PodDisruptionBudget: %w", err)
	}
	patchBase := client.MergeFrom(existing.DeepCopy())
	existing.Spec = desired
	if err := r.Patch(ctx, &existing, patchBase); err != nil {
		return fmt.Errorf("patch PodDisruptionBudget: %w", err)
	}
	return nil
}

// SetupWithManager registers the reconciler and declares owned resources.
// GenerationChangedPredicate on the For() watch keeps the reconciler's own
// Status().Patch calls (status subresource updates, which do not bump
// .metadata.generation) from re-triggering an immediate reconcile — without
// it, every reconcile's status write requeues itself in a tight loop.
func (r *HankoKeycloakInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoKeycloakInstance{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}
