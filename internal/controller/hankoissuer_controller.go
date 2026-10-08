package controller

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

const (
	defaultHankoAPIDeployment = "hanko-api"
	defaultHankoAPIContainer  = "hanko-api"
	publicIssuersEnv          = "HANKO_PUBLIC_ISSUERS"
	legacyPublicIssuerHostEnv = "HANKO_PUBLIC_ISSUER_HOSTS"
	issuerDriftCheckInterval  = 5 * time.Minute
)

// HankoIssuerReconciler aggregates declarative public issuers into the exact
// host-to-realm policy consumed by the hankoShell API deployment.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
type HankoIssuerReconciler struct {
	client.Client
	APIDeploymentName string
	APIContainerName  string
}

func (r *HankoIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var issuer hankoshv1alpha1.HankoIssuer
	err := r.Get(ctx, req.NamespacedName, &issuer)
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// A delete event arrives after the object is gone. Recompute the aggregate so
	// stale hosts are removed from the API deployment immediately.
	if apierrors.IsNotFound(err) {
		if err := r.reconcileDeploymentAllowlist(ctx, req.Namespace); err != nil {
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		return ctrl.Result{}, nil
	}

	canonicalHost, validationErr, reconcileErr := r.validateIssuer(ctx, &issuer)
	if reconcileErr != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, reconcileErr
	}

	if err := r.reconcileDeploymentAllowlist(ctx, issuer.Namespace); err != nil {
		_ = r.patchIssuerStatus(ctx, &issuer, "Error", canonicalHost, "DeploymentUpdateFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueOnError}, err
	}

	if validationErr != nil {
		if err := r.patchIssuerStatus(ctx, &issuer, "Error", "", "InvalidIssuer", validationErr.Error()); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: issuerDriftCheckInterval}, nil
	}

	if err := r.patchIssuerStatus(ctx, &issuer, "Ready", canonicalHost, "Configured", "public issuer host-to-realm binding is present in the API policy"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: issuerDriftCheckInterval}, nil
}

func (r *HankoIssuerReconciler) validateIssuer(ctx context.Context, issuer *hankoshv1alpha1.HankoIssuer) (string, error, error) {
	canonicalHost, validationErr := normalizeIssuerHost(issuer.Spec.Host)
	if validationErr != nil {
		return canonicalHost, validationErr, nil
	}
	var realm hankoshv1alpha1.HankoRealm
	if err := r.Get(ctx, types.NamespacedName{Name: issuer.Spec.RealmRef, Namespace: issuer.Namespace}, &realm); err != nil {
		if apierrors.IsNotFound(err) {
			return canonicalHost, fmt.Errorf("referenced HankoRealm %q does not exist", issuer.Spec.RealmRef), nil
		}
		return canonicalHost, nil, err
	}
	return canonicalHost, nil, nil
}

func (r *HankoIssuerReconciler) reconcileDeploymentAllowlist(ctx context.Context, namespace string) error {
	value, err := r.issuerPolicyValue(ctx, namespace)
	if err != nil {
		return err
	}
	deploymentName := stringOrDefault(r.APIDeploymentName, defaultHankoAPIDeployment)
	containerName := stringOrDefault(r.APIContainerName, defaultHankoAPIContainer)
	var deployment appsv1.Deployment
	key := types.NamespacedName{Name: deploymentName, Namespace: namespace}
	if err := r.Get(ctx, key, &deployment); err != nil {
		return fmt.Errorf("get API deployment %s: %w", key.String(), err)
	}
	patch := client.MergeFrom(deployment.DeepCopy())
	changed, found := reconcileIssuerEnvironment(&deployment, containerName, value)
	if !found {
		return fmt.Errorf("API container %q not found in deployment %s", containerName, key.String())
	}
	if !changed {
		return nil
	}
	if err := r.Patch(ctx, &deployment, patch); err != nil {
		return fmt.Errorf("patch API deployment issuer allowlist: %w", err)
	}
	return nil
}

func (r *HankoIssuerReconciler) issuerPolicyValue(ctx context.Context, namespace string) (string, error) {
	var issuers hankoshv1alpha1.HankoIssuerList
	if err := r.List(ctx, &issuers, client.InNamespace(namespace)); err != nil {
		return "", fmt.Errorf("list HankoIssuer resources: %w", err)
	}
	var realms hankoshv1alpha1.HankoRealmList
	if err := r.List(ctx, &realms, client.InNamespace(namespace)); err != nil {
		return "", fmt.Errorf("list HankoRealm resources: %w", err)
	}
	realmNames := make(map[string]struct{}, len(realms.Items))
	for i := range realms.Items {
		realmNames[realms.Items[i].Name] = struct{}{}
	}

	policySet := make(map[string]struct{}, len(issuers.Items))
	for i := range issuers.Items {
		item := &issuers.Items[i]
		if _, ok := realmNames[item.Spec.RealmRef]; !ok {
			continue
		}
		host, err := normalizeIssuerHost(item.Spec.Host)
		if err != nil {
			continue
		}
		policySet[host+"="+item.Spec.RealmRef] = struct{}{}
	}
	policies := make([]string, 0, len(policySet))
	for policy := range policySet {
		policies = append(policies, policy)
	}
	sort.Strings(policies)
	return strings.Join(policies, ","), nil
}

func reconcileIssuerEnvironment(deployment *appsv1.Deployment, containerName, value string) (bool, bool) {
	for i := range deployment.Spec.Template.Spec.Containers {
		container := &deployment.Spec.Template.Spec.Containers[i]
		if container.Name != containerName {
			continue
		}
		newEnvironment, changed := issuerEnvironment(container.Env, value)
		container.Env = newEnvironment
		return changed, true
	}
	return false, false
}

func issuerEnvironment(current []corev1.EnvVar, value string) ([]corev1.EnvVar, bool) {
	found := false
	changed := false
	result := make([]corev1.EnvVar, 0, len(current)+1)
	for _, environment := range current {
		if environment.Name == legacyPublicIssuerHostEnv {
			changed = true
			continue
		}
		if environment.Name == publicIssuersEnv {
			found = true
			if environment.Value != value || environment.ValueFrom != nil {
				environment.Value = value
				environment.ValueFrom = nil
				changed = true
			}
		}
		result = append(result, environment)
	}
	if !found {
		result = append(result, coreEnvVar(publicIssuersEnv, value))
		changed = true
	}
	return result, changed
}

func coreEnvVar(name, value string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, Value: value}
}

func (r *HankoIssuerReconciler) patchIssuerStatus(ctx context.Context, issuer *hankoshv1alpha1.HankoIssuer, phase, host, reason, message string) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Phase = phase
	issuer.Status.ConfiguredHost = host
	now := metav1.Now()
	issuer.Status.LastReconciled = &now
	conditionStatus := metav1.ConditionFalse
	if phase == "Ready" {
		conditionStatus = metav1.ConditionTrue
	}
	setCondition(&issuer.Status.Conditions, "Allowlisted", conditionStatus, reason, message)
	return r.Status().Patch(ctx, issuer, patch)
}

func normalizeIssuerHost(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t\r\n,/@?#\\*") {
		return "", fmt.Errorf("host must be one exact authority without scheme, path, wildcard, or forwarding list")
	}
	if err := validateASCIIHost(raw); err != nil {
		return "", err
	}
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host != raw || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid issuer host %q", raw)
	}
	hostname := strings.ToLower(u.Hostname())
	if strings.HasSuffix(hostname, ".") {
		return "", fmt.Errorf("host must not have a trailing dot")
	}
	if err := validateDNSHostname(hostname); err != nil {
		return "", err
	}
	return normalizedHostPort(hostname, u.Port())
}

func validateASCIIHost(raw string) error {
	for _, character := range raw {
		if character > 127 {
			return fmt.Errorf("host must contain ASCII characters only")
		}
	}
	return nil
}

func validateDNSHostname(hostname string) error {
	if net.ParseIP(hostname) != nil || hostname == "localhost" {
		return nil
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS hostname %q", hostname)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("invalid DNS hostname %q", hostname)
			}
		}
	}
	return nil
}

func normalizedHostPort(hostname, port string) (string, error) {
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid issuer port %q", port)
		}
		return net.JoinHostPort(hostname, port), nil
	}
	if strings.Contains(hostname, ":") {
		return "[" + hostname + "]", nil
	}
	return hostname, nil
}

func stringOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (r *HankoIssuerReconciler) requestsForDeployment(ctx context.Context, obj client.Object) []reconcile.Request {
	deployment, ok := obj.(*appsv1.Deployment)
	if !ok {
		return nil
	}
	name := r.APIDeploymentName
	if name == "" {
		name = defaultHankoAPIDeployment
	}
	if deployment.Name != name {
		return nil
	}
	return r.issuerRequestsInNamespace(ctx, deployment.Namespace, "")
}

func (r *HankoIssuerReconciler) requestsForRealm(ctx context.Context, obj client.Object) []reconcile.Request {
	realm, ok := obj.(*hankoshv1alpha1.HankoRealm)
	if !ok {
		return nil
	}
	return r.issuerRequestsInNamespace(ctx, realm.Namespace, realm.Name)
}

func (r *HankoIssuerReconciler) issuerRequestsInNamespace(ctx context.Context, namespace, realmName string) []reconcile.Request {
	var issuers hankoshv1alpha1.HankoIssuerList
	if err := r.List(ctx, &issuers, client.InNamespace(namespace)); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(issuers.Items))
	for i := range issuers.Items {
		if realmName != "" && issuers.Items[i].Spec.RealmRef != realmName {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Name: issuers.Items[i].Name, Namespace: issuers.Items[i].Namespace,
		}})
	}
	return requests
}

// SetupWithManager registers issuer, realm and API-deployment drift watches.
func (r *HankoIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoIssuer{}).
		Watches(&hankoshv1alpha1.HankoRealm{}, handler.EnqueueRequestsFromMapFunc(r.requestsForRealm)).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestsFromMapFunc(r.requestsForDeployment)).
		Complete(r)
}
