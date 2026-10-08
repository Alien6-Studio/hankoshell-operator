package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

// HankoMeshServiceReconciler resolves mutable names to the immutable
// Kubernetes and Hanko identity material consumed by a policy compiler.
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankomeshservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankomeshservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoresourceservers;hankoserviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services;serviceaccounts;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get
type HankoMeshServiceReconciler struct {
	client.Client
	// NodeReader deliberately bypasses controller-runtime's shared cache. A
	// cached Get lazily starts a cluster-wide Node informer and therefore needs
	// list/watch; the API reader preserves the reviewed nodes/get-only boundary.
	NodeReader client.Reader
	// EgressReader performs exact cross-namespace Service Gets without starting
	// an unrestricted informer. Helm grants it get-only Roles in reviewed
	// namespaces.
	EgressReader client.Reader
}

func (r *HankoMeshServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var meshService hankoshv1alpha1.HankoMeshService
	if err := r.Get(ctx, req.NamespacedName, &meshService); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	resolved, err := r.resolve(ctx, &meshService)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, r.statusError(ctx, &meshService, err)
	}
	return r.statusReady(ctx, &meshService, resolved)
}

type resolvedMeshService struct {
	tenantID                  string
	clusterID                 string
	workloadID                string
	audience                  string
	realm                     string
	serviceUID                string
	workloadServiceAccountUID string
	selectorSHA256            string
	enforcementMode           string
	receiverNodeUIDs          []string
	ports                     []hankoshv1alpha1.MeshServicePort
	egress                    []hankoshv1alpha1.ResolvedMeshServiceEgress
}

func (r *HankoMeshServiceReconciler) resolve(ctx context.Context, registration *hankoshv1alpha1.HankoMeshService) (resolvedMeshService, error) { // NOSONAR -- immutable Kubernetes identity resolution is deliberately fail closed.
	namespaced := func(name string) types.NamespacedName {
		return types.NamespacedName{Name: name, Namespace: registration.Namespace}
	}
	var tenant hankoshv1alpha1.HankoTenant
	if err := r.Get(ctx, namespaced(registration.Spec.TenantRef), &tenant); err != nil {
		return resolvedMeshService{}, fmt.Errorf("resolve Hanko tenant %q: %w", registration.Spec.TenantRef, err)
	}
	if tenant.Status.Phase != "Synced" || tenant.Status.ObservedGeneration != tenant.Generation || tenant.Status.TenantID == "" || tenant.Status.ClusterID == "" {
		return resolvedMeshService{}, fmt.Errorf("hanko tenant %q has no Synced Hub identity for generation %d", tenant.Name, tenant.Generation)
	}

	var identity hankoshv1alpha1.HankoServiceAccount
	if err := r.Get(ctx, namespaced(registration.Spec.IdentityRef), &identity); err != nil {
		return resolvedMeshService{}, fmt.Errorf("resolve Hanko identity %q: %w", registration.Spec.IdentityRef, err)
	}
	if identity.Status.Phase != "Ready" || identity.Status.ObservedGeneration != identity.Generation {
		return resolvedMeshService{}, fmt.Errorf("hanko identity %q has no Ready status for generation %d", identity.Name, identity.Generation)
	}
	if err := validateResolvedMeshIdentifier("workload ID", identity.Spec.ClientID); err != nil {
		return resolvedMeshService{}, err
	}

	var resourceServer hankoshv1alpha1.HankoResourceServer
	if err := r.Get(ctx, namespaced(registration.Spec.ResourceServerRef), &resourceServer); err != nil {
		return resolvedMeshService{}, fmt.Errorf("resolve Hanko resource server %q: %w", registration.Spec.ResourceServerRef, err)
	}
	if resourceServer.Status.Phase != "Ready" || resourceServer.Status.ObservedGeneration != resourceServer.Generation {
		return resolvedMeshService{}, fmt.Errorf("hanko resource server %q has no Ready status for generation %d", resourceServer.Name, resourceServer.Generation)
	}
	if identity.Spec.RealmRef != resourceServer.Spec.RealmRef {
		return resolvedMeshService{}, fmt.Errorf("hanko identity and resource server belong to different realms %q and %q", identity.Spec.RealmRef, resourceServer.Spec.RealmRef)
	}
	if err := validateMeshTenantOwnership(&tenant, &identity, &resourceServer); err != nil {
		return resolvedMeshService{}, err
	}
	if err := validateResolvedAudience(resourceServer.Spec.Audience); err != nil {
		return resolvedMeshService{}, err
	}

	var service corev1.Service
	if err := r.Get(ctx, namespaced(registration.Spec.ServiceRef), &service); err != nil {
		return resolvedMeshService{}, fmt.Errorf("resolve Kubernetes Service %q: %w", registration.Spec.ServiceRef, err)
	}
	if service.UID == "" {
		return resolvedMeshService{}, fmt.Errorf("kubernetes Service %q has no immutable UID", service.Name)
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		return resolvedMeshService{}, errors.New("externalName Services cannot be registered for Continuum transport")
	}
	if len(service.Spec.Selector) == 0 {
		return resolvedMeshService{}, errors.New("registered Kubernetes Service requires a non-empty pod selector")
	}
	ports, err := resolveMeshPorts(registration.Spec.Ports, service.Spec.Ports)
	if err != nil {
		return resolvedMeshService{}, err
	}
	enforcementMode := registration.Spec.EnforcementMode
	if enforcementMode == "" {
		enforcementMode = "bidirectional"
	}
	if enforcementMode != "bidirectional" && enforcementMode != "ingressOnly" && enforcementMode != "egressOnly" && enforcementMode != "auditOnly" {
		return resolvedMeshService{}, fmt.Errorf("unsupported enforcement mode %q", enforcementMode)
	}
	if (enforcementMode == "ingressOnly" || enforcementMode == "auditOnly") && len(registration.Spec.Egress) != 0 {
		return resolvedMeshService{}, fmt.Errorf("%s mesh service cannot declare caller egress", enforcementMode)
	}
	resolvedEgress, err := r.resolveEgress(ctx, registration)
	if err != nil {
		return resolvedMeshService{}, err
	}

	var workloadAccount corev1.ServiceAccount
	if err := r.Get(ctx, namespaced(registration.Spec.WorkloadServiceAccountRef), &workloadAccount); err != nil {
		return resolvedMeshService{}, fmt.Errorf("resolve Kubernetes ServiceAccount %q: %w", registration.Spec.WorkloadServiceAccountRef, err)
	}
	if workloadAccount.UID == "" {
		return resolvedMeshService{}, fmt.Errorf("kubernetes ServiceAccount %q has no immutable UID", workloadAccount.Name)
	}

	var selectedPods corev1.PodList
	if err := r.List(ctx, &selectedPods, client.InNamespace(registration.Namespace), client.MatchingLabels(service.Spec.Selector)); err != nil {
		return resolvedMeshService{}, fmt.Errorf("list pods selected by Kubernetes Service %q: %w", service.Name, err)
	}
	receiverNodeNames := make(map[string]struct{})
	for index := range selectedPods.Items {
		pod := &selectedPods.Items[index]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if pod.Spec.HostNetwork {
			return resolvedMeshService{}, fmt.Errorf("selected pod %q uses hostNetwork and cannot receive a workload mesh identity", pod.Name)
		}
		accountName := pod.Spec.ServiceAccountName
		if accountName == "" {
			accountName = "default"
		}
		if accountName != workloadAccount.Name {
			return resolvedMeshService{}, fmt.Errorf("selected pod %q uses Kubernetes ServiceAccount %q instead of %q", pod.Name, accountName, workloadAccount.Name)
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
			continue
		}
		if pod.UID == "" {
			return resolvedMeshService{}, fmt.Errorf("selected Ready pod %q has no immutable UID", pod.Name)
		}
		if pod.Spec.NodeName == "" {
			return resolvedMeshService{}, fmt.Errorf("selected Ready pod %q is not assigned to a node", pod.Name)
		}
		receiverNodeNames[pod.Spec.NodeName] = struct{}{}
	}
	if len(receiverNodeNames) > 256 {
		return resolvedMeshService{}, errors.New("registered Service spans more than 256 Ready receiver nodes")
	}
	nodeNames := make([]string, 0, len(receiverNodeNames))
	for nodeName := range receiverNodeNames {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)
	receiverNodeUIDs := make([]string, 0, len(nodeNames))
	seenNodeUIDs := make(map[string]struct{}, len(nodeNames))
	for _, nodeName := range nodeNames {
		var node corev1.Node
		if r.NodeReader == nil {
			return resolvedMeshService{}, errors.New("direct Kubernetes Node reader is not configured")
		}
		if err := r.NodeReader.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
			return resolvedMeshService{}, fmt.Errorf("resolve Kubernetes Node %q: %w", nodeName, err)
		}
		if node.UID == "" {
			return resolvedMeshService{}, fmt.Errorf("kubernetes Node %q has no immutable UID", nodeName)
		}
		uid := string(node.UID)
		if _, duplicate := seenNodeUIDs[uid]; duplicate {
			return resolvedMeshService{}, errors.New("selected receiver Nodes have a duplicate immutable UID")
		}
		seenNodeUIDs[uid] = struct{}{}
		receiverNodeUIDs = append(receiverNodeUIDs, uid)
	}
	sort.Strings(receiverNodeUIDs)

	return resolvedMeshService{
		tenantID:                  tenant.Status.TenantID,
		clusterID:                 tenant.Status.ClusterID,
		workloadID:                identity.Spec.ClientID,
		audience:                  resourceServer.Spec.Audience,
		realm:                     identity.Spec.RealmRef,
		serviceUID:                string(service.UID),
		workloadServiceAccountUID: string(workloadAccount.UID),
		selectorSHA256:            hashServiceSelector(service.Spec.Selector),
		enforcementMode:           enforcementMode,
		receiverNodeUIDs:          receiverNodeUIDs,
		ports:                     ports,
		egress:                    resolvedEgress,
	}, nil
}

func (r *HankoMeshServiceReconciler) resolveEgress(ctx context.Context, registration *hankoshv1alpha1.HankoMeshService) ([]hankoshv1alpha1.ResolvedMeshServiceEgress, error) { // NOSONAR -- each authorization reference is independently validated.
	if len(registration.Spec.Egress) > 64 {
		return nil, errors.New("mesh service contains more than 64 reviewed egress Services")
	}
	resolved := make([]hankoshv1alpha1.ResolvedMeshServiceEgress, 0, len(registration.Spec.Egress))
	seen := make(map[string]struct{}, len(registration.Spec.Egress))
	for _, requested := range registration.Spec.Egress {
		key := requested.Namespace + "\x00" + requested.ServiceRef
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate reviewed egress Service %s/%s", requested.Namespace, requested.ServiceRef)
		}
		seen[key] = struct{}{}
		reader := client.Reader(r.Client)
		if requested.Namespace != registration.Namespace {
			if r.EgressReader == nil {
				return nil, errors.New("direct Kubernetes egress Service reader is not configured")
			}
			reader = r.EgressReader
		}
		var service corev1.Service
		if err := reader.Get(ctx, types.NamespacedName{Namespace: requested.Namespace, Name: requested.ServiceRef}, &service); err != nil {
			return nil, fmt.Errorf("resolve reviewed egress Service %s/%s: %w", requested.Namespace, requested.ServiceRef, err)
		}
		if service.UID == "" {
			return nil, fmt.Errorf("reviewed egress Service %s/%s has no immutable UID", requested.Namespace, requested.ServiceRef)
		}
		if service.Spec.Type == corev1.ServiceTypeExternalName || service.Spec.ClusterIP == corev1.ClusterIPNone || service.Spec.ClusterIP == "" {
			return nil, fmt.Errorf("reviewed egress Service %s/%s requires an exact ClusterIP", requested.Namespace, requested.ServiceRef)
		}
		ports, err := resolveMeshPorts(requested.Ports, service.Spec.Ports)
		if err != nil {
			return nil, fmt.Errorf("resolve reviewed egress Service %s/%s: %w", requested.Namespace, requested.ServiceRef, err)
		}
		resolved = append(resolved, hankoshv1alpha1.ResolvedMeshServiceEgress{
			Namespace: requested.Namespace, ServiceName: requested.ServiceRef,
			ServiceUID: string(service.UID), Ports: ports,
		})
	}
	sort.Slice(resolved, func(left, right int) bool {
		if resolved[left].Namespace != resolved[right].Namespace {
			return resolved[left].Namespace < resolved[right].Namespace
		}
		return resolved[left].ServiceName < resolved[right].ServiceName
	})
	return resolved, nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func validateMeshTenantOwnership(tenant *hankoshv1alpha1.HankoTenant, identity *hankoshv1alpha1.HankoServiceAccount, resourceServer *hankoshv1alpha1.HankoResourceServer) error {
	mode := tenant.Spec.IsolationMode
	if mode == "" {
		mode = "realm"
	}
	if mode == "realm" {
		if tenant.Spec.RealmRef == "" || identity.Spec.RealmRef != tenant.Spec.RealmRef || resourceServer.Spec.RealmRef != tenant.Spec.RealmRef {
			return fmt.Errorf("mesh identities do not belong to tenant realm %q", tenant.Spec.RealmRef)
		}
		return nil
	}
	if mode != "keycloak" && mode != "cluster" {
		return fmt.Errorf("tenant has unsupported isolation mode %q", mode)
	}
	for kind, labels := range map[string]map[string]string{
		"Hanko identity": identity.Labels, "Hanko resource server": resourceServer.Labels,
	} {
		if labels["hanko.sh/tenant"] != tenant.Name {
			return fmt.Errorf("%s is not bound to tenant %q", kind, tenant.Name)
		}
	}
	return nil
}

func resolveMeshPorts(requested []hankoshv1alpha1.MeshServicePort, available []corev1.ServicePort) ([]hankoshv1alpha1.MeshServicePort, error) { // NOSONAR -- port resolution rejects every ambiguous mapping explicitly.
	if len(requested) == 0 || len(requested) > 64 {
		return nil, errors.New("registered service requires between 1 and 64 exact ports")
	}
	seen := make(map[hankoshv1alpha1.MeshServicePort]struct{}, len(requested))
	resolved := append([]hankoshv1alpha1.MeshServicePort(nil), requested...)
	for _, port := range requested {
		if port.Port < 1 || port.Port > 65535 || (port.Protocol != "TCP" && port.Protocol != "UDP") {
			return nil, fmt.Errorf("invalid registered port %s/%d", port.Protocol, port.Port)
		}
		if _, exists := seen[port]; exists {
			return nil, fmt.Errorf("duplicate registered port %s/%d", port.Protocol, port.Port)
		}
		seen[port] = struct{}{}
		if !slices.ContainsFunc(available, func(servicePort corev1.ServicePort) bool {
			protocol := servicePort.Protocol
			if protocol == "" {
				protocol = corev1.ProtocolTCP
			}
			return string(protocol) == port.Protocol && servicePort.Port == port.Port
		}) {
			return nil, fmt.Errorf("registered port %s/%d is not exposed by the Kubernetes Service", port.Protocol, port.Port)
		}
	}
	sort.Slice(resolved, func(left, right int) bool {
		if resolved[left].Protocol == resolved[right].Protocol {
			return resolved[left].Port < resolved[right].Port
		}
		return resolved[left].Protocol < resolved[right].Protocol
	})
	return resolved, nil
}

func hashServiceSelector(selector map[string]string) string {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(selector[key]))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validateResolvedMeshIdentifier(label, value string) error {
	valid := len(value) > 0 && len(value) <= 255 && isASCIIAlphaNumeric(value[0])
	for index := 0; valid && index < len(value); index++ {
		character := value[index]
		valid = isASCIIAlphaNumeric(character) || character == '.' || character == '_' || character == ':' || character == '/' || character == '-'
	}
	if !valid || value == "*" {
		return fmt.Errorf("resolved %s is invalid for mesh policy", label)
	}
	return nil
}

func validateResolvedAudience(value string) error {
	valid := len(value) > 0 && len(value) <= 2048
	for index := 0; valid && index < len(value); index++ {
		character := value[index]
		valid = character >= 0x21 && character <= 0x7e && character != '*' && character != '\\'
	}
	if !valid {
		return errors.New("resolved resource-server audience is invalid for mesh policy")
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
}

func (r *HankoMeshServiceReconciler) statusError(ctx context.Context, registration *hankoshv1alpha1.HankoMeshService, reconcileErr error) error {
	patch := client.MergeFrom(registration.DeepCopy())
	registration.Status.Phase = "Error"
	registration.Status.ObservedGeneration = registration.Generation
	registration.Status.TenantID = ""
	registration.Status.ClusterID = ""
	registration.Status.WorkloadID = ""
	registration.Status.Audience = ""
	registration.Status.Realm = ""
	registration.Status.ServiceUID = ""
	registration.Status.WorkloadServiceAccountUID = ""
	registration.Status.SelectorSHA256 = ""
	registration.Status.EnforcementMode = ""
	registration.Status.ReceiverNodeUIDs = nil
	registration.Status.ResolvedPorts = nil
	registration.Status.ResolvedEgress = nil
	registration.Status.LastResolved = nil
	setCondition(&registration.Status.Conditions, "Attested", metav1.ConditionFalse, "InvalidBinding", reconcileErr.Error())
	if err := r.Status().Patch(ctx, registration, patch); err != nil {
		return errors.Join(reconcileErr, err)
	}
	return reconcileErr
}

func (r *HankoMeshServiceReconciler) statusReady(ctx context.Context, registration *hankoshv1alpha1.HankoMeshService, resolved resolvedMeshService) (ctrl.Result, error) {
	patch := client.MergeFrom(registration.DeepCopy())
	now := metav1.Now()
	registration.Status.Phase = "Ready"
	registration.Status.ObservedGeneration = registration.Generation
	registration.Status.TenantID = resolved.tenantID
	registration.Status.ClusterID = resolved.clusterID
	registration.Status.WorkloadID = resolved.workloadID
	registration.Status.Audience = resolved.audience
	registration.Status.Realm = resolved.realm
	registration.Status.ServiceUID = resolved.serviceUID
	registration.Status.WorkloadServiceAccountUID = resolved.workloadServiceAccountUID
	registration.Status.SelectorSHA256 = resolved.selectorSHA256
	registration.Status.EnforcementMode = resolved.enforcementMode
	registration.Status.ReceiverNodeUIDs = append([]string{}, resolved.receiverNodeUIDs...)
	registration.Status.ResolvedPorts = resolved.ports
	registration.Status.ResolvedEgress = resolved.egress
	registration.Status.LastResolved = &now
	setCondition(&registration.Status.Conditions, "Attested", metav1.ConditionTrue, "ReferencesResolved", "Hanko and Kubernetes identities resolve to one explicit workload binding")
	if err := r.Status().Patch(ctx, registration, patch); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("HankoMeshService binding resolved", "name", registration.Name, "workloadID", resolved.workloadID, "audience", resolved.audience)
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func (r *HankoMeshServiceReconciler) enqueueNamespaceRegistrations(ctx context.Context, object client.Object) []reconcile.Request {
	var registrations hankoshv1alpha1.HankoMeshServiceList
	if err := r.List(ctx, &registrations, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(registrations.Items))
	for index := range registrations.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Name: registrations.Items[index].Name, Namespace: registrations.Items[index].Namespace,
		}})
	}
	return requests
}

func (r *HankoMeshServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	requeueNamespace := handler.EnqueueRequestsFromMapFunc(r.enqueueNamespaceRegistrations)
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoMeshService{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&hankoshv1alpha1.HankoServiceAccount{}, requeueNamespace).
		Watches(&hankoshv1alpha1.HankoResourceServer{}, requeueNamespace).
		Watches(&hankoshv1alpha1.HankoTenant{}, requeueNamespace).
		Watches(&corev1.Service{}, requeueNamespace).
		Watches(&corev1.ServiceAccount{}, requeueNamespace).
		Watches(&corev1.Pod{}, requeueNamespace).
		Complete(r)
}
