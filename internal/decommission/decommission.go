// Package decommission uninstalls the dedicated Hanko operator release from
// its own cluster after Hub requested it. It is the Go port of the reviewed
// agent-uninstall procedure: it removes only the exact release-owned resources
// and never touches IAM children, CRDs, PersistentVolumes, Keycloak, or the
// Hub credential Secret.
package decommission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

// ErrAfterConfirmation marks failures that happened after the Hub
// confirmation: the receipt is recorded and this operator's credential is
// surrendered, so the command can never be re-delivered. Callers must log the
// residue once for a reviewed manual cleanup instead of retrying.
var ErrAfterConfirmation = errors.New("decommission failed after hub confirmation")

// Config identifies the release-owned resources this operator may remove.
// ReleaseName is the Helm fullname every chart resource derives its name from.
type Config struct {
	Namespace   string
	ReleaseName string
	// CiliumPolicy enables removal of only this release's optional CNP.
	CiliumPolicy bool
	// TenantName is the HankoTenant that binds this operator to Hub. It is
	// deleted with Orphan propagation so synchronized IAM resources survive
	// for a later reviewed cleanup.
	TenantName string
	// CASecretNames are the disposable release Secrets (private Hub CA and the
	// consumed enrollment token). The Hub credential Secret is never listed
	// here and is refused defensively even if it is.
	CASecretNames []string
	// CredentialSecretName is the retained Hub credential Secret.
	CredentialSecretName string
	// Transport identifies the Continuum tenant transport release. Nil keeps
	// transport-backed tenants fail-closed: their decommission is refused.
	Transport *TransportConfig
	// MeshProjection identifies the audit-only mesh policy projection removed
	// together with the transport. Nil skips projection teardown.
	MeshProjection *MeshProjectionConfig
}

// TransportConfig identifies the Continuum tenant transport release. The
// transport is subordinate to the hub-spoke link: it is inventoried before
// the Hub confirmation — which still travels over it — and torn down right
// after, as the act that breaks the link.
type TransportConfig struct {
	// Namespace is the dedicated namespace the transport release lives in.
	Namespace string
	// ReleaseName is the Helm release name of the transport. Its bookkeeping
	// Secrets are matched by the owner=helm,name=<release> labels.
	ReleaseName string
	// DaemonSetName overrides the VPN node DaemonSet name; empty defaults to
	// "<ReleaseName>-continuum-vpn".
	DaemonSetName string
	// SecretNames are transport Secrets provisioned outside the release, such
	// as the mesh policy verifier trust anchor.
	SecretNames []string
}

func (t TransportConfig) daemonSetName() string {
	if name := strings.TrimSpace(t.DaemonSetName); name != "" {
		return name
	}
	return t.ReleaseName + "-continuum-vpn"
}

// MeshProjectionConfig identifies the audit-only mesh policy projection
// artifacts this operator maintains and may remove with the transport.
type MeshProjectionConfig struct {
	Namespace     string
	ConfigMapName string
	// WriterName is the Role/RoleBinding pair that authorizes the operator to
	// maintain the projection ConfigMap.
	WriterName string
}

// Validate reports whether the configuration identifies a removable release.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Namespace) == "" || strings.TrimSpace(c.ReleaseName) == "" || strings.TrimSpace(c.TenantName) == "" {
		return errors.New("decommission requires the release namespace, release name, and tenant name")
	}
	if c.Transport != nil &&
		(strings.TrimSpace(c.Transport.Namespace) == "" || strings.TrimSpace(c.Transport.ReleaseName) == "") {
		return errors.New("transport decommission requires the transport namespace and release name")
	}
	if c.MeshProjection != nil &&
		(strings.TrimSpace(c.MeshProjection.Namespace) == "" || strings.TrimSpace(c.MeshProjection.ConfigMapName) == "" ||
			strings.TrimSpace(c.MeshProjection.WriterName) == "") {
		return errors.New("mesh projection decommission requires the projection namespace, ConfigMap name, and writer name")
	}
	return nil
}

// Engine removes the operator release in a fail-closed order: the cluster
// surface first, then the Hub confirmation, then RBAC and the Deployment that
// runs this very process. Every step is idempotent so an interrupted run can
// be resumed on the next heartbeat that re-delivers the command.
type Engine struct {
	// Writer deletes and patches release resources.
	Writer client.Writer
	// Reader performs uncached reads: the operator has no list/watch authority
	// on RBAC resources, so cache-backed reads would fail.
	Reader client.Reader
	Config Config
	// Confirm reports the removal inventory to Hub before self-deletion.
	Confirm func(ctx context.Context, removedResources map[string]int) error
}

// Run executes the decommission and returns the removal inventory that was
// confirmed to Hub. When it returns without error the operator Deployment
// deletion has been accepted and this process is about to be terminated.
func (e *Engine) Run(ctx context.Context) (map[string]int, error) {
	if err := e.Config.Validate(); err != nil {
		return nil, err
	}
	removed, err := e.removeClusterSurface(ctx)
	if err != nil {
		return nil, err
	}
	// The link teardown is planned by reads before the confirmation so the Hub
	// receipt covers the transport, and executed only after it: the
	// confirmation is the last message that travels over the still-alive link.
	linkTargets, err := e.planLinkTeardown(ctx, removed)
	if err != nil {
		return nil, err
	}
	if err := e.confirmWithHub(ctx, removed); err != nil {
		return nil, err
	}
	// Past this point the credential is surrendered and the receipt recorded:
	// a failure can no longer be retried through a re-delivered command, so
	// the whole teardown is attempted and residue is reported in one error.
	if err := errors.Join(e.removeLink(ctx, linkTargets), e.removeSelf(ctx, removed)); err != nil {
		return removed, fmt.Errorf("%w: %w", ErrAfterConfirmation, err)
	}
	return removed, nil
}

// planLinkTeardown resolves which transport and mesh projection resources
// currently exist, counts them into the confirmed inventory, and returns them
// as the exact deletion targets for after the confirmation.
func (e *Engine) planLinkTeardown(ctx context.Context, removed map[string]int) ([]client.Object, error) { //nolint:gocognit // Sequential teardown-target inventory; complexity tracked by SonarQube S3776.
	var targets []client.Object
	appendIfFound := func(object client.Object, kind string) error {
		err := e.Reader.Get(ctx, client.ObjectKeyFromObject(object), object)
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("plan removal of %s %q: %w", kind, object.GetName(), err)
		}
		removed[kind]++
		targets = append(targets, object)
		return nil
	}
	if transport := e.Config.Transport; transport != nil {
		daemonSet := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: transport.Namespace, Name: transport.daemonSetName()}}
		if err := appendIfFound(daemonSet, "daemonSets"); err != nil {
			return nil, err
		}
		for _, name := range transport.SecretNames {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: transport.Namespace, Name: name}}
			if err := appendIfFound(secret, "secrets"); err != nil {
				return nil, err
			}
		}
		// Helm bookkeeping Secret names are versioned and unpredictable; the
		// transport namespace is dedicated, so a label-scoped list is exact.
		var bookkeeping corev1.SecretList
		if err := e.Reader.List(ctx, &bookkeeping, client.InNamespace(transport.Namespace),
			client.MatchingLabels{"owner": "helm", "name": transport.ReleaseName}); err != nil {
			return nil, fmt.Errorf("list transport release bookkeeping secrets: %w", err)
		}
		for index := range bookkeeping.Items {
			removed["secrets"]++
			targets = append(targets, &bookkeeping.Items[index])
		}
	}
	if projection := e.Config.MeshProjection; projection != nil {
		configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: projection.Namespace, Name: projection.ConfigMapName}}
		if err := appendIfFound(configMap, "configMaps"); err != nil {
			return nil, err
		}
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: projection.Namespace, Name: projection.WriterName}}
		if err := appendIfFound(role, "roles"); err != nil {
			return nil, err
		}
		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: projection.Namespace, Name: projection.WriterName}}
		if err := appendIfFound(binding, "roleBindings"); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// removeLink breaks the hub-spoke link by deleting the resources inventoried
// by planLinkTeardown. It runs after the confirmation, so failures are
// collected instead of aborting: partial residue in a dedicated namespace is
// preferable to a dead operator looping on a revoked credential.
func (e *Engine) removeLink(ctx context.Context, targets []client.Object) error {
	var errs []error
	for _, object := range targets {
		if err := e.Writer.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
			errs = append(errs, fmt.Errorf("delete %T %s/%s: %w", object, object.GetNamespace(), object.GetName(), err))
		}
	}
	return errors.Join(errs...)
}

// removeClusterSurface deletes everything the release exposes to the cluster
// before credentials are surrendered: Service, NetworkPolicies, the optional
// ServiceMonitor, and the disposable CA/enrollment Secrets. The HankoTenant is
// NOT removed here: it drives the heartbeat that re-delivers the command, so
// it must outlive the Hub confirmation.
func (e *Engine) removeClusterSurface(ctx context.Context) (map[string]int, error) {
	namespace, release := e.Config.Namespace, e.Config.ReleaseName
	removed := map[string]int{}

	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: release + "-metrics"}}
	if err := e.delete(ctx, service, removed, "services"); err != nil {
		return nil, err
	}
	for _, name := range []string{release, release + "-theme-jobs"} {
		policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		if err := e.delete(ctx, policy, removed, "networkPolicies"); err != nil {
			return nil, err
		}
	}
	if e.Config.CiliumPolicy {
		policy := &unstructured.Unstructured{}
		policy.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"})
		policy.SetNamespace(namespace)
		policy.SetName(release)
		if err := e.delete(ctx, policy, removed, "ciliumNetworkPolicies"); err != nil {
			return nil, err
		}
	}
	monitor := &unstructured.Unstructured{}
	monitor.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"})
	monitor.SetNamespace(namespace)
	monitor.SetName(release)
	if err := e.delete(ctx, monitor, removed, "serviceMonitors"); err != nil {
		return nil, err
	}

	for _, name := range e.Config.CASecretNames {
		name = strings.TrimSpace(name)
		if name == "" || name == e.Config.CredentialSecretName {
			// The Hub credential Secret is retained: it is the only proof of
			// this cluster identity if the decommission has to be audited.
			continue
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		if err := e.delete(ctx, secret, removed, "secrets"); err != nil {
			return nil, err
		}
	}
	return removed, nil
}

func (e *Engine) confirmWithHub(ctx context.Context, removed map[string]int) error {
	// A clone keeps the confirmed inventory immutable while removeSelf keeps
	// counting into the caller's map.
	err := e.Confirm(ctx, maps.Clone(removed))
	if errors.Is(err, hub.ErrDecommissionUnauthorized) {
		// A previous run already surrendered this credential; the receipt is
		// recorded on Hub, so only local teardown remains.
		return nil
	}
	if err != nil {
		return fmt.Errorf("confirm decommission inventory with hub: %w", err)
	}
	return nil
}

// removeSelf tears down the HankoTenant, RBAC and the operator Deployment.
// It runs only after the Hub confirmation: deleting the HankoTenant earlier
// would stop the heartbeat that re-delivers the command on a transient
// failure. RBAC is not deleted one by one — that would revoke the very
// authority the remaining deletions need — but transferred to release owners
// so a single anchored delete removes each group atomically.
func (e *Engine) removeSelf(ctx context.Context, removed map[string]int) error {
	namespace, release := e.Config.Namespace, e.Config.ReleaseName

	tenant := &unstructured.Unstructured{}
	tenant.SetGroupVersionKind(schema.GroupVersionKind{Group: "hanko.sh", Version: "v1alpha1", Kind: "HankoTenant"})
	tenant.SetNamespace(namespace)
	tenant.SetName(e.Config.TenantName)
	// Orphan propagation retains the synchronized IAM children for a later
	// reviewed cleanup.
	if err := e.delete(ctx, tenant, removed, "hankoTenants", client.PropagationPolicy(metav1.DeletePropagationOrphan)); err != nil {
		return err
	}

	var deployment appsv1.Deployment
	if err := e.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: release}, &deployment); err != nil {
		return fmt.Errorf("read operator deployment before self-removal: %w", err)
	}
	deploymentOwner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID}
	for _, object := range []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: release}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: release}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: release}},
	} {
		if err := e.adopt(ctx, object, deploymentOwner); err != nil {
			return err
		}
	}

	anchorName := release + "-cluster-identity-reader"
	var anchor rbacv1.ClusterRole
	if err := e.Reader.Get(ctx, types.NamespacedName{Name: anchorName}, &anchor); apierrors.IsNotFound(err) {
		// A resumed run may already have removed the cluster-scoped group.
		return e.deleteDeployment(ctx, &deployment)
	} else if err != nil {
		return fmt.Errorf("read cluster identity reader before self-removal: %w", err)
	}
	anchorOwner := metav1.OwnerReference{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: anchor.Name, UID: anchor.UID}
	for _, object := range []client.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: release + "-node-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: release + "-node-reader"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: anchorName}},
	} {
		if err := e.adopt(ctx, object, anchorOwner); err != nil {
			return err
		}
	}
	if err := e.Writer.Delete(ctx, &anchor); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete cluster identity reader: %w", err)
	}
	return e.deleteDeployment(ctx, &deployment)
}

func (e *Engine) deleteDeployment(ctx context.Context, deployment *appsv1.Deployment) error {
	if err := e.Writer.Delete(ctx, deployment); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete operator deployment: %w", err)
	}
	return nil
}

// adopt transfers an object to a release owner so one garbage-collected
// delete removes the whole group without a read on resources the operator
// cannot list. Helm-installed objects carry no owner, so replacing the list
// is exact.
func (e *Engine) adopt(ctx context.Context, object client.Object, owner metav1.OwnerReference) error {
	payload, err := json.Marshal(map[string]any{"metadata": map[string]any{"ownerReferences": []metav1.OwnerReference{owner}}})
	if err != nil {
		return fmt.Errorf("marshal ownership patch: %w", err)
	}
	err = e.Writer.Patch(ctx, object, client.RawPatch(types.MergePatchType, payload))
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("adopt %s %q for removal: %w", object.GetObjectKind().GroupVersionKind().Kind, object.GetName(), err)
	}
	return nil
}

func (e *Engine) delete(ctx context.Context, object client.Object, removed map[string]int, kind string, options ...client.DeleteOption) error {
	err := e.Writer.Delete(ctx, object, options...)
	if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
		// Absent resources (already removed, or a CRD such as ServiceMonitor
		// that was never installed) leave the inventory untouched.
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete %s %q: %w", kind, object.GetName(), err)
	}
	removed[kind]++
	return nil
}
