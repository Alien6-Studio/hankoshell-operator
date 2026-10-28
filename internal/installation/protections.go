package installation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/version"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Verify uses uncached reads and never repairs, creates or acquires protection
// objects. Missing authority or an incomplete installation prevents startup.
func (c *Contract) Verify(ctx context.Context, reader client.Reader, namespace, kubernetesVersion string) error {
	if namespace != c.Namespace {
		return errors.New("installation contract belongs to another namespace")
	}
	if err := c.verifyNamespace(ctx, reader, kubernetesVersion); err != nil {
		return err
	}
	if err := c.rejectHelmOwnership(ctx, reader); err != nil {
		return err
	}
	for _, object := range c.Objects {
		if err := verifyProtection(ctx, reader, object); err != nil {
			return err
		}
	}
	for _, crd := range c.CRDs {
		if err := verifyCRD(ctx, reader, crd); err != nil {
			return err
		}
	}
	return nil
}

func (c *Contract) verifyNamespace(ctx context.Context, reader client.Reader, kubernetesVersion string) error {
	server, err := version.ParseSemantic(kubernetesVersion)
	minimum, minErr := version.ParseSemantic(c.MinimumKubernetes)
	maximum, maxErr := version.ParseSemantic(c.MaximumKubernetes)
	if err != nil || minErr != nil || maxErr != nil || server.PreRelease() != "" || !server.AtLeast(minimum) || server.AtLeast(maximum) {
		return errors.New("kubernetes is outside the installation qualification window")
	}
	var ns corev1.Namespace
	if err := reader.Get(ctx, client.ObjectKey{Name: c.Namespace}, &ns); err != nil {
		return errors.New("cannot verify installation namespace protections")
	}
	psaVersion := ns.Labels["pod-security.kubernetes.io/enforce-version"]
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" || (psaVersion != "" && psaVersion != "latest" && psaVersion != fmt.Sprintf("v%d.%d", server.Major(), server.Minor())) {
		return errors.New("installation requires current Restricted Pod Security admission")
	}
	return nil
}

func (c *Contract) rejectHelmOwnership(ctx context.Context, reader client.Reader) error {
	var deployments appsv1.DeploymentList
	if err := reader.List(ctx, &deployments, client.InNamespace(c.Namespace)); err != nil {
		return errors.New("cannot verify exclusive operator installation ownership")
	}
	for _, deployment := range deployments.Items {
		isOperator := deployment.Spec.Template.Labels["app"] == "hanko-operator"
		if isOperator && (deployment.Name != c.Deployment || deployment.Labels["app.kubernetes.io/managed-by"] == "Helm") {
			return errors.New("another operator installation exists; migrate ownership before installing with OLM")
		}
	}
	var role rbacv1.Role
	err := reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: c.Deployment}, &role)
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.New("cannot verify installation RBAC ownership")
	}
	if err == nil && role.Labels["app.kubernetes.io/managed-by"] == "Helm" {
		return errors.New("helm still owns installation RBAC; explicit migration is required")
	}
	return nil
}

func verifyProtection(ctx context.Context, reader client.Reader, expected Object) error {
	object, err := newProtection(expected.Kind)
	if err != nil {
		return err
	}
	if err := reader.Get(ctx, client.ObjectKey{Name: expected.Name, Namespace: expected.Namespace}, object); err != nil {
		return fmt.Errorf("cannot verify required protection %s/%s", expected.Kind, expected.Name)
	}
	if object.GetDeletionTimestamp() != nil {
		return fmt.Errorf("required protection %s/%s is being deleted", expected.Kind, expected.Name)
	}
	actual, err := protectionSpec(object)
	if err != nil {
		return err
	}
	want, err := canonicalSpec(expected.Kind, expected.Spec)
	if err != nil {
		return err
	}
	got, err := canonicalSpec(expected.Kind, actual)
	if err != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("required protection %s/%s differs from the approved configuration", expected.Kind, expected.Name)
	}
	return nil
}

func newProtection(kind string) (client.Object, error) {
	switch kind {
	case "ValidatingAdmissionPolicy":
		return &admissionv1.ValidatingAdmissionPolicy{}, nil
	case "ValidatingAdmissionPolicyBinding":
		return &admissionv1.ValidatingAdmissionPolicyBinding{}, nil
	case "NetworkPolicy":
		return &networkingv1.NetworkPolicy{}, nil
	default:
		return nil, errors.New("unsupported installation protection")
	}
}

func protectionSpec(object client.Object) ([]byte, error) {
	switch typed := object.(type) {
	case *admissionv1.ValidatingAdmissionPolicy:
		if typed.Status.ObservedGeneration < typed.Generation || typed.Status.TypeChecking == nil || len(typed.Status.TypeChecking.ExpressionWarnings) != 0 {
			return nil, errors.New("admission policy has not completed successful type checking")
		}
		return json.Marshal(typed.Spec)
	case *admissionv1.ValidatingAdmissionPolicyBinding:
		return json.Marshal(typed.Spec)
	case *networkingv1.NetworkPolicy:
		return json.Marshal(typed.Spec)
	default:
		return nil, errors.New("unsupported installation protection")
	}
}

func canonicalSpec(kind string, data []byte) ([]byte, error) {
	switch kind {
	case "ValidatingAdmissionPolicy":
		var spec admissionv1.ValidatingAdmissionPolicySpec
		if err := strictSpec(data, &spec); err != nil {
			return nil, err
		}
		if spec.FailurePolicy == nil {
			policy := admissionv1.Fail
			spec.FailurePolicy = &policy
		}
		defaultMatchResources(spec.MatchConstraints)
		return json.Marshal(spec)
	case "ValidatingAdmissionPolicyBinding":
		var spec admissionv1.ValidatingAdmissionPolicyBindingSpec
		if err := strictSpec(data, &spec); err != nil {
			return nil, err
		}
		defaultMatchResources(spec.MatchResources)
		return json.Marshal(spec)
	case "NetworkPolicy":
		var spec networkingv1.NetworkPolicySpec
		if err := strictSpec(data, &spec); err != nil {
			return nil, err
		}
		return json.Marshal(spec)
	default:
		return nil, errors.New("unsupported protection specification")
	}
}

func strictSpec(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func defaultMatchResources(match *admissionv1.MatchResources) {
	if match == nil {
		return
	}
	if match.MatchPolicy == nil {
		policy := admissionv1.Equivalent
		match.MatchPolicy = &policy
	}
	if match.NamespaceSelector == nil {
		match.NamespaceSelector = &metav1.LabelSelector{}
	}
	if match.ObjectSelector == nil {
		match.ObjectSelector = &metav1.LabelSelector{}
	}
	for i := range match.ResourceRules {
		if match.ResourceRules[i].Scope == nil {
			scope := admissionv1.AllScopes
			match.ResourceRules[i].Scope = &scope
		}
	}
	for i := range match.ExcludeResourceRules {
		if match.ExcludeResourceRules[i].Scope == nil {
			scope := admissionv1.AllScopes
			match.ExcludeResourceRules[i].Scope = &scope
		}
	}
}

func verifyCRD(ctx context.Context, reader client.Reader, expected CRD) error {
	var crd apiextensionsv1.CustomResourceDefinition
	if err := reader.Get(ctx, client.ObjectKey{Name: expected.Name}, &crd); err != nil {
		return fmt.Errorf("cannot verify owned CRD %s", expected.Name)
	}
	if crd.DeletionTimestamp != nil || crd.Spec.Group != "hanko.sh" || crd.Spec.Names.Kind != expected.Kind {
		return fmt.Errorf("owned CRD %s has an incompatible identity", expected.Name)
	}
	ready := false
	for _, v := range crd.Spec.Versions {
		if v.Name == expected.Version && v.Served && v.Storage {
			ready = true
		}
	}
	for _, stored := range crd.Status.StoredVersions {
		if stored != expected.Version {
			return fmt.Errorf("owned CRD %s requires a storage migration before installation", expected.Name)
		}
	}
	if !ready || len(crd.Status.StoredVersions) == 0 {
		return fmt.Errorf("owned CRD %s does not serve the expected storage version", expected.Name)
	}
	return establishedCRD(&crd)
}

func establishedCRD(crd *apiextensionsv1.CustomResourceDefinition) error {
	established := false
	for _, condition := range crd.Status.Conditions {
		if condition.Type == apiextensionsv1.Established && condition.Status == apiextensionsv1.ConditionTrue {
			established = true
		}
		if condition.Type == apiextensionsv1.NamesAccepted && condition.Status == apiextensionsv1.ConditionFalse {
			return fmt.Errorf("owned CRD %s has a naming conflict", crd.Name)
		}
	}
	if !established {
		return fmt.Errorf("owned CRD %s does not serve the expected storage version", crd.Name)
	}
	return nil
}
