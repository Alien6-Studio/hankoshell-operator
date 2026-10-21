//go:build integration

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func checkSensitiveWrites(t *testing.T, ctx context.Context, admin client.Client, environment *envtest.Environment, config *rest.Config, chart, version string) {
	const name = "sensitive-test"
	installCompatibilityChart(t, ctx, admin, chart, version, []string{"--set-string", "fullnameOverride=" + name,
		"--set-string", "sensitiveWrites.secrets[0]=reviewed-credential", "--set-string", "sensitiveWrites.deployments[0]=reviewed-provider",
		"--set-string", "sensitiveWrites.projections[0].namespace=other", "--set-string", "sensitiveWrites.projections[0].secrets[0]=reviewed-projection"})
	identity, err := environment.AddUser(envtest.User{Name: "system:serviceaccount:auth:" + name, Groups: []string{"system:authenticated"}}, config)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := client.New(identity.Config(), client.Options{Scheme: admin.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		namespace, group, resource, verb, target string
		allowed                                  bool
	}{
		{"auth", "", "secrets", "patch", "reviewed-credential", true},
		{"auth", "", "secrets", "patch", "foreign-credential", false},
		{"auth", "apps", "deployments", "patch", "reviewed-provider", true},
		{"auth", "apps", "deployments", "patch", "foreign-provider", false},
		{"auth", "apps", "deployments", "create", "", true},
		{"other", "", "secrets", "patch", "reviewed-projection", true},
		{"other", "", "secrets", "patch", "foreign-credential", false},
		{"other", "", "secrets", "create", "", false},
		{"auth", "apps", "deployments/scale", "patch", "reviewed-provider", false},
	} {
		review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: c.namespace, Group: c.group, Resource: strings.Split(c.resource, "/")[0], Verb: c.verb, Name: c.target}}}
		if strings.Contains(c.resource, "/") {
			review.Spec.ResourceAttributes.Subresource = "scale"
		}
		if err := operator.Create(ctx, review); err != nil || review.Status.Allowed != c.allowed || review.Status.EvaluationError != "" {
			t.Fatalf("named RBAC differs for %s/%s/%s/%s: %#v %v", c.namespace, c.resource, c.verb, c.target, review.Status, err)
		}
	}
	// Deliberately add broader core-resource RBAC in this isolated test. The
	// admission boundary must still refuse unrelated names and forged ownership.
	probeRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "sensitive-admission-probe"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "create", "update", "patch", "delete"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "create", "update", "patch", "delete"}},
		{APIGroups: []string{rbacv1.GroupName}, Resources: []string{"clusterroles"}, Verbs: []string{"get", "patch"}},
	}}
	probeBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: probeRole.Name}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: probeRole.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "auth", Name: name}}}
	for _, object := range []client.Object{probeRole, probeBinding} {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = admin.Delete(ctx, probeBinding); _ = admin.Delete(ctx, probeRole) }()
	secret := func(namespace, target string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: target}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"public-fixture": []byte("not-a-credential")}}
	}
	if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		err := operator.Create(ctx, secret("auth", "foreign-credential"), client.DryRunAll)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), "administrator-approved exact target"), nil
	}); err != nil {
		t.Fatal("sensitive admission did not propagate", err)
	}
	for _, namespace := range []string{"auth", "other"} {
		for _, target := range []string{"reviewed-credential", "foreign-credential"} {
			t.Run("Secret create/"+namespace+"/"+target, func(t *testing.T) {
				object := secret(namespace, target)
				object.Labels = map[string]string{"app.kubernetes.io/managed-by": "Helm", "hanko.sh/runtime-target": "credentials"}
				err := operator.Create(ctx, object, client.DryRunAll)
				if namespace == "auth" && target == "reviewed-credential" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !apierrors.IsForbidden(err) {
					t.Fatal("forged labels bypassed exact write targets", err)
				}
			})
		}
	}
	for _, mutate := range []struct {
		name string
		f    func(*corev1.Secret)
	}{
		{"service-account-token", func(s *corev1.Secret) {
			s.Type = corev1.SecretTypeServiceAccountToken
			s.Annotations = map[string]string{corev1.ServiceAccountNameKey: "privileged"}
		}},
		{"token-annotation", func(s *corev1.Secret) { s.Annotations = map[string]string{corev1.ServiceAccountNameKey: "privileged"} }},
		{"other-secret-type", func(s *corev1.Secret) {
			s.Type = corev1.SecretTypeDockerConfigJson
			s.Data = map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)}
		}},
	} {
		t.Run("Secret privilege/"+mutate.name, func(t *testing.T) {
			object := secret("auth", "reviewed-credential")
			mutate.f(object)
			if err := admin.Create(ctx, object.DeepCopy(), client.DryRunAll); err != nil {
				t.Fatal("invalid adversarial fixture", err)
			}
			if err := operator.Create(ctx, object, client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "cannot mint service account tokens") {
				t.Fatal("token privilege not refused", err)
			}
		})
	}
	for _, target := range []string{"reviewed-credential", "foreign-credential"} {
		object := secret("auth", target)
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
		before := object.DeepCopy()
		object.Data["changed"] = []byte("public-fixture")
		err := operator.Patch(ctx, object, client.MergeFrom(before), client.DryRunAll)
		if target == "reviewed-credential" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !apierrors.IsForbidden(err) {
			t.Fatal("foreign Secret patch admitted", err)
		}
		if err := operator.Delete(ctx, object, client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatal("unapproved Secret delete admitted", err)
		}
	}
	projection := secret("other", "reviewed-projection")
	if err := admin.Create(ctx, projection); err != nil {
		t.Fatal(err)
	}
	beforeProjection := projection.DeepCopy()
	projection.Data["changed"] = []byte("public-fixture")
	if err := operator.Patch(ctx, projection, client.MergeFrom(beforeProjection), client.DryRunAll); err != nil {
		t.Fatal("named pre-existing projection patch refused", err)
	}
	if err := operator.Create(ctx, secret("other", "reviewed-projection"), client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatal("pre-existing-only projection became a creator", err)
	}
	labels := map[string]string{"app": "sensitive-provider"}
	no := false
	user := int64(1000)
	deployment := func(target string) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: target, Namespace: "auth"}, Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &no,
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: new(true), RunAsUser: &user, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				Containers:      []corev1.Container{{Name: "provider", Image: "registry.example/provider:fixture", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}}}}
	}
	for _, target := range []string{"reviewed-provider", "foreign-provider"} {
		t.Run("Deployment create/"+target, func(t *testing.T) {
			err := operator.Create(ctx, deployment(target), client.DryRunAll)
			if target == "reviewed-provider" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !apierrors.IsForbidden(err) {
				t.Fatal("foreign Deployment create admitted", err)
			}
		})
	}
	for _, mutate := range []struct {
		name string
		f    func(*appsv1.Deployment)
	}{
		{"token-mount", func(d *appsv1.Deployment) { d.Spec.Template.Spec.AutomountServiceAccountToken = new(true) }},
		{"privileged-account", func(d *appsv1.Deployment) { d.Spec.Template.Spec.ServiceAccountName = "privileged" }},
		{"token-projection", func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}}}
		}},
	} {
		t.Run("Deployment privilege/"+mutate.name, func(t *testing.T) {
			d := deployment("reviewed-provider")
			mutate.f(d)
			if err := admin.Create(ctx, d.DeepCopy(), client.DryRunAll); err != nil {
				t.Fatal("invalid adversarial Deployment", err)
			}
			if err := operator.Create(ctx, d, client.DryRunAll); !apierrors.IsForbidden(err) {
				t.Fatal("Kubernetes authority reached provider Deployment", err)
			}
		})
	}
	for _, attack := range []string{"approved", "token-mount", "privileged-account", "projected-token"} {
		t.Run("Job privilege/"+attack, func(t *testing.T) {
			pod := deployment("reviewed-provider").Spec.Template
			pod.Spec.RestartPolicy = corev1.RestartPolicyNever
			switch attack {
			case "token-mount":
				pod.Spec.AutomountServiceAccountToken = new(true)
			case "privileged-account":
				pod.Spec.ServiceAccountName = "privileged"
			case "projected-token":
				pod.Spec.Volumes = []corev1.Volume{{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}}}
			}
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "execution-probe", Namespace: "auth"}, Spec: batchv1.JobSpec{Template: pod}}
			if err := admin.Create(ctx, job.DeepCopy(), client.DryRunAll); err != nil {
				t.Fatal("invalid adversarial Job", err)
			}
			err := operator.Create(ctx, job, client.DryRunAll)
			if attack == "approved" {
				if err != nil {
					t.Fatal("ordinary token-free Job denied", err)
				}
			} else if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "cannot select privileged ServiceAccounts") {
				t.Fatal("Job bypassed sensitive-write isolation", err)
			}
		})
	}

	d := deployment("reviewed-provider")
	if err := admin.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	old := d.DeepCopy()
	d.Spec.Template.Spec.ServiceAccountName = "privileged"
	if err := operator.Patch(ctx, d, client.MergeFrom(old), client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "ServiceAccount binding") {
		t.Fatal("Deployment changed its ServiceAccount", err)
	}
	role := &rbacv1.Role{}
	if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, role); err != nil {
		t.Fatal(err)
	}
	oldRole := role.DeepCopy()
	role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	if err := operator.Patch(ctx, role, client.MergeFrom(oldRole), client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "cannot change its rules") {
		t.Fatal("operator altered its RBAC authority", err)
	}
	binding := &rbacv1.RoleBinding{}
	if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, binding); err != nil {
		t.Fatal(err)
	}
	oldBinding := binding.DeepCopy()
	binding.Subjects = append(binding.Subjects, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "User", Name: "another-authenticated-user"})
	if err := operator.Patch(ctx, binding, client.MergeFrom(oldBinding), client.DryRunAll); !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "cannot delegate its authority") {
		t.Fatal("operator bypassed write admission by delegating its Role", err)
	}
	binding = oldBinding.DeepCopy()
	binding.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "auth", UID: types.UID("qualification-owner")}}
	if err := operator.Patch(ctx, binding, client.MergeFrom(oldBinding), client.DryRunAll); err != nil {
		t.Fatal("release metadata adoption was blocked", err)
	}
	for _, mutate := range []struct {
		name string
		f    func(*rbacv1.ClusterRole)
	}{
		{"aggregation-label", func(r *rbacv1.ClusterRole) {
			r.Labels = map[string]string{"rbac.authorization.k8s.io/aggregate-to-admin": "true"}
		}},
		{"aggregation-rule", func(r *rbacv1.ClusterRole) {
			r.AggregationRule = &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"authority": "privileged"}}}}
		}},
	} {
		t.Run("RBAC privilege/"+mutate.name, func(t *testing.T) {
			changed := probeRole.DeepCopy()
			mutate.f(changed)
			if err := admin.Patch(ctx, changed.DeepCopy(), client.MergeFrom(probeRole), client.DryRunAll); err != nil {
				t.Fatal("invalid aggregation fixture", err)
			}
			if err := operator.Patch(ctx, changed, client.MergeFrom(probeRole), client.DryRunAll); !apierrors.IsForbidden(err) {
				t.Fatal("operator changed aggregation authority", err)
			}
		})
	}
	namespace := &corev1.Namespace{}
	if err := admin.Get(ctx, client.ObjectKey{Name: "auth"}, namespace); err != nil {
		t.Fatal(err)
	}
	previousNamespace := namespace.DeepCopy()
	for _, policy := range []string{"baseline", "outdated-restricted"} {
		t.Run("Deployment namespace/"+policy, func(t *testing.T) {
			changed := previousNamespace.DeepCopy()
			if policy == "baseline" {
				changed.Labels["pod-security.kubernetes.io/enforce"] = "baseline"
			} else {
				changed.Labels["pod-security.kubernetes.io/enforce-version"] = "v1.25"
			}
			if err := admin.Patch(ctx, changed, client.MergeFrom(previousNamespace)); err != nil {
				t.Fatal(err)
			}
			defer func() {
				restore, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": previousNamespace.Labels}})
				if err != nil {
					t.Error(err)
					return
				}
				if err := admin.Patch(ctx, previousNamespace.DeepCopy(), client.RawPatch(types.MergePatchType, restore)); err != nil {
					t.Error(err)
				}
			}()
			if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				err := operator.Create(ctx, deployment("reviewed-provider"), client.DryRunAll)
				return apierrors.IsForbidden(err) && strings.Contains(err.Error(), "current Restricted Pod Security"), nil
			}); err != nil {
				t.Fatal("weak Pod Security namespace admitted a Deployment write", err)
			}
		})
	}
	policies := &admissionv1.ValidatingAdmissionPolicyList{}
	if err := admin.List(ctx, policies); err != nil {
		t.Fatal(err)
	}
	for _, p := range policies.Items {
		if strings.HasPrefix(p.Name, name+"-") && p.Status.TypeChecking != nil && len(p.Status.TypeChecking.ExpressionWarnings) > 0 {
			t.Fatalf("admission CEL type warnings in %s: %#v", p.Name, p.Status.TypeChecking.ExpressionWarnings)
		}
	}
}
