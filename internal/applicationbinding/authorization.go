package applicationbinding

import (
	"context"
	"reflect"
	"regexp"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const TargetLabel = "hanko.sh/runtime-target"
const ApplicationNamespace = "hanko.sh/runtime-application-namespace"
const ApplicationName = "hanko.sh/runtime-application-name"
const ApplicationUID = "hanko.sh/runtime-application-uid"
const BindingName = "hanko.sh/runtime-binding-name"
const ServiceAccountName = "hanko.sh/runtime-service-account"
const ServiceAccountUID = "hanko.sh/runtime-service-account-uid"

var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Authorization is deliberately distinct from delivered annotations. It must
// be set by the target owner, with nonempty application and workload UIDs.
func Authorization(app *api.HankoApplication, binding api.ApplicationRuntimeBinding, workloadUID string) map[string]string {
	return map[string]string{ApplicationNamespace: app.Namespace, ApplicationName: app.Name, ApplicationUID: string(app.UID),
		BindingName: binding.Name, ServiceAccountName: binding.Workload.ServiceAccountRef, ServiceAccountUID: workloadUID}
}

func authorized(obj client.Object, app *api.HankoApplication, b api.ApplicationRuntimeBinding, uid, kind string) error {
	if obj.GetUID() == "" || !obj.GetDeletionTimestamp().IsZero() || obj.GetLabels()[TargetLabel] != kind || app.UID == "" || uid == "" {
		return failure("TargetNotAuthorized")
	}
	for key, value := range Authorization(app, b, uid) {
		if obj.GetAnnotations()[key] != value {
			if key == ServiceAccountUID {
				return failure("WorkloadChanged")
			}
			return failure("TargetNotAuthorized")
		}
	}
	return nil
}

// Validate rejects conflicting writers independently of admission/defaulting.
func Validate(app *api.HankoApplication) error {
	if len(app.Spec.RuntimeBindings) > MaxBindings {
		return failure("InvalidBindings")
	}
	if len(app.Spec.RuntimeBindings) != 0 && (app.Spec.Mode == "Observe" || app.Labels["hanko.sh/imported-by"] != "") {
		return failure("ManageRequired")
	}
	names, targets := map[string]bool{}, map[string]bool{}
	for _, b := range app.Spec.RuntimeBindings {
		if !validBinding(b) || names[b.Name] {
			return failure("InvalidBindings")
		}
		names[b.Name] = true
		key := targetIdentity("metadata", b.Workload.Namespace, b.PublicMetadata.ConfigMapRef)
		if targets[key] {
			return failure("DuplicateWriter")
		}
		targets[key] = true
		if err := validateCredentialTarget(app, b, targets); err != nil {
			return err
		}
	}
	return nil
}
func validBinding(b api.ApplicationRuntimeBinding) bool {
	return len(b.Name) <= 63 && dnsLabel.MatchString(b.Name) && len(b.Workload.Namespace) <= 63 && dnsLabel.MatchString(b.Workload.Namespace) &&
		len(b.Workload.ServiceAccountRef) <= 253 && dnsName.MatchString(b.Workload.ServiceAccountRef) && len(b.PublicMetadata.ConfigMapRef) <= 253 && dnsName.MatchString(b.PublicMetadata.ConfigMapRef)
}
func validateCredentialTarget(app *api.HankoApplication, b api.ApplicationRuntimeBinding, targets map[string]bool) error {
	if b.Credentials == nil {
		return nil
	}
	if app.Spec.Protocol == "saml" || app.Spec.Type == "spa" || len(b.Credentials.SecretRef) > 253 || !dnsName.MatchString(b.Credentials.SecretRef) {
		return failure("InvalidCredentials")
	}
	key := targetIdentity("credentials", b.Workload.Namespace, b.Credentials.SecretRef)
	if targets[key] || b.Workload.Namespace == app.Namespace && b.Credentials.SecretRef == "hanko-app-"+app.Spec.ClientID {
		return failure("DuplicateWriter")
	}
	for _, old := range app.Spec.ClientSecretProjections {
		if old.Namespace == b.Workload.Namespace && old.Name == b.Credentials.SecretRef {
			return failure("DuplicateWriter")
		}
	}
	targets[key] = true
	return nil
}

func workload(ctx context.Context, c client.Reader, b api.ApplicationRuntimeBinding) (*corev1.ServiceAccount, error) {
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, client.ObjectKey{Namespace: b.Workload.Namespace, Name: b.Workload.ServiceAccountRef}, &sa); err != nil {
		return nil, failure("WorkloadUnavailable")
	}
	if sa.UID == "" || len(sa.UID) > 128 || !sa.DeletionTimestamp.IsZero() {
		return nil, failure("WorkloadUnavailable")
	}
	return &sa, nil
}

func (d *Delivery) current(ctx context.Context, app *api.HankoApplication, proof *Proof) (*api.HankoApplication, error) {
	var current api.HankoApplication
	if err := d.Reader.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
		return nil, failure("StaleSource")
	}
	if current.UID != app.UID || current.Generation != app.Generation || !reflect.DeepEqual(current.Spec, app.Spec) || !reflect.DeepEqual(current.Labels, app.Labels) {
		return nil, failure("StaleSource")
	}
	if proof != nil {
		if !current.DeletionTimestamp.IsZero() || !proofMatches(&current, *proof) {
			return nil, failure("StaleSource")
		}
		if d.Verify == nil {
			return nil, failure("StaleSource")
		}
		if err := d.Verify(ctx); err != nil {
			return nil, failure("StaleSource")
		}
	}
	return &current, nil
}

func controllerOwned(source *corev1.Secret, app *api.HankoApplication) bool {
	owner := metav1.GetControllerOf(source)
	return source.UID != "" && source.ResourceVersion != "" && owner != nil && owner.UID == app.UID && owner.Name == app.Name && owner.Kind == "HankoApplication" && owner.APIVersion == "hanko.sh/v1alpha1" && source.DeletionTimestamp.IsZero()
}
