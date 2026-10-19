package controller

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *HankoRealmReconciler) realmReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// Every namespace-local realmRef blocks destructive parent cleanup, including
// Observe resources, terminating children and declarations without a finalizer.
// Keep this inventory exhaustive when adding a realmRef to another API kind.
func realmDependentKinds() []string {
	return []string{"HankoApplication", "HankoServiceAccount", "HankoIssuer", "HankoRole",
		"HankoOrganization", "HankoResourceServer", "HankoWorkloadTrust", "HankoTenant"}
}

func (r *HankoRealmReconciler) realmDeletionBlockers(ctx context.Context, realm *api.HankoRealm) (map[string]int, error) {
	counts := map[string]int{}
	for _, kind := range realmDependentKinds() {
		continuation := ""
		seen := map[string]bool{}
		for {
			page := &unstructured.UnstructuredList{}
			page.SetGroupVersionKind(api.GroupVersion.WithKind(kind + "List"))
			if err := r.realmReader().List(ctx, page, client.InNamespace(realm.Namespace), client.Limit(200), client.Continue(continuation)); err != nil {
				return nil, fmt.Errorf("read %s realm dependency inventory: %w", kind, err)
			}
			for _, object := range page.Items {
				reference, _, err := unstructured.NestedString(object.Object, "spec", "realmRef")
				if err != nil || object.GetNamespace() != realm.Namespace {
					return nil, fmt.Errorf("invalid %s realm dependency inventory", kind)
				}
				if strings.TrimSpace(reference) == realm.Name {
					counts[kind]++
				}
			}
			continuation = page.GetContinue()
			if continuation == "" {
				if remaining := page.GetRemainingItemCount(); remaining != nil && *remaining != 0 {
					return nil, fmt.Errorf("incomplete %s realm dependency inventory", kind)
				}
				break
			}
			if seen[continuation] {
				return nil, fmt.Errorf("repeated %s realm dependency continuation", kind)
			}
			seen[continuation] = true
		}
	}
	return counts, nil
}

func (r *HankoRealmReconciler) waitForRealmDependents(ctx context.Context, realm *api.HankoRealm, counts map[string]int) (ctrl.Result, error) {
	before := realm.DeepCopy()
	realm.Status.Phase = "Reconciling"
	realm.Status.ObservedGeneration = realm.Generation
	setCondition(&realm.Status.Conditions, "Synced", metav1.ConditionFalse, "DependenciesRemain",
		fmt.Sprintf("Remove realm dependents before deleting the provider realm: %v", counts))
	if !reflect.DeepEqual(before.Status, realm.Status) {
		if err := r.Status().Patch(ctx, realm, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("record realm deletion dependency wait: %w", err)
		}
	}
	// An expected dependency wait is not a provider failure. Returning an error
	// here would discard RequeueAfter and start the retry limiter at milliseconds.
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

// Provider preflight can race a switch to Observe or a connection/tenant edit.
// Re-read the live parent immediately before the destructive provider call.
func (r *HankoRealmReconciler) verifyRealmDeletionAuthority(ctx context.Context, expected *api.HankoRealm) error {
	var current api.HankoRealm
	if err := r.realmReader().Get(ctx, client.ObjectKeyFromObject(expected), &current); err != nil {
		return fmt.Errorf("recheck realm deletion authority: %w", err)
	}
	if current.UID != expected.UID || current.Generation != expected.Generation || current.DeletionTimestamp.IsZero() ||
		!controllerutil.ContainsFinalizer(&current, realmFinalizerName) || isImported(current.Labels) ||
		!maps.Equal(current.Labels, expected.Labels) || !maps.Equal(current.Annotations, expected.Annotations) {
		return fmt.Errorf("realm deletion authority changed; retry with current state")
	}
	return nil
}
