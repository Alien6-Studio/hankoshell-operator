package controller

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestIAMConcurrencyIsBoundedAndDoesNotEchoInput(t *testing.T) {
	key := "HANKO_IAM_MAX_CONCURRENT_RECONCILES"
	t.Setenv(key, "1")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	options, err := iamControllerOptions("Application")
	if err != nil || options.MaxConcurrentReconciles != 1 {
		t.Fatal("default concurrency changed", options, err)
	}
	if options.UsePriorityQueue == nil || !*options.UsePriorityQueue || options.NewQueue == nil || options.RateLimiter == nil {
		t.Fatal("IAM recovery needs normalized initial-list priority and the existing retry limiter")
	}
	for _, value := range []string{"1", "4", "8", "", "0", "9", "-1", "+2", "02", "1.0", " 2", "private-input-sentinel"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(key, value)
			options, err := iamControllerOptions("Application")
			valid := value == "1" || value == "4" || value == "8"
			if (err == nil) != valid || valid && options.MaxConcurrentReconciles < 1 || options.MaxConcurrentReconciles > 8 {
				t.Fatal("invalid worker configuration accepted")
			}
			if err != nil && strings.Contains(err.Error(), "private-input-sentinel") {
				t.Fatal("invalid environment value escaped fixed diagnostic")
			}
			if valid && (options.UsePriorityQueue == nil || !*options.UsePriorityQueue || options.NewQueue == nil) {
				t.Fatal("worker configuration bypassed the IAM scheduler")
			}
		})
	}
}

func TestIAMPerKindWorkersAreBoundedIsolatedAndInheritTheGlobalDefault(t *testing.T) {
	t.Setenv("HANKO_IAM_MAX_CONCURRENT_RECONCILES", "4")
	kinds := []string{"Application", "Role", "Organization", "ResourceServer"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			key := "HANKO_IAM_" + strings.ToUpper(kind) + "_MAX_CONCURRENT_RECONCILES"
			for _, value := range []string{"1", "8", "", "0", "9", "02", "private-input-sentinel"} {
				t.Run(value, func(t *testing.T) {
					t.Setenv(key, value)
					options, err := iamControllerOptions(kind)
					valid := value == "1" || value == "8"
					if (err == nil) != valid || valid && strconv.Itoa(options.MaxConcurrentReconciles) != value {
						t.Fatal("kind worker override did not enforce its exact bounds")
					}
					if err != nil && strings.Contains(err.Error(), "private-input-sentinel") {
						t.Fatal("override diagnostic echoed an untrusted value")
					}
					for _, other := range kinds {
						if other == kind {
							continue
						}
						inherited, err := iamControllerOptions(other)
						if err != nil || inherited.MaxConcurrentReconciles != 4 {
							t.Fatal("per-kind override changed another controller")
						}
					}
				})
			}
		})
	}
	t.Setenv("HANKO_IAM_MAX_CONCURRENT_RECONCILES", "0")
	t.Setenv("HANKO_IAM_APPLICATION_MAX_CONCURRENT_RECONCILES", "8")
	if _, err := iamControllerOptions("Application"); err == nil {
		t.Fatal("per-kind override masked an invalid global setting")
	}
	if _, err := iamControllerOptions("private-input-sentinel"); err == nil || strings.Contains(err.Error(), "private-input-sentinel") {
		t.Fatal("unreviewed controller was accepted or echoed")
	}
}

func TestIAMSetupRejectsInvalidConcurrencyBeforeUsingManager(t *testing.T) {
	t.Setenv("HANKO_IAM_MAX_CONCURRENT_RECONCILES", "9")
	for _, err := range []error{
		(&HankoApplicationReconciler{}).SetupWithManager(nil),
		(&HankoRoleReconciler{}).SetupWithManager(nil),
		(&HankoOrganizationReconciler{}).SetupWithManager(nil),
		(&HankoResourceServerReconciler{}).SetupWithManager(nil),
	} {
		if err == nil {
			t.Fatal("controller accepted out-of-bounds concurrency")
		}
	}
}

func TestIAMSetupUsesItsOwnKindOverrideBeforeManagerRegistration(t *testing.T) {
	t.Setenv("HANKO_IAM_MAX_CONCURRENT_RECONCILES", "1")
	for _, test := range []struct {
		kind  string
		setup func() error
	}{
		{"Application", func() error { return (&HankoApplicationReconciler{}).SetupWithManager(nil) }},
		{"Role", func() error { return (&HankoRoleReconciler{}).SetupWithManager(nil) }},
		{"Organization", func() error { return (&HankoOrganizationReconciler{}).SetupWithManager(nil) }},
		{"ResourceServer", func() error { return (&HankoResourceServerReconciler{}).SetupWithManager(nil) }},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Setenv("HANKO_IAM_"+strings.ToUpper(test.kind)+"_MAX_CONCURRENT_RECONCILES", "0")
			if err := test.setup(); err == nil {
				t.Fatal("controller registration ignored its own invalid override")
			}
		})
	}
}

func TestOrganizationAndIssuerIgnoreStatusEchoButRetainAuthorityWakes(t *testing.T) {
	predicate := generationOrReconcileRequestChanged()
	for _, object := range []client.Object{&api.HankoOrganization{}, &api.HankoIssuer{}} {
		object.SetGeneration(2)
		statusOnly := object.DeepCopyObject().(client.Object)
		statusOnly.SetResourceVersion("new-status-version")
		switch value := statusOnly.(type) {
		case *api.HankoOrganization:
			value.Status.Phase = "Ready"
			value.Status.LastReconciled = &metav1.Time{Time: metav1.Now().Time}
		case *api.HankoIssuer:
			value.Status.Phase = "Ready"
		}
		if predicate.Update(event.UpdateEvent{ObjectOld: object, ObjectNew: statusOnly}) {
			t.Fatal("status update re-enqueues its own reconciliation")
		}
		for _, key := range []string{"hanko.sh/tenant", importedByLabel} {
			for _, value := range []string{"", "selected"} {
				changed := object.DeepCopyObject().(client.Object)
				changed.SetLabels(map[string]string{key: value})
				if !predicate.Update(event.UpdateEvent{ObjectOld: object, ObjectNew: changed}) || !predicate.Update(event.UpdateEvent{ObjectOld: changed, ObjectNew: object}) {
					t.Fatal("credential authority presence/value change was filtered")
				}
			}
		}
		deleting := object.DeepCopyObject().(client.Object)
		now := metav1.Now()
		deleting.SetDeletionTimestamp(&now)
		if !predicate.Update(event.UpdateEvent{ObjectOld: object, ObjectNew: deleting}) {
			t.Fatal("finalizer wake was filtered")
		}
	}
}

func TestAuthorizationReferencesIgnoreStatusButRetainAllAuthorityChanges(t *testing.T) {
	for _, old := range []client.Object{&api.HankoApplication{}, &api.HankoRealm{}, &api.HankoServiceAccount{}} {
		old.SetGeneration(1)
		old.SetUID("original")
		next := old.DeepCopyObject().(client.Object)
		next.SetResourceVersion("status-update")
		switch object := next.(type) {
		case *api.HankoApplication:
			object.Status.Phase = "Error"
			object.Status.ObservedGeneration = 1
		case *api.HankoRealm:
			object.Status.Phase = "Ready"
			object.Status.ObservedGeneration = 1
		case *api.HankoServiceAccount:
			object.Status.Phase = "Ready"
			object.Status.ObservedGeneration = 1
		}
		if authorizationDependencyChanged().Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}) {
			t.Fatal("provider observation status broadcast to spec-only authorization consumers")
		}
		for _, change := range []func(client.Object){
			func(o client.Object) { o.SetUID("recreated") },
			func(o client.Object) { o.SetGeneration(2) },
			func(o client.Object) { now := metav1.Now(); o.SetDeletionTimestamp(&now) },
			func(o client.Object) { o.SetLabels(map[string]string{"hanko.sh/tenant": ""}) },
			func(o client.Object) { o.SetLabels(map[string]string{importedByLabel: ""}) },
			func(o client.Object) { o.SetLabels(map[string]string{providerConnectionLabel: "connection"}) },
			func(o client.Object) { o.SetAnnotations(map[string]string{reconcileRequestAnnotation: "new"}) },
		} {
			changed := old.DeepCopyObject().(client.Object)
			change(changed)
			if !authorizationDependencyChanged().Update(event.UpdateEvent{ObjectOld: old, ObjectNew: changed}) {
				t.Fatal("reference authority change was filtered")
			}
		}
		if !authorizationDependencyChanged().Create(event.CreateEvent{Object: old}) || !authorizationDependencyChanged().Delete(event.DeleteEvent{Object: old}) {
			t.Fatal("reference creation/deletion was filtered")
		}
	}
}

func TestRealmDefaultRotationChangesWakeConsumersButStatusDoesNot(t *testing.T) {
	old := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
	status := old.DeepCopy()
	status.Status.Phase = "Ready"
	status.Status.LastReconciled = &metav1.Time{Time: metav1.Now().Time}
	if generationOrReconcileRequestChanged().Update(event.UpdateEvent{ObjectOld: old, ObjectNew: status}) {
		t.Fatal("realm status re-enqueued clients inheriting defaults")
	}
	next := old.DeepCopy()
	next.Generation++
	days := 10
	next.Spec.SecurityProfile = &api.RealmSecurityProfile{ClientSecretRotationDays: &days}
	if !generationOrReconcileRequestChanged().Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}) {
		t.Fatal("new realm credential defaults did not wake inheriting clients")
	}
}

func TestConcurrencyAndStatusPredicatesAreWiredOnlyToReviewedControllers(t *testing.T) {
	files, err := filepath.Glob("*_controller.go")
	if err != nil {
		t.Fatal(err)
	}
	var concurrent, filtered, scheduled []string
	dependencyWatches := 0
	for _, file := range files {
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range tree.Decls {
			method, ok := declaration.(*ast.FuncDecl)
			if !ok || method.Name.Name != "SetupWithManager" {
				continue
			}
			ast.Inspect(method.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "iamControllerOptions" {
					concurrent = append(concurrent, file)
				}
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "generationOrReconcileRequestChanged" {
					filtered = append(filtered, file)
				}
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "scheduleIAMReconciler" {
					scheduled = append(scheduled, file)
				}
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "authorizationDependencyChanged" && file == "hankoresourceserver_controller.go" {
					dependencyWatches++
				}
				return true
			})
		}
	}
	slices.Sort(concurrent)
	if !slices.Equal(concurrent, []string{"hankoapplication_controller.go", "hankoorganization_controller.go", "hankoresourceserver_controller.go", "hankorole_controller.go"}) {
		t.Fatal("concurrency widened beyond the reviewed request-local IAM controllers", concurrent)
	}
	slices.Sort(scheduled)
	if !slices.Equal(concurrent, scheduled) {
		t.Fatal("IAM queue priorities and result scheduling must cover the same four controllers", scheduled)
	}
	for _, file := range []string{"hankoorganization_controller.go", "hankoissuer_controller.go"} {
		if !slices.Contains(filtered, file) {
			t.Fatal("primary status-echo predicate was removed", file)
		}
	}
	if dependencyWatches != 5 {
		t.Fatal("authorization dependency watches lack semantic status filtering")
	}
}
