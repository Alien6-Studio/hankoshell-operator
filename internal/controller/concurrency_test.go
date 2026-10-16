package controller

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
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
	options, err := iamControllerOptions()
	if err != nil || options.MaxConcurrentReconciles != 1 {
		t.Fatal("default concurrency changed", options, err)
	}
	for _, value := range []string{"1", "4", "8", "", "0", "9", "-1", "+2", "02", "1.0", " 2", "private-input-sentinel"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(key, value)
			options, err := iamControllerOptions()
			valid := value == "1" || value == "4" || value == "8"
			if (err == nil) != valid || valid && options.MaxConcurrentReconciles < 1 || options.MaxConcurrentReconciles > 8 {
				t.Fatal("invalid worker configuration accepted")
			}
			if err != nil && strings.Contains(err.Error(), "private-input-sentinel") {
				t.Fatal("invalid environment value escaped fixed diagnostic")
			}
		})
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

func TestConcurrencyAndStatusPredicatesAreWiredOnlyToReviewedControllers(t *testing.T) {
	files, err := filepath.Glob("*_controller.go")
	if err != nil {
		t.Fatal(err)
	}
	var concurrent, filtered []string
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
				return true
			})
		}
	}
	slices.Sort(concurrent)
	if !slices.Equal(concurrent, []string{"hankoapplication_controller.go", "hankoorganization_controller.go", "hankoresourceserver_controller.go", "hankorole_controller.go"}) {
		t.Fatal("concurrency widened beyond the reviewed request-local IAM controllers", concurrent)
	}
	for _, file := range []string{"hankoorganization_controller.go", "hankoissuer_controller.go"} {
		if !slices.Contains(filtered, file) {
			t.Fatal("primary status-echo predicate was removed", file)
		}
	}
}
