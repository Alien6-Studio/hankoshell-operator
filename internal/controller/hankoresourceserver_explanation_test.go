package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestExplanationFailureAndForgedStatusCannotControlAuthorization(t *testing.T) {
	obj, objects := validResourceServerObjects(ModeManage)
	group := organizationNode("europe", "", "/europe")
	objects = append(objects, group)
	c := resourceServerClient(t, objects...)
	driver := &organizationTestDriver{groups: map[string]authorization.OrganizationGroup{"europe": organizationProof(group)}}
	driver.capabilities = supportedAuthorizationCapabilities()
	driver.state = authorization.State{Observation: successfulIAMObservation(), Capabilities: driver.capabilities, Structure: &authorization.StructuralObservation{Enabled: true, Complete: true,
		Resources:   []authorization.ObservedResource{{Name: "invoices", Present: true, Scopes: []string{"invoices:read"}}},
		Policies:    []authorization.ObservedPolicy{{Name: "readers#role:billing-reader", Type: "role", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Present: true, Owned: true, Principals: []string{"realm_role/billing-reader/required=false"}}},
		Permissions: []authorization.ObservedPermission{{Name: "readers", Type: "scope", Logic: "POSITIVE", DecisionStrategy: "AFFIRMATIVE", Present: true, Owned: true, Resources: []string{"invoices"}, Scopes: []string{"invoices:read"}, Policies: []string{"readers#role:billing-reader"}}}}}
	driver.readError = authorization.OrganizationFailure("OrganizationReadUnavailable")
	r := &HankoResourceServerReconciler{Client: c, APIReader: c, DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, obj); err != nil {
		t.Fatal(err)
	}
	if !conditionTrue(obj.Status.Conditions, "Synced") || conditionTrue(obj.Status.Conditions, "AuthorizationExplained") || obj.Status.AuthorizationExplanation == nil || obj.Status.AuthorizationExplanation.Complete {
		t.Fatal("optional provenance affected synchronization")
	}
	first := obj.Status.AuthorizationExplanation.ExplanationHash
	obj.Status.AuthorizationExplanation.ExplanationHash = "forged"
	obj.Status.AuthorizationExplanation.Paths[0].SourceRef = "foreign-forged"
	obj.Status.AuthorizationExplanation.Complete = true
	if err := c.Status().Update(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, obj); err != nil {
		t.Fatal(err)
	}
	if obj.Status.AuthorizationExplanation.ExplanationHash != first {
		t.Fatal("status tampering influenced fresh explanation")
	}
	old := obj.Status.AuthorizationExplanation.DeepCopy()
	driver.err = errors.New("untrusted-provider-secret-sentinel")
	if _, err := r.Reconcile(context.Background(), req); err == nil {
		t.Fatal("provider failure ignored")
	}
	if err := c.Get(context.Background(), req.NamespacedName, obj); err != nil {
		t.Fatal(err)
	}
	if obj.Status.AuthorizationExplanation.ExplanationHash != old.ExplanationHash || conditionTrue(obj.Status.Conditions, "AuthorizationExplained") {
		t.Fatal("historical explanation erased or labelled current")
	}
	if len(driver.deleted) != 0 {
		t.Fatal("explanation authorized deletion")
	}
}
