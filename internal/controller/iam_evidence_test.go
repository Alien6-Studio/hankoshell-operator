package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestResourceServerEvidenceFailureAndObservationContract(t *testing.T) {
	for _, outcome := range []string{"manage", "observe", "observe-drift", "readback-drift", "incomplete", "write-failed", "invalid-reference", "unsupported", "oversized-ownership"} {
		t.Run(outcome, func(t *testing.T) {
			obj, objects := validResourceServerObjects(ModeManage)
			obj.Generation = 2
			prior := string(iamcontract.Hash(iamcontract.Version, "test", "prior-applied", nil))
			obj.Status = api.HankoResourceServerStatus{ContractVersion: string(iamcontract.Version), AppliedGeneration: 1, AppliedPlanHash: prior}
			state := authorization.State{Observation: successfulIAMObservation(), ProviderResourceServerID: "provider-id", Capabilities: supportedAuthorizationCapabilities(), ManagedObjects: authorization.ManagedObjects{ResourceServerID: "provider-id"}}
			d := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), state: state}
			switch outcome {
			case "observe", "observe-drift":
				obj.Spec.Mode = ModeObserve
				d.state.Observation.Drifted = outcome == "observe-drift"
			case "readback-drift":
				d.state.Observation.Drifted = true
			case "incomplete":
				d.state.Observation.Complete = false
			case "write-failed":
				d.err = errors.New("fixture-secret-sentinel")
				d.state.Observation = iamcontract.Observation{}
			case "invalid-reference":
				obj.Spec.ApplicationRef = "missing"
			case "unsupported":
				d.capabilities.ResourceObjects = false
			case "oversized-ownership":
				d.state.ManagedObjects.Scopes = make([]authorization.ManagedReference, 65)
			}
			c := resourceServerClient(t, objects...)
			r := &HankoResourceServerReconciler{Client: c, DriverFactory: func(string, map[string]string) authorization.Driver { return d }}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			var got api.HankoResourceServer
			if getErr := c.Get(context.Background(), client.ObjectKeyFromObject(obj), &got); getErr != nil {
				t.Fatal(getErr)
			}
			s := got.Status
			if s.ObservedGeneration != 2 {
				t.Fatal("processed generation omitted on success/failure")
			}
			if outcome == "invalid-reference" {
				if s.EvaluatedGeneration != 0 || s.IntentHash != "" || len(d.reconcile) != 0 {
					t.Fatal("unresolved reference claimed complete evaluation")
				}
			} else if s.EvaluatedGeneration != 2 || !iamcontract.ValidDigest(s.IntentHash) {
				t.Fatal("evaluation identity missing")
			}
			switch outcome {
			case "manage":
				if err != nil || s.AppliedGeneration != 2 || s.AppliedPlanHash != s.EvaluatedPlanHash || s.DriftState != "InSync" || !s.ObservationComplete {
					t.Fatal("Manage did not prove application", err)
				}
			case "observe", "observe-drift":
				if err != nil || s.AppliedGeneration != 0 || s.AppliedPlanHash != "" || len(d.reconcile) != 0 || !conditionTrue(s.Conditions, "ObservationSucceeded") {
					t.Fatal("Observe application/write claim", err)
				}
				if outcome == "observe-drift" && (s.DriftState != "Drifted" || conditionTrue(s.Conditions, "Synced")) {
					t.Fatal("successful observation hid drift")
				}
			default:
				if err == nil || s.AppliedGeneration != 1 || s.AppliedPlanHash != prior || conditionTrue(s.Conditions, "Synced") {
					t.Fatal("failed attempt advanced application proof", err)
				}
			}
			if outcome == "unsupported" && (s.EvaluatedPlanHash != "" || len(s.Findings) == 0 || len(d.reconcile) != 0) {
				t.Fatal("unsupported evaluation lacked refusal evidence")
			}
			iamconformance.NoSecrets(t, []string{"fixture-secret-sentinel"}, s)
		})
	}
}

func TestReferenceOnlyChangeProducesNewPlanEvidence(t *testing.T) {
	obj, objects := validResourceServerObjects(ModeManage)
	c := resourceServerClient(t, objects...)
	d := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), state: authorization.State{Observation: successfulIAMObservation()}}
	r := &HankoResourceServerReconciler{Client: c, DriverFactory: func(string, map[string]string) authorization.Driver { return d }}
	p, err := r.compileAuthorizationPlan(context.Background(), obj, d, ModeManage)
	if err != nil {
		t.Fatal(err)
	}
	var app api.HankoApplication
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.ApplicationRef}, &app); err != nil {
		t.Fatal(err)
	}
	app.Generation++
	if err := c.Update(context.Background(), &app); err != nil {
		t.Fatal(err)
	}
	q, err := r.compileAuthorizationPlan(context.Background(), obj, d, ModeManage)
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity().Intent != q.Identity().Intent || p.Identity().Plan == q.Identity().Plan || !errors.Is(p.Validate(q), iamcontract.ErrStale) {
		t.Fatal("reference-only change did not change provider-plan identity")
	}
}

func TestIAMFindingsAndOwnershipEvidenceBudgets(t *testing.T) {
	findings := make([]iamcontract.Finding, 100)
	for i := range findings {
		findings[i] = iamcontract.Finding{Classification: iamcontract.Unsupported, ObjectKind: "policy", ObjectName: strings.Repeat("x", 300), Code: strings.Repeat("y", 100) + string(rune('A'+i)), Message: strings.Repeat("m", 1000), ReadOnly: true}
	}
	bounded := findingsStatus(findings)
	if len(bounded) > iamcontract.MaxFindings {
		t.Fatal("findings exceed count budget")
	}
	for _, f := range bounded {
		if len(f.Message) > 256 || len(f.ObjectName) > 255 || len(f.Code) > 64 {
			t.Fatal("findings exceed text budget")
		}
	}
	if authorization.BoundedManagedObjects(authorization.ManagedObjects{Policies: make([]authorization.ManagedReference, 257)}) {
		t.Fatal("ownership was silently truncated")
	}
}

func TestLegacyAppliedHashIsNotUpgradedWithoutReadback(t *testing.T) {
	obj, objects := validResourceServerObjects(ModeManage)
	obj.Status.AppliedPlanHash = "legacy-write-acknowledgement"
	d := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities(), err: errors.New("provider unavailable")}
	c := resourceServerClient(t, objects...)
	r := &HankoResourceServerReconciler{Client: c, DriverFactory: func(string, map[string]string) authorization.Driver { return d }}
	_, _ = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
		t.Fatal(err)
	}
	if obj.Status.AppliedPlanHash != "" || obj.Status.AppliedGeneration != 0 {
		t.Fatal("legacy HTTP acknowledgement became new application proof")
	}
}

func TestStalePlanHasBoundedPublicReason(t *testing.T) {
	obj, objects := validResourceServerObjects(ModeManage)
	c := resourceServerClient(t, objects...)
	d := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
	d.capabilityHook = func() {
		var app api.HankoApplication
		key := client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.ApplicationRef}
		if err := c.Get(context.Background(), key, &app); err != nil {
			t.Fatal(err)
		}
		app.Generation++
		if err := c.Update(context.Background(), &app); err != nil {
			t.Fatal(err)
		}
	}
	r := &HankoResourceServerReconciler{Client: c, DriverFactory: func(string, map[string]string) authorization.Driver { return d }}
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	if !errors.Is(err, iamcontract.ErrStale) || result.RequeueAfter == 0 || len(d.reconcile) != 0 {
		t.Fatal("stale attempt did not fail before mutation")
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
		t.Fatal(err)
	}
	for _, condition := range obj.Status.Conditions {
		if condition.Type == "Synced" && (condition.Reason != "StalePlan" || condition.Status != metav1.ConditionFalse) {
			t.Fatal("stale public status missing")
		}
	}
}
