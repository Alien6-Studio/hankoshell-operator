package controller

import (
	"context"
	"errors"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRoleEvidenceFailureAndObservationContract(t *testing.T) {
	for _, outcome := range []string{"manage", "observe-drift", "readback-drift", "incomplete", "write-failed", "invalid-reference", "unsupported", "lossy"} {
		t.Run(outcome, func(t *testing.T) {
			prior := string(iamcontract.Hash(iamcontract.Version, "test", "prior", nil))
			obj := &api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: "role", Namespace: "auth", UID: "role-uid", Generation: 2}, Spec: api.HankoRoleSpec{RealmRef: "realm", Name: "role"}, Status: api.HankoRoleStatus{ContractVersion: string(iamcontract.Version), AppliedGeneration: 1, AppliedPlanHash: prior}}
			realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "realm", Namespace: "auth", UID: "realm-uid", Generation: 1}}
			state := roles.State{Present: true, Owned: true, Observation: successfulIAMObservation()}
			d := &recordingRoleDriver{caps: roles.KeycloakEvidence(), state: &state}
			switch outcome {
			case "observe-drift":
				obj.Labels = map[string]string{importedByLabel: "fixture"}
				state.Observation.Drifted = true
			case "readback-drift":
				state.Observation.Drifted = true
			case "incomplete":
				state.Observation.Complete = false
			case "write-failed":
				d.err = errors.New("fixture-secret-sentinel")
				state.Observation = iamcontract.Observation{}
			case "invalid-reference":
				obj.Spec.RealmRef = "missing"
			case "unsupported":
				d.caps.Supported.RealmRoles = false
			case "lossy":
				d.caps.Findings = []iamcontract.Finding{{Classification: iamcontract.Lossy, ObjectKind: "role", Code: "lossy_mapping", Message: "desired role mapping is lossy"}}
			}
			c := fake.NewClientBuilder().WithScheme(resourceServerScheme(t)).WithObjects(obj, realm).WithStatusSubresource(&api.HankoRole{}).Build()
			r := &HankoRoleReconciler{Client: c, DriverFactory: func(string, map[string]string) roles.Driver { return d }}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			if getErr := c.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); getErr != nil {
				t.Fatal(getErr)
			}
			s := obj.Status
			if s.ObservedGeneration != 2 {
				t.Fatal("processed generation missing")
			}
			if outcome == "invalid-reference" {
				if s.EvaluatedGeneration != 0 || d.writes != 0 {
					t.Fatal("invalid reference claimed evaluation")
				}
			} else if s.EvaluatedGeneration != 2 || !iamcontract.ValidDigest(s.IntentHash) {
				t.Fatal("role evaluation identity missing")
			}
			switch outcome {
			case "manage":
				if err != nil || s.AppliedGeneration != 2 || s.AppliedPlanHash != s.EvaluatedPlanHash || s.DriftState != "InSync" {
					t.Fatal("role Manage proof missing", err)
				}
			case "observe-drift":
				if err != nil || s.AppliedGeneration != 0 || s.AppliedPlanHash != "" || d.writes != 0 || !conditionTrue(s.Conditions, "ObservationSucceeded") || conditionTrue(s.Conditions, "Synced") {
					t.Fatal("Observe drift/application contract violated", err)
				}
			default:
				if err == nil || s.AppliedGeneration != 1 || s.AppliedPlanHash != prior || conditionTrue(s.Conditions, "Synced") {
					t.Fatal("role failure advanced applied proof", err)
				}
			}
			if outcome == "unsupported" || outcome == "lossy" {
				if d.writes != 0 || s.EvaluatedPlanHash != "" || len(s.Findings) == 0 {
					t.Fatal("rejection did not expose bounded findings")
				}
			}
			if outcome == "lossy" && s.Findings[0].Classification != "lossy" {
				t.Fatal("typed lossy finding was reclassified")
			}
			iamconformance.NoSecrets(t, []string{"fixture-secret-sentinel"}, s)
		})
	}
}
