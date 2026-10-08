package supervision

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIAMEvidenceDeterministicBoundedAndSecretFree(t *testing.T) {
	const sentinel = "fixture-secret-sentinel"
	digest := string(iamcontract.Hash(iamcontract.Version, "test", "public", nil))
	roles := []api.HankoRole{}
	for i := range 100 {
		roles = append(roles, api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("role-%03d", i), Namespace: "auth", UID: "uid", Generation: 2}, Spec: api.HankoRoleSpec{Attributes: map[string][]string{"secret": {sentinel}}}, Status: api.HankoRoleStatus{ContractVersion: string(iamcontract.Version), BackendKind: "keycloak", EvaluatedGeneration: 2, AppliedGeneration: 1, IntentHash: digest, EvaluatedPlanHash: digest, AppliedPlanHash: digest, ObservedStateHash: digest, DriftState: "InSync", Findings: []api.AuthorizationFinding{{Classification: "unsupported", Message: sentinel, ReadOnly: true}}}})
	}
	servers := []api.HankoResourceServer{{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "auth"}, Status: api.HankoResourceServerStatus{ProviderResourceServerID: sentinel, IntentHash: sentinel, ManagedObjects: api.AuthorizationManagedObjects{Scopes: []api.AuthorizationManagedReference{{Name: sentinel, ID: sentinel}}}, Conditions: []metav1.Condition{{Message: sentinel}}}}}
	a := BuildIAMEvidence(roles, servers)
	slices.Reverse(roles)
	b := BuildIAMEvidence(roles, servers)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) || !a.Truncated || len(a.Resources) != MaxIAMEvidenceResources {
		t.Fatal("connected evidence ordering/count not deterministic")
	}
	if strings.Contains(string(x), sentinel) {
		t.Fatal("private/provider data leaked to connected DTO")
	}
	if len(x) > 128*1024 {
		t.Fatal("connected DTO exceeds byte budget")
	}
}

func TestIAMEvidenceRejectsUntrustedMetadataFields(t *testing.T) {
	const sentinel = "credential-sentinel"
	obj := api.HankoRole{Status: api.HankoRoleStatus{ContractVersion: sentinel, BackendKind: sentinel, IntentHash: sentinel, AppliedPlanHash: sentinel, ObservedStateHash: sentinel, DriftState: sentinel}}
	snapshot := BuildIAMEvidence([]api.HankoRole{obj}, nil)
	data, _ := json.Marshal(snapshot)
	if strings.Contains(string(data), sentinel) || snapshot.Resources[0].DriftState != "Unknown" {
		t.Fatal("unchecked status strings entered connected evidence")
	}
}
