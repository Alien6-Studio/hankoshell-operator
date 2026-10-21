//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkIAMStatusEvidence(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	hash := "sha256:" + strings.Repeat("a", 64)
	role := &api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: "evidence-role", Namespace: "auth"}, Spec: api.HankoRoleSpec{RealmRef: "realm", Name: "role"}}
	if err := c.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	role.Status = api.HankoRoleStatus{Phase: "Ready", ObservedGeneration: 1, EvaluatedGeneration: 1, AppliedGeneration: 1, ContractVersion: "hanko.sh/iam-contract/v1alpha1", BackendKind: "keycloak", IntentHash: hash, EvaluatedPlanHash: hash, AppliedPlanHash: hash, ObservedStateHash: hash, ObservationGeneration: 1, ObservationPlanHash: hash, ObservationComplete: true, DriftState: "InSync"}
	for i := range 32 {
		role.Status.Findings = append(role.Status.Findings, api.AuthorizationFinding{Classification: "lossless", ObjectKind: "role", ObjectName: fmt.Sprintf("object-%d", i), Code: "reviewed", Message: strings.Repeat("m", 256)})
	}
	if err := c.Status().Update(ctx, role); err != nil {
		t.Fatal("additive role status rejected", err)
	}
	stored := &api.HankoRole{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(role), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.AppliedGeneration != 1 || stored.Status.ObservedStateHash != hash || !stored.Status.ObservationComplete || len(stored.Status.Findings) != 32 {
		t.Fatal("role evidence pruned by schema")
	}
	stored.Status.Findings = append(stored.Status.Findings, api.AuthorizationFinding{Classification: "unsupported", ObjectKind: "role", ObjectName: "overflow", Code: "overflow"})
	if err := c.Status().Update(ctx, stored); !apierrors.IsInvalid(err) {
		t.Fatal("finding budget not enforced", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(role), stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.ObservedStateHash = "raw-provider-payload"
	if err := c.Status().Update(ctx, stored); !apierrors.IsInvalid(err) {
		t.Fatal("invalid observation digest accepted", err)
	}
	server := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Name: "evidence-server", Namespace: "auth"}, Spec: api.HankoResourceServerSpec{RealmRef: "realm", Audience: "urn:api", ApplicationRef: "app"}}
	if err := c.Create(ctx, server); err != nil {
		t.Fatal(err)
	}
	server.Status = api.HankoResourceServerStatus{Phase: "Ready", ObservedGeneration: 1, EvaluatedGeneration: 1, AppliedGeneration: 1, ContractVersion: "hanko.sh/iam-contract/v1alpha1", BackendKind: "keycloak", IntentHash: hash, EvaluatedPlanHash: hash, AppliedPlanHash: hash, ObservedStateHash: hash, ObservationGeneration: 1, ObservationPlanHash: hash, ObservationComplete: true, DriftState: "InSync"}
	for i := range 64 {
		server.Status.ManagedObjects.Scopes = append(server.Status.ManagedObjects.Scopes, api.AuthorizationManagedReference{Name: fmt.Sprintf("scope-%d", i), ID: fmt.Sprintf("id-%d", i)})
	}
	if err := c.Status().Update(ctx, server); err != nil {
		t.Fatal("additive server status rejected", err)
	}
	server.Status.ManagedObjects.Scopes = append(server.Status.ManagedObjects.Scopes, api.AuthorizationManagedReference{Name: "overflow", ID: "overflow"})
	if err := c.Status().Update(ctx, server); !apierrors.IsInvalid(err) {
		t.Fatal("ownership budget not enforced", err)
	}
}
