package controller

import (
	"context"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const operationalInventoryLimit = 1000

// OperationalInventory makes at most three namespace-scoped, limited API reads
// every 30 seconds on the elected replica. It never reads Secrets or retains CRs.
type OperationalInventory struct {
	reader    client.Reader
	namespace string
}

func NewOperationalInventory(reader client.Reader, namespace string) *OperationalInventory {
	return &OperationalInventory{reader: reader, namespace: namespace}
}
func (*OperationalInventory) NeedLeaderElection() bool { return true }
func (i *OperationalInventory) Start(ctx context.Context) error {
	defer observability.Default.Inventory(false, nil, nil, nil)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		i.sample(ctx, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (i *OperationalInventory) sample(parent context.Context, now time.Time) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	instances := &api.HankoKeycloakInstanceList{}
	apps := &api.HankoApplicationList{}
	accounts := &api.HankoServiceAccountList{}
	opts := []client.ListOption{client.InNamespace(i.namespace), client.Limit(operationalInventoryLimit)}
	for _, list := range []client.ObjectList{instances, apps, accounts} {
		if err := i.reader.List(ctx, list, opts...); err != nil || list.GetContinue() != "" {
			observability.Default.Inventory(false, nil, nil, nil)
			return
		}
	}
	// Defend against readers ignoring Limit without processing a partial snapshot.
	if len(instances.Items) > operationalInventoryLimit || len(apps.Items) > operationalInventoryLimit || len(accounts.Items) > operationalInventoryLimit {
		observability.Default.Inventory(false, nil, nil, nil)
		return
	}
	states := map[string]int{}
	rotations := map[string]map[string]int{}
	overdue := map[string]float64{}
	rotation := func(kind string, enabled bool, next *metav1.Time, conditions []metav1.Condition) {
		if !enabled {
			return
		}
		if rotations[kind] == nil {
			rotations[kind] = map[string]int{}
		}
		state := "scheduled"
		if next != nil && now.After(next.Time) {
			state = "overdue"
			overdue[kind] = max(overdue[kind], now.Sub(next.Time).Seconds())
		}
		for _, condition := range conditions {
			if condition.Status == metav1.ConditionFalse && (condition.Type == "CredentialRotationReady" || condition.Reason == "SecretRotationFailed" || condition.Reason == "SecretRotationRecoveryRequired" || condition.Reason == "RotationFailed") {
				state = "failed"
			}
		}
		rotations[kind][state]++
	}
	for index := range instances.Items {
		item := &instances.Items[index]
		state := "pending"
		switch item.Status.Phase {
		case "Ready":
			state = "ready"
		case "Degraded", "Error":
			state = "degraded"
		}
		states[state]++
		rotation("HankoKeycloakInstance", item.Spec.RotateAdminCredentials, item.Status.NextCredentialRotation, item.Status.Conditions)
	}
	for index := range apps.Items {
		item := &apps.Items[index]
		rotation("HankoApplication", item.Spec.SecretRotationPolicy != nil && item.Spec.SecretRotationPolicy.Enabled, item.Status.NextRotation, item.Status.Conditions)
	}
	for index := range accounts.Items {
		item := &accounts.Items[index]
		rotation("HankoServiceAccount", item.Spec.SecretRotationPolicy != nil && item.Spec.SecretRotationPolicy.Enabled, item.Status.NextRotation, item.Status.Conditions)
	}
	observability.Default.Inventory(true, states, rotations, overdue)
}
