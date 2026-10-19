package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type inventoryReader struct {
	client.Reader
	calls             int
	truncated, failed bool
	t                 *testing.T
}

func (r *inventoryReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.calls++
	options := &client.ListOptions{}
	options.ApplyOptions(opts)
	if options.Namespace != "auth" || options.Limit != operationalInventoryLimit {
		r.t.Fatal("inventory list lost its namespace/size boundary")
	}
	if r.failed {
		return errors.New("secret-sentinel")
	}
	if err := r.Reader.List(ctx, list, opts...); err != nil {
		return err
	}
	if r.truncated {
		list.SetContinue("unread-page")
	}
	return nil
}
func TestOperationalInventoryDropsStalePartialAndFailedSamples(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	overdue := metav1.NewTime(now.Add(-time.Hour))
	reader := &inventoryReader{t: t, Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "private-instance", Namespace: "auth"}, Status: api.HankoKeycloakInstanceStatus{Phase: "Degraded"}},
		&api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "private-app", Namespace: "auth"}, Spec: api.HankoApplicationSpec{SecretRotationPolicy: &api.SecretRotationPolicy{Enabled: true}}, Status: api.HankoApplicationStatus{NextRotation: &overdue}},
	).Build()}
	inventory := NewOperationalInventory(reader, "auth")
	registry := prometheus.NewRegistry()
	observability.Default.Register(registry)
	complete := func() float64 {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() == "hanko_operator_inventory_complete" {
				return family.Metric[0].Gauge.GetValue()
			}
		}
		t.Fatal("missing completeness")
		return -1
	}
	inventory.sample(context.Background(), now)
	if reader.calls != 3 || complete() != 1 {
		t.Fatal("complete bounded sample not published")
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() == "hanko_operator_rotation_overdue_seconds" {
			for _, metric := range family.Metric {
				if metric.Gauge.GetValue() == 3600 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("overdue enabled rotation not measured")
	}
	reader.truncated = true
	inventory.sample(context.Background(), now)
	if complete() != 0 {
		t.Fatal("truncated sample preserved healthy state")
	}
	reader.truncated = false
	reader.failed = true
	inventory.sample(context.Background(), now)
	if complete() != 0 {
		t.Fatal("failed sample preserved healthy state")
	}
}
