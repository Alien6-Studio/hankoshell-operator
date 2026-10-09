//go:build integration

package v1alpha1_test

import (
	"context"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func checkOrganizationPrincipalAdmission(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	for _, test := range []struct {
		name, kind, ref      string
		descendants, invalid bool
	}{
		{"org-direct", "organization", "europe", false, false},
		{"org-descendants", "organization", "europe", true, false},
		{"org-role-invalid", "realm_role", "reader", true, true},
		{"org-application-invalid", "application", "app", true, true},
		{"org-service-invalid", "service_account", "worker", true, true},
		{"org-provider-path-invalid", "organization", "/Europe", false, true},
	} {
		rs := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Name: test.name, Namespace: "auth"}, Spec: api.HankoResourceServerSpec{RealmRef: "realm", ApplicationRef: "app", Audience: "urn:" + test.name, Scopes: []api.AuthorizationScope{{Name: "read"}}, Permissions: []api.AuthorizationPermission{{Name: "read", Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: test.kind, Ref: test.ref, IncludeDescendants: test.descendants}}}}}}
		err := c.Create(ctx, rs)
		if test.invalid {
			if !apierrors.IsInvalid(err) {
				t.Fatal("unsafe principal admitted", test.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var stored api.HankoResourceServer
		if err := c.Get(ctx, client.ObjectKeyFromObject(rs), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Spec.Permissions[0].Principals[0].IncludeDescendants != test.descendants {
			t.Fatal("descendant semantics pruned")
		}
		stored.Status.Capabilities.OrganizationPrincipals = true
		stored.Status.Capabilities.OrganizationDescendants = true
		if err := c.Status().Update(ctx, &stored); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(rs), &stored); err != nil {
			t.Fatal(err)
		}
		if !stored.Status.Capabilities.OrganizationPrincipals || !stored.Status.Capabilities.OrganizationDescendants {
			t.Fatal("additive capability snapshot pruned")
		}
		// A v0.3 controller/status client must still be able to write the old
		// capability snapshot without fields introduced by this source change.
		legacy := client.RawPatch(types.MergePatchType, []byte(`{"status":{"capabilities":{"organizationPrincipals":null,"organizationDescendants":null}}}`))
		if err := c.Status().Patch(ctx, &stored, legacy); err != nil {
			t.Fatal("legacy capability snapshot rejected", err)
		}
		duplicate := stored.DeepCopy()
		duplicate.Name = test.name + "-duplicate"
		duplicate.ResourceVersion = ""
		duplicate.UID = ""
		duplicate.Spec.Audience = "urn:" + duplicate.Name
		duplicate.Spec.Permissions[0].Principals = append(duplicate.Spec.Permissions[0].Principals, api.AuthorizationPrincipal{Kind: "organization", Ref: "europe", IncludeDescendants: !test.descendants})
		if err := c.Create(ctx, duplicate); !apierrors.IsInvalid(err) {
			t.Fatal("contradictory map-list forms admitted", err)
		}
	}
}

// The API/watch boundary uses a synthetic driver. Actual provider ownership,
// policy and UMA semantics are independently covered by both HTTPS versions.
type organizationWatchDriver struct{ plans chan iamcontract.PlanIdentity }

func (*organizationWatchDriver) Capabilities(context.Context, string) (authorization.Capabilities, error) {
	return authorization.Capabilities{ScopeGrants: true, OrganizationPrincipals: true, OrganizationDescendants: true}, nil
}
func (*organizationWatchDriver) ReadOrganizationGroup(_ context.Context, _ string, g authorization.OrganizationGroup) (authorization.OrganizationGroup, error) {
	return g, nil
}
func (d *organizationWatchDriver) Observe(context.Context, authorization.Plan) (authorization.State, error) {
	return d.state(), nil
}
func (d *organizationWatchDriver) Reconcile(_ context.Context, p authorization.Plan, _ authorization.ManagedObjects) (authorization.State, error) {
	select {
	case d.plans <- p.Identity():
	default:
	}
	return d.state(), nil
}
func (*organizationWatchDriver) DeleteOwned(context.Context, authorization.Model, authorization.ManagedObjects, string) error {
	return nil
}
func (d *organizationWatchDriver) state() authorization.State {
	caps, _ := d.Capabilities(context.Background(), "")
	return authorization.State{Capabilities: caps, ProviderResourceServerID: "watch-fixture", ManagedObjects: authorization.ManagedObjects{ResourceServerID: "watch-fixture"}, Observation: iamcontract.Observation{Complete: true, StateHash: iamcontract.Hash(iamcontract.Version, "watch-test", "observation", nil)}}
}

func checkOrganizationDependencyWatch(t *testing.T, ctx context.Context, c client.Client, config *rest.Config) {
	t.Helper()
	for _, object := range []client.Object{
		&api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "watch-realm", Namespace: "auth"}},
		&api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "watch-app", Namespace: "auth"}, Spec: api.HankoApplicationSpec{RealmRef: "watch-realm", ClientID: "watch-api", Type: "m2m"}},
	} {
		if err := c.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	createOrg := func(name, parent, path string) *api.HankoOrganization {
		t.Helper()
		o := &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}, Spec: api.HankoOrganizationSpec{RealmRef: "watch-realm", Name: name, ParentRef: parent}}
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
		o.Status = api.HankoOrganizationStatus{GroupID: "provider-" + name, GroupPath: path, ObservedGeneration: o.Generation, Conditions: []metav1.Condition{{Type: "Synced", Status: metav1.ConditionTrue, ObservedGeneration: o.Generation, Reason: "Fixture", LastTransitionTime: metav1.Now()}}}
		if err := c.Status().Update(ctx, o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	createOrg("watch-europe", "", "/watch-europe")
	driver := &organizationWatchDriver{plans: make(chan iamcontract.PlanIdentity, 128)}
	manager, err := ctrl.NewManager(config, ctrl.Options{Scheme: c.Scheme(), Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
	if err != nil {
		t.Fatal(err)
	}
	reconciler := &controller.HankoResourceServerReconciler{Client: manager.GetClient(), DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
	if err := reconciler.SetupWithManager(manager); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- manager.Start(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("watch manager did not stop")
		}
	})
	if !manager.GetCache().WaitForCacheSync(runCtx) {
		t.Fatal("watch cache did not synchronize")
	}
	rs := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Name: "organization-watch", Namespace: "auth"}, Spec: api.HankoResourceServerSpec{RealmRef: "watch-realm", ApplicationRef: "watch-app", Audience: "urn:watch", Scopes: []api.AuthorizationScope{{Name: "read"}}, Permissions: []api.AuthorizationPermission{{Name: "read", Scopes: []string{"read"}, Principals: []api.AuthorizationPrincipal{{Kind: "organization", Ref: "watch-europe", IncludeDescendants: true}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var initial iamcontract.PlanIdentity
	select {
	case initial = <-driver.plans:
	case <-time.After(15 * time.Second):
		t.Fatal("initial organizational plan not applied")
	}
	createOrg("watch-france", "watch-europe", "/watch-europe/watch-france")
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case next := <-driver.plans:
			if next.Plan == initial.Plan {
				continue
			}
			if next.Intent != initial.Intent {
				t.Fatal("dependency watch changed portable intent")
			}
			return
		case <-deadline.C:
			t.Fatal("new previously unknown descendant did not requeue/recompile")
		}
	}
}
