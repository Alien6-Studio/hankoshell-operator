package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

type organizationTestDriver struct {
	recordingAuthorizationDriver
	groups    map[string]authorization.OrganizationGroup
	readError error
}

func (d *organizationTestDriver) ReadOrganizationGroup(_ context.Context, _ string, expected authorization.OrganizationGroup) (authorization.OrganizationGroup, error) {
	if d.readError != nil {
		return authorization.OrganizationGroup{}, d.readError
	}
	if d.groups[expected.Ref] != expected {
		return authorization.OrganizationGroup{}, authorization.OrganizationFailure("OrganizationOwnershipConflict")
	}
	return expected, nil
}
func organizationNode(name, parent, path string) *api.HankoOrganization {
	return &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID("uid-" + name), Generation: 1}, Spec: api.HankoOrganizationSpec{RealmRef: "acme", Name: name, ParentRef: parent}, Status: api.HankoOrganizationStatus{Phase: "Error", GroupID: "group-" + name, GroupPath: path, ObservedGeneration: 1, Conditions: []metav1.Condition{{Type: "Synced", Status: metav1.ConditionTrue, ObservedGeneration: 1}, {Type: "Projection", Status: metav1.ConditionFalse}}}}
}
func organizationProof(o *api.HankoOrganization) authorization.OrganizationGroup {
	return authorization.OrganizationGroup{Ref: o.Name, Namespace: o.Namespace, UID: string(o.UID), ID: o.Status.GroupID, Name: o.Spec.Name, Path: o.Status.GroupPath}
}
func organizationTestReconciler(t *testing.T, descendants bool) (*HankoResourceServerReconciler, *api.HankoResourceServer, *organizationTestDriver) {
	t.Helper()
	rs, objects := validResourceServerObjects(ModeManage)
	rs.Spec.Permissions[0].Principals = []api.AuthorizationPrincipal{{Kind: "organization", Ref: "europe", IncludeDescendants: descendants}}
	driver := &organizationTestDriver{groups: map[string]authorization.OrganizationGroup{}}
	driver.capabilities = supportedAuthorizationCapabilities()
	driver.capabilities.OrganizationPrincipals = true
	driver.capabilities.OrganizationDescendants = true
	for _, o := range []*api.HankoOrganization{organizationNode("europe", "", "/europe"), organizationNode("france", "europe", "/europe/france"), organizationNode("paris", "france", "/europe/france/paris"), organizationNode("germany", "europe", "/europe/germany"), organizationNode("prefix", "", "/europe-sibling")} {
		if o.Name == "prefix" {
			o.Spec.Name = "europe-sibling"
		}
		objects = append(objects, o)
		driver.groups[o.Name] = organizationProof(o)
	}
	c := fake.NewClientBuilder().WithScheme(resourceServerScheme(t)).WithObjects(objects...).WithStatusSubresource(&api.HankoResourceServer{}, &api.HankoOrganization{}).WithIndex(&api.HankoResourceServer{}, organizationPrincipalIndex, authorizationProvenanceIndexValues).Build()
	return &HankoResourceServerReconciler{Client: c, APIReader: c, DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}, rs, driver
}

func TestOrganizationResolutionAndDependencyFreshness(t *testing.T) {
	ctx := context.Background()
	r, rs, d := organizationTestReconciler(t, true)
	plan, err := r.compileAuthorizationPlan(ctx, rs, d, ModeManage)
	if err != nil {
		t.Fatal(err)
	}
	// Direct resolution, including an optional failed projection, is independently valid.
	resolver := organizationGrantResolver{reader: r.APIReader, provider: d, namespace: rs.Namespace, realm: rs.Spec.RealmRef}
	p, err := resolver.resolve(ctx, api.AuthorizationPrincipal{Kind: "organization", Ref: "europe"})
	if err != nil || len(p.Organization.Groups) != 1 {
		t.Fatal("direct-only expansion", err)
	}
	p, err = resolver.resolve(ctx, rs.Spec.Permissions[0].Principals[0])
	if err != nil || len(p.Organization.Groups) != 4 {
		t.Fatal("declared descendant expansion", err)
	}
	for _, g := range p.Organization.Groups {
		if g.Ref == "prefix" {
			t.Fatal("prefix group included")
		}
	}
	spain := organizationNode("spain", "europe", "/europe/spain")
	d.groups[spain.Name] = organizationProof(spain)
	if err := r.Create(ctx, spain); err != nil {
		t.Fatal(err)
	}
	next, err := r.compileAuthorizationPlan(ctx, rs, d, ModeManage)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Identity().Intent != next.Identity().Intent || plan.Identity().Plan == next.Identity().Plan || !errors.Is(plan.Validate(next), iamcontract.ErrStale) {
		t.Fatal("new child did not stale the provider plan independently of portable intent")
	}
	requests := r.organizationRequests(ctx, spain)
	if len(requests) != 1 || requests[0].Name != rs.Name {
		t.Fatal("new child did not requeue organization-principal consumer")
	}
	if err := r.Delete(ctx, spain); err != nil {
		t.Fatal(err)
	}
	restored, err := r.compileAuthorizationPlan(ctx, rs, d, ModeManage)
	if err != nil || restored.Identity() != plan.Identity() {
		t.Fatal("complete graph deletion did not restore original plan", err)
	}
}

func TestOrganizationResolutionRefusesUnsafeDependenciesBeforeWrites(t *testing.T) {
	for _, test := range []struct {
		name, code string
		mutate     func(*api.HankoOrganization)
	}{
		{"realm", "OrganizationRealmMismatch", func(o *api.HankoOrganization) { o.Spec.RealmRef = "other" }},
		{"uid", "OrganizationNotCurrent", func(o *api.HankoOrganization) { o.UID = "" }},
		{"generation", "OrganizationNotCurrent", func(o *api.HankoOrganization) { o.Generation++ }},
		{"condition", "OrganizationNotCurrent", func(o *api.HankoOrganization) { o.Status.Conditions[0].ObservedGeneration = 0 }},
		{"path", "OrganizationHierarchyMismatch", func(o *api.HankoOrganization) { o.Status.GroupPath = "/wrong" }},
		{"cycle", "OrganizationHierarchyCycle", func(o *api.HankoOrganization) { o.Spec.ParentRef = "paris" }},
		{"unsafe name", "OrganizationHierarchyMismatch", func(o *api.HankoOrganization) { o.Spec.Name = "europe/foreign" }},
		{"status locator spoof", "OrganizationOwnershipConflict", func(o *api.HankoOrganization) { o.Status.GroupID = "foreign-group" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, rs, d := organizationTestReconciler(t, true)
			var o api.HankoOrganization
			if err := r.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "europe"}, &o); err != nil {
				t.Fatal(err)
			}
			// A separate APIReader models fresh authority despite the client's old cached object.
			test.mutate(&o)
			var all api.HankoOrganizationList
			if err := r.List(context.Background(), &all); err != nil {
				t.Fatal(err)
			}
			_, objects := validResourceServerObjects(ModeManage)
			for i := range all.Items {
				v := &all.Items[i]
				if v.Name == o.Name {
					v = &o
				}
				objects = append(objects, v)
			}
			r.APIReader = resourceServerClient(t, objects...)
			_, err := r.compileAuthorizationPlan(context.Background(), rs, d, ModeManage)
			var failure authorization.OrganizationError
			if !errors.As(err, &failure) || failure.Code != test.code || len(d.reconcile) != 0 {
				t.Fatalf("refusal %v, expected %s", err, test.code)
			}
		})
	}
}

func TestMissingOrganizationReadPreservesHistoricalAppliedEvidence(t *testing.T) {
	r, rs, d := organizationTestReconciler(t, true)
	ctx := context.Background()
	hash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rs.Status.ContractVersion = string(iamcontract.Version)
	rs.Status.AppliedGeneration = 1
	rs.Status.AppliedPlanHash = hash
	if err := r.Status().Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
	d.readError = authorization.OrganizationFailure("OrganizationReadUnavailable")
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rs)})
	if err == nil || len(d.reconcile) != 0 {
		t.Fatal("unreadable groups mutated authorization")
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(rs), rs); err != nil {
		t.Fatal(err)
	}
	if rs.Status.AppliedPlanHash != hash || rs.Status.AppliedGeneration != 1 || rs.Status.Phase != "Error" || len(rs.Status.Findings) != 1 || rs.Status.Findings[0].Code != "OrganizationReadUnavailable" {
		t.Fatal("historical proof or bounded refusal differs", rs.Status)
	}
}

func TestOrganizationExecutionRechecksFreshDependencyAfterCompile(t *testing.T) {
	r, rs, d := organizationTestReconciler(t, true)
	ctx := context.Background()
	d.capabilityHook = func() {
		// Compilation has already read the original graph/provider proof.
		// Change an existing child before execution's uncached revalidation.
		var child api.HankoOrganization
		key := client.ObjectKey{Namespace: rs.Namespace, Name: "france"}
		if err := r.Get(ctx, key, &child); err != nil {
			t.Fatal(err)
		}
		child.Generation++
		if err := r.Update(ctx, &child); err != nil {
			t.Fatal(err)
		}
	}
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rs)})
	if err == nil || len(d.reconcile) != 0 {
		t.Fatal("changed dependency executed a stale provider plan")
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(rs), rs); err != nil {
		t.Fatal(err)
	}
	if rs.Status.AppliedPlanHash != "" || rs.Status.Phase != "Error" || len(rs.Status.Findings) != 1 || rs.Status.Findings[0].Code != "OrganizationNotCurrent" {
		t.Fatal("stale dependency certified current application")
	}
}

func TestOrganizationWatchExcludesOtherNamespacesAndNonConsumers(t *testing.T) {
	r, rs, _ := organizationTestReconciler(t, true)
	r.Client = cacheContinuationClient{Client: r.Client}
	other := rs.DeepCopy()
	other.Namespace = "unrelated"
	other.ResourceVersion = ""
	nonConsumer := rs.DeepCopy()
	nonConsumer.Name += "-workload-only"
	nonConsumer.ResourceVersion = ""
	nonConsumer.Spec.Permissions[0].Principals = []api.AuthorizationPrincipal{{Kind: "service_account", Ref: "workload"}}
	for _, candidate := range []*api.HankoResourceServer{other, nonConsumer} {
		if err := r.Create(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	requests := r.organizationRequests(context.Background(), organizationNode("new-child", "europe", "/europe/new-child"))
	if len(requests) != 1 || requests[0].NamespacedName != client.ObjectKeyFromObject(rs) {
		t.Fatal("organization watch escaped namespace/explicit-principal boundary")
	}
}

type cacheContinuationClient struct {
	client.Client
}

func (c cacheContinuationClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	list.SetContinue("continue-not-supported")
	return nil
}

func TestOrganizationWatchRefusesOversizedCachedConsumerSet(t *testing.T) {
	r, rs, _ := organizationTestReconciler(t, true)
	r.Client = cacheContinuationClient{Client: r.Client}
	for i := range maxOrganizationInventory {
		other := rs.DeepCopy()
		other.Name = fmt.Sprintf("consumer-%d", i)
		other.ResourceVersion = ""
		other.UID = ""
		if err := r.Create(context.Background(), other); err != nil {
			t.Fatal(err)
		}
	}
	if requests := r.organizationRequests(context.Background(), organizationNode("europe", "", "/europe")); len(requests) != 0 {
		t.Fatal("oversized cached dependency inventory was partially enqueued")
	}
}

func TestResourceServerWatchFiltersOnlyStatusEchoes(t *testing.T) {
	old := &api.HankoResourceServer{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
	for _, test := range []struct {
		name   string
		wake   bool
		change func(*api.HankoResourceServer)
	}{
		{"status", false, func(o *api.HankoResourceServer) { o.Status.ObservedGeneration = 1 }},
		{"spec generation", true, func(o *api.HankoResourceServer) { o.Generation++ }},
		{"manual request", true, func(o *api.HankoResourceServer) { o.Annotations = map[string]string{reconcileRequestAnnotation: "new"} }},
		{"credential authority", true, func(o *api.HankoResourceServer) { o.Labels = map[string]string{"hanko.sh/tenant": "new"} }},
		{"deletion", true, func(o *api.HankoResourceServer) { now := metav1.Now(); o.DeletionTimestamp = &now }},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := old.DeepCopy()
			test.change(next)
			if resourceServerAuthorityChanged().Update(event.UpdateEvent{ObjectOld: old, ObjectNew: next}) != test.wake {
				t.Fatal("ResourceServer event authority contract differs")
			}
		})
	}
}

func TestOrganizationHierarchyBudgetsAndRecreation(t *testing.T) {
	ctx := context.Background()
	for _, count := range []int{129, 34} {
		r, rs, d := organizationTestReconciler(t, true)
		parent, path := "europe", "/europe"
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("added-%03d", i)
			nextPath := path + "/" + name
			o := organizationNode(name, parent, nextPath)
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
			d.groups[name] = organizationProof(o)
			if count == 34 {
				parent, path = name, nextPath
			}
		}
		_, err := r.compileAuthorizationPlan(ctx, rs, d, ModeManage)
		var refusal authorization.OrganizationError
		if !errors.As(err, &refusal) || (refusal.Code != "OrganizationExpansionTooLarge" && refusal.Code != "OrganizationHierarchyTooDeep") {
			t.Fatal("unbounded hierarchy accepted", err)
		}
	}
	r, rs, d := organizationTestReconciler(t, false)
	var org api.HankoOrganization
	key := client.ObjectKey{Namespace: "default", Name: "europe"}
	if err := r.Get(ctx, key, &org); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, &org); err != nil {
		t.Fatal(err)
	}
	org.ResourceVersion = ""
	org.UID = "recreated-uid"
	if err := r.Create(ctx, &org); err != nil {
		t.Fatal(err)
	}
	_, err := r.compileAuthorizationPlan(ctx, rs, d, ModeManage)
	var refusal authorization.OrganizationError
	if !errors.As(err, &refusal) || refusal.Code != "OrganizationOwnershipConflict" {
		t.Fatal("new UID adopted old provider group", err)
	}
}
