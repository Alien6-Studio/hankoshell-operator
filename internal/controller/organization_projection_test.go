package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type testOrganizationProjector struct {
	ensureCalls, deleteCalls int
	err, deleteErr           error
	parents                  []string
}

func (p *testOrganizationProjector) EnsurePosition(_ context.Context, _ string, s hankoapi.PositionSpec) (string, error) {
	p.ensureCalls++
	p.parents = append(p.parents, s.ParentID)
	if p.err != nil {
		return "", p.err
	}
	return "position-" + s.GroupID, nil
}
func (p *testOrganizationProjector) DeletePosition(context.Context, string, string) error {
	p.deleteCalls++
	return p.deleteErr
}

func organizationTestFixture(t *testing.T) (*controller.HankoOrganizationReconciler, *mockKeycloak, []*api.HankoOrganization) {
	t.Helper()
	m := newMockKeycloak(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/admin/realms/realm" {
			_ = json.NewEncoder(w).Encode(map[string]any{"realm": "realm", "organizationsEnabled": true})
			return
		}
		m.ServeHTTP(w, req)
	}))
	t.Cleanup(server.Close)
	nodes := []*api.HankoOrganization{}
	path := ""
	for i, name := range []string{"root", "child", "grandchild"} {
		parent := ""
		if i > 0 {
			parent = nodes[i-1].Name
		}
		path += "/" + name
		o := &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", UID: types.UID("owner-" + name), Generation: 3}, Spec: api.HankoOrganizationSpec{RealmRef: "realm", Name: name, ParentRef: parent}}
		m.addGroup("realm", keycloak.Group{ID: "group-" + name, Name: name, Path: path, Attributes: testOrganizationOwnership(o)})
		nodes = append(nodes, o)
	}
	m.addOrganization("realm", keycloak.Organization{ID: "native-root", Alias: "root", Name: "root", Enabled: true, Attributes: testOrganizationOwnership(nodes[0])})
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(nodes[0], nodes[1], nodes[2]).WithStatusSubresource(&api.HankoOrganization{}).Build()
	r := &controller.HankoOrganizationReconciler{Client: c, Pool: keycloak.NewPool(keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP())), Recorder: events.NewFakeRecorder(10)}
	return r, m, nodes
}

func runOrganization(t *testing.T, r *controller.HankoOrganizationReconciler, o *api.HankoOrganization) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)}); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), o); err != nil {
		t.Fatal(err)
	}
}

func requireOrganizationCondition(t *testing.T, o *api.HankoOrganization, kind string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	for _, c := range o.Status.Conditions {
		if c.Type == kind {
			if c.Status != status || c.Reason != reason || c.ObservedGeneration != o.Generation {
				t.Fatalf("incorrect %s condition: %+v", kind, c)
			}
			return
		}
	}
	t.Fatalf("missing %s", kind)
}

func TestStandaloneOrganizationHierarchyAndLegacyProjection(t *testing.T) {
	r, m, nodes := organizationTestFixture(t)
	p := &testOrganizationProjector{}
	r.Positions = p
	for _, o := range nodes {
		runOrganization(t, r, o)
		if o.Status.Phase != "Ready" || o.Status.GroupID == "" || o.Status.PositionID != "" {
			t.Fatal("standalone not Ready", o.Status)
		}
		requireOrganizationCondition(t, o, "Synced", metav1.ConditionTrue, "Reconciled")
		requireOrganizationCondition(t, o, "Projection", metav1.ConditionUnknown, "Disabled")
	}
	nodes[0].Status.PositionID = "last-known-position"
	if err := r.Status().Update(context.Background(), nodes[0]); err != nil {
		t.Fatal(err)
	}
	runOrganization(t, r, nodes[0])
	if nodes[0].Status.PositionID != "last-known-position" || p.ensureCalls != 0 || p.deleteCalls != 0 {
		t.Fatal("disabled projection was used or metadata discarded")
	}
	before := m.count("updateOrganization")
	runOrganization(t, r, nodes[0])
	if m.count("updateOrganization") != before {
		t.Fatal("retry mutated matching native organization")
	}
}

func TestConfiguredProjectionFailurePreservesProviderEvidence(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "remote failure", true: "missing client"}[unavailable], func(t *testing.T) {
			r, m, nodes := organizationTestFixture(t)
			r.ProjectionMode = hankoapi.ProjectionEnabled
			p := &testOrganizationProjector{err: errors.New("sentinel-projection-token raw remote payload")}
			if !unavailable {
				r.Positions = p
			}
			runOrganization(t, r, nodes[0])
			o := nodes[0]
			if o.Status.Phase != "Error" || o.Status.GroupID == "" || o.Status.OrgID == "" || o.Status.ObservedGeneration != 3 {
				t.Fatal("provider success was lost", o.Status)
			}
			reason := "ProjectionFailed"
			if unavailable {
				reason = "ProjectorUnavailable"
			}
			requireOrganizationCondition(t, o, "Synced", metav1.ConditionTrue, "Reconciled")
			requireOrganizationCondition(t, o, "Projection", metav1.ConditionFalse, reason)
			data, _ := json.Marshal(o)
			if strings.Contains(string(data), "sentinel-projection-token") {
				t.Fatal("remote credential leaked")
			}
			before := m.count("updateOrganization")
			runOrganization(t, r, o)
			if m.count("updateOrganization") != before {
				t.Fatal("projection retry changed Keycloak")
			}
			runOrganization(t, r, nodes[1])
			if nodes[1].Status.GroupID == "" {
				t.Fatal("parent projection blocked provider hierarchy")
			}
			requireOrganizationCondition(t, nodes[1], "Synced", metav1.ConditionTrue, "Reconciled")
			if !unavailable {
				if nodes[1].Status.Phase != "Pending" {
					t.Fatal("child should wait only for projection")
				}
				requireOrganizationCondition(t, nodes[1], "Projection", metav1.ConditionFalse, "ParentProjectionPending")
			}
		})
	}
}

func TestConnectedOrganizationHierarchyAndDeletionRetries(t *testing.T) {
	r, m, nodes := organizationTestFixture(t)
	r.ProjectionMode = hankoapi.ProjectionEnabled
	p := &testOrganizationProjector{}
	r.Positions = p
	for _, o := range nodes {
		runOrganization(t, r, o)
		requireOrganizationCondition(t, o, "Projection", metav1.ConditionTrue, "Reconciled")
		if o.Status.Phase != "Ready" {
			t.Fatal("connected organization not ready")
		}
	}
	if p.parents[1] != nodes[0].Status.PositionID || p.parents[2] != nodes[1].Status.PositionID {
		t.Fatal("incorrect projected hierarchy")
	}
	for i := len(nodes) - 1; i > 0; i-- {
		child := nodes[i]
		if err := r.Delete(context.Background(), child); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(child)}); err != nil {
			t.Fatal(err)
		}
	}
	priorDeleteCalls := p.deleteCalls
	o := nodes[0]
	p.deleteErr = errors.New("sentinel-projection-token")
	if err := r.Delete(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	runOrganization(t, r, o)
	requireOrganizationCondition(t, o, "Synced", metav1.ConditionTrue, "Deleted")
	requireOrganizationCondition(t, o, "Projection", metav1.ConditionFalse, "ProjectionFailed")
	if m.count("deleteGroup") != 3 || m.count("deleteOrganization") != 1 || len(o.Finalizers) == 0 {
		t.Fatal("provider cleanup did not precede failed projection cleanup")
	}
	runOrganization(t, r, o)
	if m.count("deleteGroup") != 3 || m.count("deleteOrganization") != 1 || p.deleteCalls != priorDeleteCalls+2 {
		t.Fatal("cleanup retry repeated provider mutations")
	}
	p.deleteErr = nil
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)}); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), &api.HankoOrganization{}); !apierrors.IsNotFound(err) {
		t.Fatal("finalizer remained", err)
	}
}

func TestDisabledLegacyPositionDeletionWarnsWithoutAPICall(t *testing.T) {
	r, m, nodes := organizationTestFixture(t)
	o := nodes[0]
	runOrganization(t, r, o)
	o.Status.PositionID = "legacy-position"
	if err := r.Status().Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := &testOrganizationProjector{}
	r.Positions = p
	m.mu.Lock()
	delete(m.groupsByPath, "realm|/root/child")
	delete(m.groupsByPath, "realm|/root/child/grandchild")
	m.mu.Unlock()
	if err := r.Delete(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)}); err != nil {
		t.Fatal(err)
	}
	if p.deleteCalls != 0 || m.count("deleteGroup") != 1 || m.count("deleteOrganization") != 1 {
		t.Fatal("disabled cleanup depended on projection")
	}
	recorder := r.Recorder.(*events.FakeRecorder)
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "ProjectionCleanupSkipped") || strings.Contains(event, "legacy-position") {
			t.Fatal("unexpected warning", event)
		}
	default:
		t.Fatal("external cleanup warning missing")
	}
}

func TestOrganizationDeletionNeverCascadesIntoChildGroups(t *testing.T) {
	for _, child := range []string{"owned child", "foreign child", "child lookup unavailable"} {
		t.Run(child, func(t *testing.T) {
			r, m, nodes := organizationTestFixture(t)
			o := nodes[0]
			runOrganization(t, r, o)
			if child == "foreign child" {
				m.addGroup("realm", keycloak.Group{ID: "foreign-child", Name: "foreign", Path: "/root/foreign"})
			}
			if child == "child lookup unavailable" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if strings.HasSuffix(req.URL.Path, "/children") {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					m.ServeHTTP(w, req)
				}))
				defer server.Close()
				r.Pool = keycloak.NewPool(keycloak.New(server.URL, "client", "secret", keycloak.WithInsecureHTTP()))
			}
			if err := r.Delete(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			runOrganization(t, r, o)
			if m.count("deleteGroup") != 0 || m.count("deleteOrganization") != 0 || len(o.Finalizers) == 0 {
				t.Fatal("provider cleanup cascaded or was treated as proven")
			}
			requireOrganizationCondition(t, o, "Synced", metav1.ConditionFalse, "CleanupFailed")
		})
	}
}

func TestPositionMetadataNeverAuthorizesProviderAdoption(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "group", true: "native organization"}[native], func(t *testing.T) {
			r, m, nodes := organizationTestFixture(t)
			o := nodes[0]
			o.Status.PositionID = "last-known-position"
			if err := r.Status().Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if native {
				m.mu.Lock()
				m.organizations["realm"] = []keycloak.Organization{{ID: "native-root", Alias: "root", Name: "root", Enabled: true}}
				m.mu.Unlock()
			} else {
				m.addGroup("realm", keycloak.Group{ID: "group-root", Name: "root", Path: "/root"})
			}
			p := &testOrganizationProjector{}
			r.ProjectionMode, r.Positions = hankoapi.ProjectionEnabled, p
			runOrganization(t, r, o)
			if o.Status.Phase != "Error" || p.ensureCalls != 0 || m.count("updateOrganization") != 0 {
				t.Fatal("platform identity authorized foreign provider adoption")
			}
			reason := "GroupOwnershipConflict"
			if native {
				reason = "OrganizationOwnershipConflict"
			}
			requireOrganizationCondition(t, o, "Synced", metav1.ConditionFalse, reason)
		})
	}
}

func testOrganizationOwnership(o *api.HankoOrganization) map[string][]string {
	return map[string][]string{"hanko.sh/organization-name": {o.Name}, "hanko.sh/organization-namespace": {o.Namespace}, "hanko.sh/organization-uid": {string(o.UID)}}
}
