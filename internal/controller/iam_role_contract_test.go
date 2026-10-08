package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
)

type recordingRoleDriver struct {
	caps                 roles.CapabilityEvidence
	writes, observations int
	hook                 func()
	state                *roles.State
	err                  error
}

func (d *recordingRoleDriver) Capabilities(context.Context) (roles.CapabilityEvidence, error) {
	if d.hook != nil {
		hook := d.hook
		d.hook = nil
		hook()
	}
	return d.caps, nil
}
func (d *recordingRoleDriver) Observe(context.Context, roles.Plan) (roles.State, error) {
	d.observations++
	if d.state != nil {
		return *d.state, d.err
	}
	return roles.State{Present: true, Owned: true, Observation: successfulIAMObservation()}, nil
}
func (d *recordingRoleDriver) Reconcile(context.Context, roles.Plan) (roles.State, error) {
	d.writes++
	if d.state != nil {
		return *d.state, d.err
	}
	return roles.State{Present: true, Owned: true, Observation: successfulIAMObservation()}, nil
}
func (d *recordingRoleDriver) DeleteOwned(context.Context, roles.Plan) error { d.writes++; return nil }
func (*recordingRoleDriver) AuthorityClosure(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func TestRoleControllerContractRefusalObserveAndFreshness(t *testing.T) {
	for _, mode := range []string{"unsupported", "observe", "stale-reference", "native-conflict"} {
		t.Run(mode, func(t *testing.T) {
			role := &api.HankoRole{ObjectMeta: metav1.ObjectMeta{Name: "editor", Namespace: "default", UID: "role-uid", Generation: 1}, Spec: api.HankoRoleSpec{RealmRef: "realm", Name: "editor"}}
			realm := &api.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "realm", Namespace: "default", UID: "realm-uid"}}
			d := &recordingRoleDriver{caps: roles.KeycloakEvidence()}
			if mode == "unsupported" {
				d.caps.Supported.RealmRoles = false
			}
			if mode == "observe" {
				role.Labels = map[string]string{importedByLabel: "fixture"}
				role.Finalizers = []string{roleFinalizerName}
			}
			if mode == "native-conflict" {
				role.Spec.Attributes = map[string][]string{roles.OwnerAttribute: {"fixture-secret-sentinel"}}
			}
			c := fake.NewClientBuilder().WithScheme(resourceServerScheme(t)).WithObjects(role, realm).WithStatusSubresource(&api.HankoRole{}).Build()
			if mode == "stale-reference" {
				d.hook = func() {
					var current api.HankoRealm
					if err := c.Get(context.Background(), client.ObjectKeyFromObject(realm), &current); err != nil {
						t.Fatal(err)
					}
					current.Generation++
					if err := c.Update(context.Background(), &current); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := &HankoRoleReconciler{Client: c, DriverFactory: func(string, map[string]string) roles.Driver { return d }}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(role)})
			if d.writes != 0 {
				t.Fatal("refused/Observe/stale role wrote provider")
			}
			if mode == "observe" {
				if err != nil || d.observations != 1 {
					t.Fatal("Observe failed")
				}
			} else if err == nil {
				t.Fatal("invalid plan accepted")
			}
			var current api.HankoRole
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(role), &current); err != nil {
				t.Fatal(err)
			}
			iamconformance.NoSecrets(t, []string{"fixture-secret-sentinel"}, current.Status)
		})
	}
}
