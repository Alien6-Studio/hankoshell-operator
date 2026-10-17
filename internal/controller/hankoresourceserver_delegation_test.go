package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func delegatedResourceServerObjects() (*api.HankoResourceServer, []client.Object) {
	obj, objects := validResourceServerObjects(ModeManage)
	for _, object := range objects {
		if object.GetUID() == "" {
			object.SetUID(types.UID("uid-" + object.GetName()))
		}
	}
	actor := &api.HankoServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "actor", Namespace: obj.Namespace, UID: "actor-uid"}, Spec: api.HankoServiceAccountSpec{RealmRef: obj.Spec.RealmRef, ClientID: "actor-client"}}
	subject := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "subject", Namespace: obj.Namespace, UID: "subject-uid"}, Spec: api.HankoApplicationSpec{RealmRef: obj.Spec.RealmRef, ClientID: "subject-client", Protocol: "oidc"}}
	obj.Spec.Permissions[0].Delegation = &api.AuthorizationDelegation{Actor: api.AuthorizationDelegationIdentity{Kind: "service_account", Ref: actor.Name}, Subject: api.AuthorizationDelegationIdentity{Kind: "application", Ref: subject.Name}}
	return obj, append(objects, actor, subject)
}

func TestDelegationRefusalPrecedesEveryControllerWritePath(t *testing.T) {
	for _, scenario := range []string{"manage", "observe", "imported", "adoption", "delete", "status failure", "restart", "workload identity", "previous grant"} {
		t.Run(scenario, func(t *testing.T) {
			obj, objects := delegatedResourceServerObjects()
			switch scenario {
			case "observe":
				obj.Spec.Mode = ModeObserve
			case "imported":
				obj.Labels = map[string]string{importedByLabel: "inventory"}
			case "adoption":
				obj.Spec.Mode = ModeObserve
				obj.Annotations = map[string]string{"hanko.sh/adopt": "true", "hanko.sh/adoption-candidate": "stale"}
			case "delete":
				at := metav1.Now()
				obj.DeletionTimestamp = &at
				obj.Finalizers = []string{resourceServerFinalizerName}
			case "workload identity":
				// Refusal must precede workload activation or UID-loss cleanup.
				objects[len(objects)-2].(*api.HankoServiceAccount).Spec.Authentication = &api.ServiceAccountAuthentication{Mode: "Kubernetes"}
			case "previous grant":
				obj.Generation = 2
				obj.Status = api.HankoResourceServerStatus{ContractVersion: string(iamcontract.Version), AppliedGeneration: 1, AppliedPlanHash: string(iamcontract.Hash(iamcontract.Version, "test", "prior", nil))}
			}
			backend := resourceServerClient(t, objects...)
			kube := backend
			if scenario == "status failure" {
				kube = interceptor.NewClient(backend.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
					return errors.New("status unavailable")
				}})
			}
			driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
			for attempt := 0; attempt < 2; attempt++ {
				r := &HankoResourceServerReconciler{Client: kube, DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
				_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if !errors.Is(err, authorization.ErrCapabilityUnsupported) {
					t.Fatal("delegation did not return capability refusal", err)
				}
			}
			if driver.observeCalls != 0 || len(driver.reconcile) != 0 || len(driver.deleted) != 0 {
				t.Fatal("unsupported declaration reached provider")
			}
			var stored api.HankoResourceServer
			if err := backend.Get(context.Background(), client.ObjectKeyFromObject(obj), &stored); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored.Finalizers, obj.Finalizers) || stored.Status.AppliedPlanHash != obj.Status.AppliedPlanHash || stored.Status.AppliedGeneration != obj.Status.AppliedGeneration || stored.Status.EvaluatedPlanHash != "" || stored.Status.AdoptionReceipt != nil {
				t.Fatal("refusal changed write authority or claimed application")
			}
			if scenario != "status failure" {
				if stored.Status.Phase != "Error" || stored.Status.Capabilities.BoundedDelegation || conditionTrue(stored.Status.Conditions, "CapabilitiesSatisfied") || !iamcontract.ValidDigest(stored.Status.IntentHash) || len(stored.Status.Findings) != 1 || stored.Status.Findings[0].Code != "DelegationUnsupported" {
					t.Fatalf("missing explicit refusal evidence: %#v", stored.Status)
				}
			}
		})
	}
}

func TestDelegationReferencesAndBoundsAreValidatedLocally(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*api.HankoResourceServer, []client.Object)
	}{
		{"missing actor", func(o *api.HankoResourceServer, _ []client.Object) {
			o.Spec.Permissions[0].Delegation.Actor.Ref = "absent"
		}},
		{"missing resource server application", func(o *api.HankoResourceServer, _ []client.Object) { o.Spec.ApplicationRef = "absent" }},
		{"undeclared resource", func(o *api.HankoResourceServer, _ []client.Object) {
			o.Spec.Permissions[0].Resources = []string{"absent"}
		}},
		{"all resources implicit", func(o *api.HankoResourceServer, _ []client.Object) { o.Spec.Permissions[0].Resources = nil }},
		{"cross realm", func(_ *api.HankoResourceServer, objects []client.Object) {
			objects[len(objects)-1].(*api.HankoApplication).Spec.RealmRef = "other"
		}},
		{"cross namespace", func(_ *api.HankoResourceServer, objects []client.Object) {
			objects[len(objects)-1].SetNamespace("other")
		}},
		{"cross tenant", func(_ *api.HankoResourceServer, objects []client.Object) {
			objects[len(objects)-1].SetLabels(map[string]string{"hanko.sh/tenant": "other"})
		}},
		{"missing UID", func(_ *api.HankoResourceServer, objects []client.Object) { objects[len(objects)-1].SetUID("") }},
		{"SAML subject", func(_ *api.HankoResourceServer, objects []client.Object) {
			objects[len(objects)-1].(*api.HankoApplication).Spec.Protocol = "saml"
		}},
		{"alias same native identity", func(_ *api.HankoResourceServer, objects []client.Object) {
			objects[len(objects)-1].(*api.HankoApplication).Spec.ClientID = "actor-client"
		}},
		{"human subject", func(o *api.HankoResourceServer, _ []client.Object) {
			o.Spec.Permissions[0].Delegation.Subject.Kind = "human"
		}},
		{"raw client identifier", func(o *api.HankoResourceServer, _ []client.Object) {
			o.Spec.Permissions[0].Delegation.Actor.Ref = "https://client.example"
		}},
		{"zero depth", func(o *api.HankoResourceServer, _ []client.Object) {
			v := int32(0)
			o.Spec.Permissions[0].Delegation.MaxDepth = &v
		}},
		{"excess lifetime", func(o *api.HankoResourceServer, _ []client.Object) {
			v := int32(601)
			o.Spec.Permissions[0].Delegation.MaxTTLSeconds = &v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj, objects := delegatedResourceServerObjects()
			tc.edit(obj, objects)
			kube := resourceServerClient(t, objects...)
			driver := &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}
			r := &HankoResourceServerReconciler{Client: kube, DriverFactory: func(string, map[string]string) authorization.Driver { return driver }}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil || errors.Is(err, authorization.ErrCapabilityUnsupported) {
				t.Fatal("invalid reference was not rejected locally", err)
			}
			if driver.observeCalls != 0 || len(driver.reconcile) != 0 || len(driver.deleted) != 0 {
				t.Fatal("invalid reference reached provider")
			}
		})
	}
}

func TestDelegationPlanBindsUIDsAndWatchesExactReferences(t *testing.T) {
	obj, objects := delegatedResourceServerObjects()
	backend := fake.NewClientBuilder().WithScheme(resourceServerScheme(t)).WithObjects(objects...).WithStatusSubresource(&api.HankoResourceServer{}).WithIndex(&api.HankoResourceServer{}, delegationReferenceIndex, delegationIndexValues).Build()
	driver := &syntheticDelegationPlanDriver{recordingAuthorizationDriver: &recordingAuthorizationDriver{capabilities: supportedAuthorizationCapabilities()}}
	driver.capabilities.BoundedDelegation = true // Synthetic compiler only; no native execution proof.
	r := &HankoResourceServerReconciler{Client: backend}
	plan, err := r.compileAuthorizationPlan(context.Background(), obj, driver, ModeManage)
	if err != nil {
		t.Fatal(err)
	}
	var actor api.HankoServiceAccount
	key := client.ObjectKey{Namespace: obj.Namespace, Name: "actor"}
	if err := backend.Get(context.Background(), key, &actor); err != nil {
		t.Fatal(err)
	}
	actor.Generation++
	if err := backend.Update(context.Background(), &actor); err != nil {
		t.Fatal(err)
	}
	current, err := r.compileAuthorizationPlan(context.Background(), obj, driver, ModeManage)
	if err != nil || current.Identity().Intent != plan.Identity().Intent || !errors.Is(plan.Validate(current), iamcontract.ErrStale) {
		t.Fatal("actor change retained old plan", err)
	}
	if err := backend.Delete(context.Background(), &actor); err != nil {
		t.Fatal(err)
	}
	actor.UID, actor.ResourceVersion = "replacement-actor-uid", ""
	if err := backend.Create(context.Background(), &actor); err != nil {
		t.Fatal(err)
	}
	recreated, err := r.compileAuthorizationPlan(context.Background(), obj, driver, ModeManage)
	if err != nil || recreated.Identity().Intent != current.Identity().Intent || !errors.Is(current.Validate(recreated), iamcontract.ErrStale) {
		t.Fatal("actor recreation retained old plan", err)
	}
	for _, ref := range objects {
		if ref.GetName() == "billing-reader" || ref == obj {
			continue
		}
		if got := r.delegationRequests(context.Background(), ref); len(got) != 1 || got[0].NamespacedName != client.ObjectKeyFromObject(obj) {
			t.Fatal("reference watch missed delegation", ref.GetName())
		}
	}
	actor.Name = "unrelated"
	if len(r.delegationRequests(context.Background(), &actor)) != 0 {
		t.Fatal("unrelated identity triggered delegation")
	}
	if _, err := readResourceServerAdoption(context.Background(), backend, backend, nil, obj); !errors.Is(err, authorization.ErrCapabilityUnsupported) {
		t.Fatal("adoption accepted delegation")
	}
}

type syntheticDelegationPlanDriver struct{ *recordingAuthorizationDriver }

func (*syntheticDelegationPlanDriver) PrepareDelegation(_ context.Context, model authorization.Model, _ string) (authorization.Model, error) {
	model.DelegationContext.Runtime = iamcontract.Hash(iamcontract.Version, "test", "synthetic-delegation", []byte("not-provider-evidence"))
	return model, nil
}
