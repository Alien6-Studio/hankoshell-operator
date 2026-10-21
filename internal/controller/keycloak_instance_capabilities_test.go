//go:build keycloak_integration

package controller_test

import (
	"context"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
)

type capabilityRotationAudit struct{ calls int }

func (a *capabilityRotationAudit) RecordServiceAccountRotation(context.Context, string, string, string, string, time.Time) error {
	a.calls++
	return nil
}

// Use an identity with both optional master roles, so denial cannot mask an
// unwanted write. No global admin or realm-admin role reaches the reconciler.
func verifyRealInstanceCapabilityBoundary(f *keycloakFixture) {
	f.t.Helper()
	_, credential := f.serviceClient("instance-authority")
	f.grantClientRoles("instance-authority", "master", []string{"manage-realm", "manage-clients"})
	ctx := context.Background()
	instance := &hanko.HankoKeycloakInstance{ObjectMeta: fixtureMeta("capabilities"), Spec: hanko.HankoKeycloakInstanceSpec{
		Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "capability-admin"}, TLSCARef: "capability-ca",
	}}
	secret := &corev1.Secret{ObjectMeta: fixtureMeta("capability-admin"), Data: map[string][]byte{
		"HANKO_KEYCLOAK_URL": []byte(f.baseURL), "HANKO_KC_CLIENT_ID": []byte("instance-authority"), "HANKO_KC_CLIENT_SECRET": []byte(credential),
	}}
	secret.Annotations = map[string]string{"hanko.sh/sa-rotated-at": time.Now().Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	ca := &corev1.Secret{ObjectMeta: fixtureMeta("capability-ca"), Data: map[string][]byte{"ca.crt": f.ca}}
	scheme := newScheme(f.t)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(instance).WithObjects(instance, secret, ca).Build()
	audit := &capabilityRotationAudit{}
	r := &controller.HankoKeycloakInstanceReconciler{Client: kube, Scheme: scheme, RequireHTTPS: true, CredentialRotationAudit: audit}
	var beforeMaster map[string]any
	f.admin(http.MethodGet, "/admin/realms/master", nil, &beforeMaster)
	beforeClient := f.client("master", "instance-authority")
	fixtureReconcile(f, ctx, r, instance)
	fixtureGet(f, ctx, kube, instance)
	fixtureEqual(f.t, "unrequested capability instance phase", instance.Status.Phase, "Ready")
	var afterMaster map[string]any
	f.admin(http.MethodGet, "/admin/realms/master", nil, &afterMaster)
	fixtureEqual(f.t, "unrequested master policy unchanged", afterMaster, beforeMaster)
	fixtureEqual(f.t, "unrequested master client unchanged", f.client("master", "instance-authority"), beforeClient)
	var observed corev1.Secret
	f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed))
	fixtureEqual(f.t, "unrequested credential unchanged", observed.Data, secret.Data)
	fixtureEqual(f.t, "unrequested rotation clock unchanged", observed.Annotations, secret.Annotations)

	instance.Spec.HardenMasterRealm = true
	f.requireNoError(kube.Update(ctx, instance))
	fixtureReconcile(f, ctx, r, instance)
	fixtureGet(f, ctx, kube, instance)
	fixtureEqual(f.t, "requested hardening phase", instance.Status.Phase, "Ready")
	f.admin(http.MethodGet, "/admin/realms/master", nil, &afterMaster)
	fixtureEqual(f.t, "explicit master hardening applied", afterMaster["bruteForceProtected"], true)

	instance.Spec.HardenMasterRealm = false
	instance.Spec.RotateAdminCredentials = true
	f.requireNoError(kube.Update(ctx, instance))
	fixtureReconcile(f, ctx, r, instance) // Persist pending credential before provider mutation.
	f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed))
	pending := string(observed.Data["HANKO_KC_CLIENT_SECRET_PENDING"])
	if pending == "" {
		f.t.Fatal("explicit rotation was not prepared")
	}
	f.secrets = append(f.secrets, pending)
	fixtureReconcile(f, ctx, r, instance) // Rotate, authenticate pending credential, then promote.
	fixtureReconcile(f, ctx, r, instance) // Reload promoted credential and finish probing.
	fixtureGet(f, ctx, kube, instance)
	f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed))
	fixtureEqual(f.t, "explicit credential promotion", string(observed.Data["HANKO_KC_CLIENT_SECRET"]), pending)
	fixtureEqual(f.t, "explicit rotation phase", instance.Status.Phase, "Ready")
	fixtureEqual(f.t, "explicit rotation metadata audit", audit.calls, 1)
}
