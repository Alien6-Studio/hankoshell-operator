//go:build integration

package v1alpha1_test

import (
	"context"
	"fmt"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func checkApplicationProtocols(t *testing.T, ctx context.Context, kube client.Client) {
	t.Helper()
	legacy := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "protocol-legacy", Namespace: "auth"}, Spec: api.HankoApplicationSpec{RealmRef: "example", ClientID: "portal", Type: "spa", RedirectURIs: []string{"https://portal.test/callback"}}}
	if err := kube.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Spec.Protocol != "oidc" {
		t.Fatal("legacy protocol was not defaulted to oidc")
	}
	saml := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "protocol-saml", Namespace: "auth"}, Spec: api.HankoApplicationSpec{RealmRef: "example", ClientID: "https://sp.test/entity", Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{"https://sp.test/acs"}}}}
	if err := kube.Create(ctx, saml); err != nil {
		t.Fatal(err)
	}
	if saml.Spec.SAML.RequireSignedAssertions == nil || !*saml.Spec.SAML.RequireSignedAssertions || saml.Spec.SAML.NameIDFormat != "persistent" {
		t.Fatal("SAML security defaults absent")
	}
	saml.Status.Protocol = "saml"
	saml.Status.ContractVersion = "hanko.sh/iam-contract/v1alpha1"
	saml.Status.BackendKind = "keycloak"
	saml.Status.SAMLEndpoints = &api.SAMLEndpoints{Issuer: "https://idp.test/realms/example", SSO: "https://idp.test/realms/example/protocol/saml", Metadata: "https://idp.test/realms/example/protocol/saml/descriptor", ResponseBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}
	saml.Status.Capabilities.SAML = true
	if err := kube.Status().Update(ctx, saml); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(saml), saml); err != nil {
		t.Fatal(err)
	}
	if saml.Status.Protocol != "saml" || saml.Status.SAMLEndpoints == nil || !saml.Status.Capabilities.SAML {
		t.Fatal("protocol-specific status lost in roundtrip")
	}
	for n, change := range []func(map[string]any){
		func(s map[string]any) { s["protocol"] = "unknown" },
		func(s map[string]any) { delete(s, "saml") },
		func(s map[string]any) { s["protocol"] = "oidc" },
		func(s map[string]any) { s["type"] = "spa" },
		func(s map[string]any) { s["type"] = "web" },
		func(s map[string]any) { s["redirectURIs"] = []any{"https://sp.test/callback"} },
		func(s map[string]any) { s["postLogoutRedirectURIs"] = []any{"https://sp.test/logout"} },
		func(s map[string]any) { s["realmRoleScopes"] = []any{} },
		func(s map[string]any) {
			s["tokenClaims"] = []any{map[string]any{"name": "claim", "claim": "department", "userAttribute": "department"}}
		},
		func(s map[string]any) {
			s["identityMappings"] = []any{map[string]any{"name": "broker", "identityProvider": "entra", "claim": "department", "target": map[string]any{"userAttribute": "department"}}}
		},
		func(s map[string]any) { s["secretRotationPolicy"] = map[string]any{"enabled": true} },
		func(s map[string]any) {
			s["clientSecretProjections"] = []any{map[string]any{"namespace": "other", "name": "secret"}}
		},
		func(s map[string]any) { s["attributes"] = map[string]any{"saml.assertion.signature": "false"} },
		func(s map[string]any) { s["attributes"] = map[string]any{"hanko.sh/application-owner": "forged"} },
		func(s map[string]any) { s["attributes"] = map[string]any{"private_key": "forbidden"} },
		func(s map[string]any) { s["saml"].(map[string]any)["requireSignedAssertions"] = false },
		func(s map[string]any) { s["saml"].(map[string]any)["nameIDFormat"] = "unknown" },
		func(s map[string]any) { s["saml"].(map[string]any)["assertionConsumerServices"] = []any{} },
		func(s map[string]any) {
			s["saml"].(map[string]any)["assertionConsumerServices"] = []any{"http://sp.test/acs"}
		},
		func(s map[string]any) {
			s["saml"].(map[string]any)["assertionConsumerServices"] = []any{"https://user:pass@sp.test/acs"}
		},
		func(s map[string]any) {
			s["saml"].(map[string]any)["assertionConsumerServices"] = []any{"https://sp.test/*"}
		},
		func(s map[string]any) {
			s["saml"].(map[string]any)["assertionConsumerServices"] = []any{"https://sp.test/acs#fragment"}
		},
		func(s map[string]any) {
			s["saml"].(map[string]any)["assertionConsumerServices"] = []any{"https://sp.test/acs?query"}
		},
	} {
		spec := map[string]any{"realmRef": "example", "clientID": "https://sp.test/entity", "protocol": "saml", "saml": map[string]any{"assertionConsumerServices": []any{"https://sp.test/acs"}}}
		change(spec)
		bad := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": map[string]any{"name": fmt.Sprintf("protocol-invalid-%d", n), "namespace": "auth"}, "spec": spec}}
		if err := kube.Create(ctx, bad); !apierrors.IsInvalid(err) {
			t.Fatalf("invalid protocol case %d admitted: %v", n, err)
		}
	}
}
