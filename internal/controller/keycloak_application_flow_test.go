//go:build keycloak_integration

package controller_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/beevik/etree"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealKeycloakApplicationProtocolsAndFlows(t *testing.T) {
	f := newKeycloakFixtureWithTransport(t, false, true)
	// Bootstrap supplies only test users and the dedicated account's existing
	// target-realm manage-clients grant. No realm-admin, global admin, user
	// management, impersonation or identity-provider authority enters the operator.
	operator, _ := f.serviceClient("application-protocol-operator")
	f.grantClientRoles("application-protocol-operator", "managed", []string{"manage-clients"})
	denied, _ := f.serviceClient("application-protocol-no-role")
	username, password := fixtureProtocolUser(f)
	kube := newFakeClient(t)
	ar := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: newScheme(t), Pool: keycloak.NewPool(operator)}
	ctx := context.Background()
	issuer := f.baseURL + "/realms/managed"
	entity, acs := "https://sp.example.test/saml", "https://sp.example.test/saml/acs"
	saml := &api.HankoApplication{ObjectMeta: fixtureMeta("saml"), Spec: api.HankoApplicationSpec{
		RealmRef: "managed", ClientID: entity, Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{acs}},
		Roles: []api.ApplicationRole{{Name: "use", Description: "Use application"}},
	}}
	f.requireNoError(kube.Create(ctx, saml))
	fixtureReconcile(f, ctx, ar, saml)
	fixtureGet(f, ctx, kube, saml)
	fixtureEqual(t, "SAML ready", saml.Status.Phase, "Ready")
	if saml.Status.Protocol != "saml" || saml.Status.OIDCEndpoints != nil || saml.Status.SAMLEndpoints == nil || saml.Status.ClientSecret != nil || saml.Status.AppliedGeneration != saml.Generation || !saml.Status.ObservationComplete || saml.Status.DriftState != "InSync" {
		t.Fatal("SAML status/evidence contract incomplete")
	}
	if !applicationHasCondition(saml.Status.Conditions, "Operational", metav1.ConditionTrue, "Reachable") {
		t.Fatal("SAML metadata readiness failed")
	}
	provider := f.client("managed", entity)
	fixtureEqual(t, "SAML UID ownership", provider["attributes"].(map[string]any)[applications.OwnerAttribute], string(saml.UID))
	roles, err := operator.ListClientRoles(ctx, "managed", entity)
	f.requireNoError(err)
	fixtureEqual(t, "SAML client roles", len(roles), 1)
	var secret corev1.Secret
	if err := kube.Get(ctx, client.ObjectKey{Namespace: saml.Namespace, Name: "hanko-app-" + entity}, &secret); err == nil {
		t.Fatal("SAML created an OIDC credential Secret")
	}
	fixtureReconcile(f, ctx, ar, saml)
	fixtureEqual(t, "SAML idempotence", f.client("managed", entity), provider)
	if _, err := denied.GetApplication(ctx, "managed", entity); err == nil || !keycloak.IsForbidden(err) {
		t.Fatal("no-role identity read SAML Admin API")
	}
	if err := denied.CreateApplication(ctx, "managed", keycloak.Application{ClientID: "denied-saml", Protocol: "saml"}); err == nil || !keycloak.IsForbidden(err) {
		t.Fatal("no-role identity wrote SAML Admin API")
	}
	metadata, err := operator.ProtocolDocument(ctx, "managed", "saml")
	f.requireNoError(err)
	certificates := samlMetadataCertificates(f, metadata)
	t.Log("real SAML POST login: four NameID formats; exact issuer/ACS/audience, response and assertion RSA-SHA256 signatures")
	for _, format := range []string{"persistent", "transient", "email", "unspecified"} {
		fixtureGet(f, ctx, kube, saml)
		saml.Spec.SAML.NameIDFormat = format
		saml.Generation++
		f.requireNoError(kube.Update(ctx, saml))
		fixtureReconcile(f, ctx, ar, saml)
		data, requestID := fixtureSAMLResponse(f, protocolBrowser(f), entity, acs, issuer+"/protocol/saml", username, password)
		nameFormat := "urn:oasis:names:tc:SAML:2.0:nameid-format:" + format
		if format == "email" {
			nameFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		}
		if format == "unspecified" {
			nameFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
		}
		want := samlExpectation{Issuer: issuer, Audience: entity, ACS: acs, RequestID: requestID, NameIDFormat: nameFormat, Now: time.Now()}
		name, err := validateSAMLResponse(data, certificates, want)
		f.requireNoError(err)
		if format == "email" && name != "protocol-user@example.test" {
			t.Fatal("email NameID does not match fixture user")
		}
		for _, negative := range []struct {
			name string
			want samlExpectation
			data []byte
		}{
			{name: "wrong ACS", want: func() samlExpectation { v := want; v.ACS = acs + "-wrong"; return v }(), data: data},
			{name: "wrong audience", want: func() samlExpectation { v := want; v.Audience = entity + "-wrong"; return v }(), data: data},
			{name: "wrong request", want: func() samlExpectation { v := want; v.RequestID = "_wrong"; return v }(), data: data},
			{name: "expired", want: func() samlExpectation { v := want; v.Now = time.Now().Add(time.Hour); return v }(), data: data},
			{name: "tampered issuer", want: want, data: []byte(strings.Replace(string(data), issuer, issuer+"-tampered", 1))},
			{name: "algorithm downgrade", want: want, data: []byte(strings.Replace(string(data), samlRSA256, samlDSigNS+"rsa-sha1", 1))},
			{name: "duplicate assertion", want: want, data: duplicateSAMLAssertion(t, data)},
		} {
			if _, err := validateSAMLResponse(negative.data, certificates, negative.want); err == nil {
				t.Fatalf("accepted %s", negative.name)
			}
		}
	}
	status, _, _ := protocolHTTP(f, protocolBrowser(f), http.MethodPost, issuer+"/protocol/saml", samlAuthnRequest(entity, acs+"-foreign", issuer+"/protocol/saml", "_wrong_acs"))
	if status != http.StatusBadRequest {
		t.Fatalf("Keycloak accepted unregistered ACS: HTTP %d", status)
	}
	qualifyOIDCFlows(f, ctx, kube, ar, username, password)
	qualifyApplicationLifecycle(f, ctx, kube, ar, saml)
	qualifyForeignApplications(f, ctx, kube, ar)
	qualifyOIDCRecreation(f, ctx, kube, ar)
	qualifyPublicSAMLMetadata(f, ctx, kube, ar, username, password)
	t.Logf("Keycloak %s: manage-clients only; SAML protocol and lifecycle, OIDC browser+PKCE, M2M credentials; denied no-role Admin API", f.version)
}

func qualifyForeignApplications(f *keycloakFixture, ctx context.Context, kube client.Client, ar *controller.HankoApplicationReconciler) {
	for _, protocol := range []string{"oidc", "saml"} {
		entity := "https://foreign-" + protocol + ".example.test/entity"
		providerProtocol := protocol
		spec := api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Protocol: protocol}
		if protocol == "oidc" {
			providerProtocol = "openid-connect"
			spec.Type = "spa"
		} else {
			spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: []string{"https://foreign-saml.example.test/acs"}}
		}
		f.admin(http.MethodPost, "/admin/realms/managed/clients", map[string]any{"clientId": entity, "protocol": providerProtocol, "enabled": true, "attributes": map[string]string{applications.OwnerAttribute: "another-kubernetes-uid"}}, nil)
		before := f.client("managed", entity)
		app := &api.HankoApplication{ObjectMeta: fixtureMeta("foreign-" + protocol), Spec: spec}
		f.requireNoError(kube.Create(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		fixtureGet(f, ctx, kube, app)
		app.Annotations = map[string]string{applications.MigrationUUIDAnnotation: before["id"].(string), applications.MigrationObservationAnnotation: app.Status.ObservedStateHash}
		app.Status.AppliedPlanHash = app.Status.EvaluatedPlanHash
		app.Status.AppliedGeneration = app.Generation
		f.requireNoError(kube.Status().Update(ctx, app))
		f.requireNoError(kube.Update(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		fixtureGet(f, ctx, kube, app)
		if app.Status.Phase != "Conflict" {
			f.t.Fatal("foreign UID adopted by approvals/status")
		}
		fixtureEqual(f.t, "foreign client unchanged", f.client("managed", entity), before)
		f.requireNoError(kube.Delete(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		fixtureEqual(f.t, "foreign client preserved on deletion", f.client("managed", entity), before)
		observer := &api.HankoApplication{ObjectMeta: fixtureMeta("mismatch-" + protocol), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Mode: "Observe"}}
		if protocol == "oidc" {
			observer.Spec.Protocol = "saml"
			observer.Spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: []string{"https://foreign-oidc.example.test/acs"}}
		}
		f.requireNoError(kube.Create(ctx, observer))
		fixtureReconcile(f, ctx, ar, observer)
		fixtureGet(f, ctx, kube, observer)
		if observer.Status.Protocol != protocol || !applicationHasCondition(observer.Status.Conditions, "Synced", metav1.ConditionFalse, "ProtocolMismatch") || observer.Status.ClientSecret != nil || observer.Status.AppliedPlanHash != "" {
			f.t.Fatal("Observe mismatch normalized or acquired authority")
		}
		fixtureEqual(f.t, "Observe mismatch makes no mutation", f.client("managed", entity), before)
	}
}

func qualifyOIDCRecreation(f *keycloakFixture, ctx context.Context, kube client.Client, ar *controller.HankoApplicationReconciler) {
	entity := "https://recreation.example.test/entity"
	app := &api.HankoApplication{ObjectMeta: fixtureMeta("recreation"), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Type: "spa", RedirectURIs: []string{"https://recreation.example.test/callback"}}}
	f.requireNoError(kube.Create(ctx, app))
	fixtureReconcile(f, ctx, ar, app)
	fixtureGet(f, ctx, kube, app)
	before := f.client("managed", entity)
	app.Spec = api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{"https://recreation.example.test/acs"}}}
	app.Generation++
	f.requireNoError(kube.Update(ctx, app))
	fixtureReconcile(f, ctx, ar, app)
	fixtureGet(f, ctx, kube, app)
	if !applicationHasCondition(app.Status.Conditions, "Synced", metav1.ConditionFalse, "ProtocolChangeRequiresRecreation") {
		f.t.Fatal("OIDC -> SAML converted in place")
	}
	fixtureEqual(f.t, "refused OIDC conversion preserves object", f.client("managed", entity), before)
	f.requireNoError(kube.Delete(ctx, app))
	fixtureReconcile(f, ctx, ar, app)
	app.ObjectMeta = fixtureMeta("recreation")
	app.UID = "recreated-uid"
	app.Status = api.HankoApplicationStatus{}
	f.requireNoError(kube.Create(ctx, app))
	fixtureReconcile(f, ctx, ar, app)
	if f.client("managed", entity)["id"] == before["id"] {
		f.t.Fatal("reviewed recreation retained old protocol identity")
	}
}

func qualifyPublicSAMLMetadata(f *keycloakFixture, ctx context.Context, kube client.Client, ar *controller.HankoApplicationReconciler, username, password string) {
	publicBase := strings.Replace(f.baseURL, "localhost", "127.0.0.1", 1)
	f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"attributes": map[string]string{"frontendUrl": publicBase}}, nil)
	f.requireNoError(kube.Create(ctx, &api.HankoRealm{ObjectMeta: fixtureMeta("managed"), Spec: api.HankoRealmSpec{FrontendURL: publicBase}}))
	entity, acs := "https://public-sp.example.test/entity", "https://public-sp.example.test/acs"
	app := &api.HankoApplication{ObjectMeta: fixtureMeta("public-saml"), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{acs}}}}
	f.requireNoError(kube.Create(ctx, app))
	fixtureReconcile(f, ctx, ar, app)
	fixtureGet(f, ctx, kube, app)
	issuer := publicBase + "/realms/managed"
	if app.Status.SAMLEndpoints == nil || app.Status.SAMLEndpoints.Issuer != issuer || app.Status.SAMLEndpoints.SSO != issuer+"/protocol/saml" || app.Status.SAMLEndpoints.Metadata != issuer+"/protocol/saml/descriptor" {
		f.t.Fatal("SAML exposes private administrative origin instead of configured public realm")
	}
	// Separate TLS-verified origins: administrative reads still use localhost;
	// the synthetic SP consumes public 127.0.0.1 metadata and SSO endpoints.
	publicFixture := *f
	publicFixture.baseURL = publicBase
	status, _, metadata := protocolHTTP(&publicFixture, f.http, http.MethodGet, app.Status.SAMLEndpoints.Metadata, nil)
	fixtureEqual(f.t, "public SAML metadata", status, http.StatusOK)
	certs := samlMetadataCertificates(&publicFixture, metadata)
	response, request := fixtureSAMLResponse(&publicFixture, protocolBrowser(&publicFixture), entity, acs, app.Status.SAMLEndpoints.SSO, username, password)
	_, err := validateSAMLResponse(response, certs, samlExpectation{Issuer: issuer, Audience: entity, ACS: acs, RequestID: request, NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", Now: time.Now()})
	f.requireNoError(err)
}

func qualifyOIDCFlows(f *keycloakFixture, ctx context.Context, kube client.Client, ar *controller.HankoApplicationReconciler, username, password string) {
	issuer := f.baseURL + "/realms/managed"
	for _, kind := range []string{"web", "spa", "m2m"} {
		clientID := "flow-" + kind
		callback := "https://" + clientID + ".example.test/callback"
		value, audience := "qualification", clientID
		app := &api.HankoApplication{ObjectMeta: fixtureMeta(clientID), Spec: api.HankoApplicationSpec{
			RealmRef: "managed", ClientID: clientID, Type: kind, RedirectURIs: []string{callback},
			TokenClaims: []api.ApplicationTokenClaim{{Name: "environment", Claim: "deployment_environment", Value: &value}, {Name: "audience", Claim: "aud", Value: &audience}},
		}}
		if kind == "spa" {
			app.Spec.Attributes = map[string]string{"pkce.code.challenge.method": "S256"}
		}
		// Deliberately omit protocol: these are valid legacy-style manifests.
		f.requireNoError(kube.Create(ctx, app))
		fixtureReconcile(f, ctx, ar, app)
		fixtureGet(f, ctx, kube, app)
		if app.Status.Phase != "Ready" || app.Status.Protocol != "oidc" || app.Status.OIDCEndpoints == nil || app.Status.SAMLEndpoints != nil {
			f.t.Fatal("legacy OIDC status/regression")
		}
		provider := f.client("managed", clientID)
		form := url.Values{"client_id": {clientID}}
		if kind != "spa" {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: app.Namespace, Name: app.Status.ClientSecret.SecretRef.Name}}
			fixtureGet(f, ctx, kube, secret)
			credential := fixtureSecretValue(secret)
			f.secrets = append(f.secrets, credential)
			form.Set("client_secret", credential)
		} else if app.Status.ClientSecret != nil {
			f.t.Fatal("SPA acquired Secret")
		}
		if kind == "m2m" {
			form.Set("grant_type", "client_credentials")
		} else {
			verifier := fixtureSecret(f.t)
			challenge := sha256.Sum256([]byte(verifier))
			nonce, state := "fixture-nonce", "fixture-state"
			authorize := url.Values{"client_id": {clientID}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {callback}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
			bad := maps.Clone(authorize)
			bad.Set("redirect_uri", callback+"-foreign")
			status, _, _ := protocolHTTP(f, protocolBrowser(f), http.MethodGet, issuer+"/protocol/openid-connect/auth?"+bad.Encode(), nil)
			if status != http.StatusBadRequest {
				f.t.Fatalf("OIDC accepted foreign redirect: HTTP %d", status)
			}
			headers, _ := loginProtocol(f, protocolBrowser(f), http.MethodGet, issuer+"/protocol/openid-connect/auth?"+authorize.Encode(), nil, username, password, callback)
			redirect, err := url.Parse(headers.Get("Location"))
			f.requireNoError(err)
			if redirect.Query().Get("state") != state || redirect.Query().Get("code") == "" {
				f.t.Fatal("OIDC authorization code/state missing")
			}
			form.Set("grant_type", "authorization_code")
			form.Set("code", redirect.Query().Get("code"))
			form.Set("redirect_uri", callback)
			form.Set("code_verifier", verifier)
		}
		status, headers, data := protocolHTTP(f, f.http, http.MethodPost, issuer+"/protocol/openid-connect/token", form)
		fixtureEqual(f.t, "OIDC token status", status, http.StatusOK)
		var tokens struct {
			AccessToken string `json:"access_token"`
			IDToken     string `json:"id_token"`
			Scope       string `json:"scope"`
		}
		f.requireNoError(json.Unmarshal(data, &tokens))
		claims := fixtureVerifyJWT(f, tokens.AccessToken, issuer, clientID)
		fixtureEqual(f.t, "managed OIDC claim", claims["deployment_environment"], value)
		if kind != "m2m" {
			idClaims := fixtureVerifyJWT(f, tokens.IDToken, issuer, clientID)
			fixtureEqual(f.t, "OIDC nonce", idClaims["nonce"], "fixture-nonce")
			if !strings.Contains(tokens.Scope, "openid") {
				f.t.Fatal("OIDC openid scope missing")
			}
		}
		if kind == "spa" {
			request, err := http.NewRequest(http.MethodOptions, issuer+"/protocol/openid-connect/token", nil)
			f.requireNoError(err)
			request.Header.Set("Origin", "https://"+clientID+".example.test")
			request.Header.Set("Access-Control-Request-Method", "POST")
			response, err := f.http.Do(request)
			f.requireNoError(err)
			response.Body.Close()
			fixtureEqual(f.t, "SPA CORS origin", response.Header.Get("Access-Control-Allow-Origin"), "https://"+clientID+".example.test")
		}
		_ = headers
		fixtureReconcile(f, ctx, ar, app)
		fixtureEqual(f.t, "legacy OIDC UUID/mappers/attributes stable", f.client("managed", clientID), provider)
	}
}

func qualifyApplicationLifecycle(f *keycloakFixture, ctx context.Context, kube client.Client, ar *controller.HankoApplicationReconciler, saml *api.HankoApplication) {
	fixtureGet(f, ctx, kube, saml)
	provider := f.client("managed", saml.Spec.ClientID)
	id := provider["id"].(string)
	f.admin(http.MethodPut, "/admin/realms/managed/clients/"+id+"/roles/use", map[string]any{"name": "use", "description": "drifted"}, nil)
	provider["attributes"].(map[string]any)["saml.assertion.signature"] = "false"
	f.admin(http.MethodPut, "/admin/realms/managed/clients/"+id, provider, nil)
	fixtureReconcile(f, ctx, ar, saml)
	var repairedRole map[string]any
	f.admin(http.MethodGet, "/admin/realms/managed/clients/"+id+"/roles/use", nil, &repairedRole)
	fixtureEqual(f.t, "shared client role description drift repaired", repairedRole["description"], "Use application")
	fixtureEqual(f.t, "SAML signing drift repaired", f.client("managed", saml.Spec.ClientID)["attributes"].(map[string]any)["saml.assertion.signature"], "true")
	fixtureGet(f, ctx, kube, saml)
	before := f.client("managed", saml.Spec.ClientID)
	spec := saml.Spec
	saml.Spec.SAML = nil
	saml.Spec.Protocol = "oidc"
	saml.Spec.Type = "web"
	saml.Generation++
	f.requireNoError(kube.Update(ctx, saml))
	fixtureReconcile(f, ctx, ar, saml)
	fixtureGet(f, ctx, kube, saml)
	if !applicationHasCondition(saml.Status.Conditions, "Synced", metav1.ConditionFalse, "ProtocolChangeRequiresRecreation") {
		f.t.Fatal("owned protocol conversion was not refused")
	}
	fixtureEqual(f.t, "refused conversion preserves client", f.client("managed", saml.Spec.ClientID), before)
	saml.Spec = spec
	saml.Generation++
	f.requireNoError(kube.Update(ctx, saml))
	fixtureReconcile(f, ctx, ar, saml)
	fixtureGet(f, ctx, kube, saml)
	observer := &api.HankoApplication{ObjectMeta: fixtureMeta("saml-observe"), Spec: spec}
	observer.Spec.Mode = "Observe"
	observer.Status.AppliedPlanHash = "sha256:" + strings.Repeat("a", 64)
	f.requireNoError(kube.Create(ctx, observer))
	fixtureReconcile(f, ctx, ar, observer)
	fixtureGet(f, ctx, kube, observer)
	if observer.Status.Phase != "Ready" || observer.Status.AppliedPlanHash != "" || observer.Status.AppliedGeneration != 0 || len(observer.Finalizers) != 0 || observer.Status.ClientSecret != nil {
		f.t.Fatal("SAML Observe acquired execution authority/credential")
	}
	fixtureEqual(f.t, "Observe preserves client", f.client("managed", saml.Spec.ClientID), before)
	f.requireNoError(kube.Delete(ctx, saml))
	fixtureReconcile(f, ctx, ar, saml)
	exists, err := f.kc.ClientExists(ctx, "managed", spec.ClientID)
	f.requireNoError(err)
	if exists {
		f.t.Fatal("UID-owned SAML client was not deleted")
	}
}

func duplicateSAMLAssertion(t *testing.T, data []byte) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatal(err)
	}
	assertion, err := singleSAMLChild(doc.Root(), samlAssertionNS, "Assertion")
	if err != nil {
		t.Fatal(err)
	}
	doc.Root().AddChild(assertion.Copy())
	result, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func applicationHasCondition(conditions []metav1.Condition, kind string, status metav1.ConditionStatus, reason string) bool {
	for _, condition := range conditions {
		if condition.Type == kind {
			return condition.Status == status && condition.Reason == reason
		}
	}
	return false
}
