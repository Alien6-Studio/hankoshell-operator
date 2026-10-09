//go:build keycloak_integration

package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/roles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These probes characterize provider primitives, not a production adoption API.
// Bootstrap provisions disposable foreign objects. Dedicated target-realm
// identities perform every observation, owner-only PUT and deletion below.
type adoptionProbe struct {
	f            *keycloakFixture
	name, secret string
}

func (p adoptionProbe) request(method, path string, payload, target any) int {
	p.f.t.Helper()
	data, err := json.Marshal(payload)
	p.f.requireNoError(err)
	token := p.f.token(url.Values{"client_id": {p.name}, "client_secret": {p.secret}, "grant_type": {"client_credentials"}})
	req, err := http.NewRequest(method, p.f.baseURL+path, bytes.NewReader(data))
	p.f.requireNoError(err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := p.f.http.Do(req)
	p.f.requireNoError(err)
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	p.f.requireNoError(err)
	if len(body) > 1<<20 {
		p.f.t.Fatal("characterization response exceeds budget")
	}
	if target != nil && response.StatusCode == http.StatusOK {
		p.f.requireNoError(json.Unmarshal(body, target))
	}
	return response.StatusCode
}

func (p adoptionProbe) read(path string) map[string]any {
	p.f.t.Helper()
	var result map[string]any
	fixtureEqual(p.f.t, "scoped observation", p.request(http.MethodGet, path, nil, &result), http.StatusOK)
	return result
}

func (p adoptionProbe) list(path string) []map[string]any {
	p.f.t.Helper()
	var result []map[string]any
	fixtureEqual(p.f.t, "scoped collection observation", p.request(http.MethodGet, path, nil, &result), http.StatusOK)
	sort.Slice(result, func(i, j int) bool { return adoptionObjectKey(result[i]) < adoptionObjectKey(result[j]) })
	return result
}

func adoptionObjectKey(value map[string]any) string {
	for _, key := range []string{"id", "_id", "name"} {
		if id, ok := value[key].(string); ok {
			return id
		}
	}
	return ""
}

func adoptionScopedWriter(f *keycloakFixture, name, role string) (adoptionProbe, *keycloak.Client) {
	f.t.Helper()
	kc, secret := f.serviceClient(name)
	f.grantClientRoles(name, "managed", []string{role})
	return adoptionProbe{f, name, secret}, kc
}

func adoptionClone(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(fixtureJSON(t, value), &result); err != nil {
		t.Fatal("invalid characterization snapshot")
	}
	// Administrative representations may contain credentials; never send those
	// back as part of an ownership write or put them into diagnostic output.
	delete(result, "secret")
	// These client scope collections are sets; Keycloak may reorder them on
	// PUT. Preserve semantic equality without dropping any native field.
	for _, key := range []string{"defaultClientScopes", "optionalClientScopes"} {
		if values, ok := result[key].([]any); ok {
			sort.Slice(values, func(i, j int) bool { return values[i].(string) < values[j].(string) })
		}
	}
	return result
}

func adoptionCredentialStatus(f *keycloakFixture, clientID, credential, grant string) int {
	f.t.Helper()
	form := url.Values{"client_id": {clientID}, "client_secret": {credential}, "grant_type": {grant}}
	if grant == "authorization_code" {
		form.Set("code", "nonexistent-fixture-code")
	}
	response, err := f.http.PostForm(f.baseURL+"/realms/managed/protocol/openid-connect/token", form)
	f.requireNoError(err)
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	f.requireNoError(err)
	return response.StatusCode
}

func newAdoptionInventoryProxy(t *testing.T, f *keycloakFixture, name, secret string) (*keycloak.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	upstream, err := url.Parse(f.baseURL)
	f.requireNoError(err)
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(upstream); r.Out.Host = upstream.Host },
		Transport: f.http.Transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "fixture upstream unavailable", http.StatusBadGateway)
		},
	}
	// An exact route allowlist fixes every upstream URL to the disposable
	// loopback fixture; incoming request URLs never select another destination.
	allowed := map[string]bool{}
	for _, path := range []string{"/realms/master/protocol/openid-connect/token", "/admin/realms", "/admin/realms/managed/clients", "/admin/realms/managed/identity-provider/instances", "/admin/realms/managed/identity-provider/instances/existing-broker/mappers"} {
		allowed[path] = true
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if len(seen) >= 1024 {
			mu.Unlock()
			http.Error(w, "inventory route budget exceeded", http.StatusForbidden)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, ok := allowed[r.URL.Path]
		if !ok || strings.Contains(r.URL.Path, "client-secret") || (r.Method != http.MethodGet && r.URL.Path != "/realms/master/protocol/openid-connect/token") {
			http.Error(w, "inventory may not mutate or read credentials", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	kc, err := keycloak.NewWithTLS(server.URL, name, secret, ca)
	f.requireNoError(err)
	f.requireNoError(kc.RequireHTTPS())
	return kc, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func newAdoptionLostAckProxy(t *testing.T, f *keycloakFixture, name, secret, path string) (*keycloak.Client, func() int) {
	t.Helper()
	upstream, err := url.Parse(f.baseURL)
	f.requireNoError(err)
	var mu sync.Mutex
	committed := 0
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(upstream); r.Out.Host = upstream.Host },
		Transport: f.http.Transport,
		ModifyResponse: func(r *http.Response) error {
			if r.Request.Method == http.MethodPut && r.StatusCode == http.StatusNoContent {
				mu.Lock()
				committed++
				mu.Unlock()
				// Keycloak committed the write, but the caller receives no success
				// acknowledgement. Do not disclose upstream bodies or headers.
				return io.ErrUnexpectedEOF
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "fixture acknowledgement unavailable", http.StatusBadGateway)
		},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == path && (r.Method == http.MethodGet || r.Method == http.MethodPut)) || (r.URL.Path == "/realms/master/protocol/openid-connect/token" && r.Method == http.MethodPost) {
			proxy.ServeHTTP(w, r)
			return
		}
		http.Error(w, "fixture route not allowed", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	kc, err := keycloak.NewWithTLS(server.URL, name, secret, ca)
	f.requireNoError(err)
	f.requireNoError(kc.RequireHTTPS())
	return kc, func() int {
		mu.Lock()
		defer mu.Unlock()
		return committed
	}
}

func TestRealKeycloakAdoptionCharacterization(t *testing.T) {
	f := newKeycloakFixture(t)
	_, readSecret := f.serviceClient("adoption-reader")
	reader := adoptionProbe{f, "adoption-reader", readSecret}
	f.grantClientRoles(reader.name, "managed", []string{"view-realm", "view-clients", "view-users", "view-identity-providers", "view-authorization", "view-organizations"})
	writerKC, writeSecret := f.serviceClient("adoption-writer")
	writer := adoptionProbe{f, "adoption-writer", writeSecret}
	f.grantClientRoles(writer.name, "managed", []string{"manage-realm", "manage-clients", "manage-users", "manage-identity-providers"})
	base := "/admin/realms/managed"
	ctx := context.Background()

	f.run("client owner-only preservation and SAML inventory", func(t *testing.T) {
		writer, writerKC := adoptionScopedWriter(f, "client-owner-writer", "manage-clients")
		for _, kind := range []string{"spa", "web", "m2m", "saml"} {
			name, protocol := "existing-"+kind, "openid-connect"
			if kind == "saml" {
				name, protocol = "https://existing.example.test/saml", "saml"
			}
			credential := fixtureSecret(t)
			f.secrets = append(f.secrets, credential)
			f.admin(http.MethodPost, base+"/clients", map[string]any{
				"clientId": name, "name": "Existing " + kind, "protocol": protocol, "enabled": true,
				"publicClient": kind == "spa", "serviceAccountsEnabled": kind == "m2m",
				"standardFlowEnabled": kind != "m2m", "fullScopeAllowed": false, "secret": credential,
				"redirectUris": []string{"https://existing.example.test/acs"},
				"attributes":   map[string]string{"native.future.option": "preserve", "saml.server.signature": "true"},
			}, nil)
			cl := f.client("managed", name)
			path := base + "/clients/" + cl["id"].(string)
			f.admin(http.MethodPost, path+"/roles", map[string]any{"name": "foreign-access", "description": "Foreign role"}, nil)
			if kind != "saml" {
				f.admin(http.MethodPost, path+"/protocol-mappers/models", map[string]any{
					"name": "foreign-claim", "protocol": protocol, "protocolMapper": "oidc-hardcoded-claim-mapper",
					"config": map[string]string{"claim.name": "native", "claim.value": "preserve", "jsonType.label": "String"},
				}, nil)
			}
			before := adoptionClone(t, reader.read(path))
			roles := reader.list(path + "/roles")
			mappers := reader.list(path + "/protocol-mappers/models")
			fixtureEqual(t, "inventory cannot mark owner", reader.request(http.MethodPut, path, before, nil), http.StatusForbidden)
			got, err := writerKC.GetApplication(ctx, "managed", name)
			f.requireNoError(err)
			// Exercise the existing production owner-only primitive, without
			// enabling Manage or using an imported object as approval authority.
			f.requireNoError(writerKC.MarkApplicationOwner(ctx, "managed", *got, applications.OwnerAttribute, "probe-"+kind))
			after := adoptionClone(t, reader.read(path))
			attrs := after["attributes"].(map[string]any)
			fixtureEqual(t, "client owner read-back", attrs[applications.OwnerAttribute], "probe-"+kind)
			delete(attrs, applications.OwnerAttribute)
			fixtureEqual(t, "owner-only client PUT preserves all non-secret fields", after, before)
			fixtureEqual(t, "owner-only client PUT preserves role IDs", reader.list(path+"/roles"), roles)
			fixtureEqual(t, "owner-only client PUT preserves mapper IDs", reader.list(path+"/protocol-mappers/models"), mappers)
			if len(mappers) > 0 {
				mapper := adoptionClone(t, mappers[0])
				mapper["config"].(map[string]any)[applications.OwnerAttribute] = "probe-" + kind
				mapperPath := path + "/protocol-mappers/models/" + mapper["id"].(string)
				fixtureEqual(t, "protocol mapper ownership-only PUT", writer.request(http.MethodPut, mapperPath, mapper, nil), http.StatusNoContent)
				fixtureEqual(t, "protocol mapper UUID and semantics preserved", reader.read(mapperPath), mapper)
			}
			if kind == "web" || kind == "m2m" {
				expected, grant := http.StatusBadRequest, "authorization_code" // Valid web credential, invalid disposable code.
				if kind == "m2m" {
					expected, grant = http.StatusOK, "client_credentials"
				}
				fixtureEqual(t, "known confidential credential preserved", adoptionCredentialStatus(f, name, credential, grant), expected)
				fixtureEqual(t, "wrong confidential credential denied", adoptionCredentialStatus(f, name, fixtureSecret(t), grant), http.StatusUnauthorized)
			}
			if err := writerKC.DeleteApplicationIfOwned(ctx, "managed", got.ID, name, applications.OwnerAttribute, "foreign-uid"); err == nil {
				t.Fatal("foreign owner deletion accepted")
			}
		}
	})

	f.run("owner write remains provable after lost acknowledgement", func(t *testing.T) {
		writer, writerKC := adoptionScopedWriter(f, "lost-ack-writer", "manage-clients")
		f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": "lost-ack-client", "protocol": "openid-connect", "enabled": true, "publicClient": true, "attributes": map[string]string{"native.future.option": "keep"}}, nil)
		expected, err := writerKC.GetApplication(ctx, "managed", "lost-ack-client")
		f.requireNoError(err)
		path := base + "/clients/" + expected.ID
		before := adoptionClone(t, reader.read(path))
		flaky, committed := newAdoptionLostAckProxy(t, f, writer.name, writer.secret, path)
		if err := flaky.MarkApplicationOwner(ctx, "managed", *expected, applications.OwnerAttribute, "lost-ack-owner"); err == nil {
			t.Fatal("lost ownership acknowledgement appeared successful")
		}
		fixtureEqual(t, "owner write committed exactly once", committed(), 1)
		after := adoptionClone(t, reader.read(path))
		fixtureEqual(t, "fresh read proves owner after ambiguous write", after["attributes"].(map[string]any)[applications.OwnerAttribute], "lost-ack-owner")
		delete(after["attributes"].(map[string]any), applications.OwnerAttribute)
		fixtureEqual(t, "lost acknowledgement preserves native state", after, before)
		// No local adoption status was retained. The remote marker is evidence;
		// blindly retrying the unmarked precondition must not acquire it again.
		if err := flaky.MarkApplicationOwner(ctx, "managed", *expected, applications.OwnerAttribute, "lost-ack-owner"); err == nil {
			t.Fatal("blind owner acquisition retry accepted")
		}
		fixtureEqual(t, "retry performs no second owner PUT", committed(), 1)
	})

	f.run("realm role owner-only preserves direct and effective composites", func(t *testing.T) {
		writer, writerKC := adoptionScopedWriter(f, "role-owner-writer", "manage-realm")
		for _, name := range []string{"existing-leaf", "existing-middle", "existing-root"} {
			f.admin(http.MethodPost, base+"/roles", map[string]any{"name": name, "description": "Existing description", "attributes": map[string][]string{"native": {"keep"}}}, nil)
		}
		leaf, middle := reader.read(base+"/roles/existing-leaf"), reader.read(base+"/roles/existing-middle")
		f.admin(http.MethodPost, base+"/roles/existing-middle/composites", []any{leaf}, nil)
		f.admin(http.MethodPost, base+"/roles/existing-root/composites", []any{middle}, nil)
		path := base + "/roles/existing-root"
		before := reader.read(path)
		direct := reader.list(path + "/composites")
		closure, err := writerKC.GetRealmRoleClosure(ctx, "managed", "existing-root")
		f.requireNoError(err)
		next := adoptionClone(t, before)
		next["attributes"].(map[string]any)[roles.OwnerAttribute] = []any{"probe-role"}
		fixtureEqual(t, "inventory cannot mark role", reader.request(http.MethodPut, path, next, nil), http.StatusForbidden)
		fixtureEqual(t, "role marker-only update", writer.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "role marker read-back", reader.read(path), next)
		fixtureEqual(t, "role marker no-op", writer.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "direct composite IDs preserved", reader.list(path+"/composites"), direct)
		afterClosure, err := writerKC.GetRealmRoleClosure(ctx, "managed", "existing-root")
		f.requireNoError(err)
		for i := range afterClosure {
			delete(afterClosure[i].Attributes, roles.OwnerAttribute)
		}
		fixtureEqual(t, "effective composites preserved", afterClosure, closure)
		fixtureEqual(t, "owned role delete primitive", writer.request(http.MethodDelete, path, nil, nil), http.StatusNoContent)
		fixtureEqual(t, "role deletion preserves child role", reader.read(base+"/roles/existing-leaf"), leaf)
	})

	f.run("legacy approval also protects unmarked SAML migration", func(t *testing.T) {
		_, operator := adoptionScopedWriter(f, "saml-migration-writer", "manage-clients")
		entity, acs := "https://migration.example.test/saml", "https://migration.example.test/acs"
		f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": entity, "protocol": "saml", "enabled": true, "publicClient": false, "standardFlowEnabled": true, "serviceAccountsEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "fullScopeAllowed": false, "webOrigins": []string{}, "redirectUris": []string{acs}, "attributes": map[string]string{"saml.server.signature": "true", "saml.assertion.signature": "true", "saml.client.signature": "false"}}, nil)
		before := f.client("managed", entity)
		app := &api.HankoApplication{ObjectMeta: fixtureMeta("saml-migration"), Spec: api.HankoApplicationSpec{RealmRef: "managed", ClientID: entity, Protocol: "saml", SAML: &api.ApplicationSAML{AssertionConsumerServices: []string{acs}}}}
		kube := newFakeClient(t, app)
		r := &controller.HankoApplicationReconciler{Client: kube, OwnershipReader: kube, Scheme: newScheme(t), Pool: keycloak.NewPool(operator)}
		fixtureReconcile(f, ctx, r, app)
		fixtureGet(f, ctx, kube, app)
		if !applicationHasCondition(app.Status.Conditions, "Synced", metav1.ConditionFalse, "OwnershipApprovalRequired") || !app.Status.ObservationComplete {
			t.Fatal("unmarked SAML did not require complete explicit approval")
		}
		app.Annotations = map[string]string{applications.MigrationUUIDAnnotation: before["id"].(string), applications.MigrationObservationAnnotation: app.Status.ObservedStateHash}
		f.requireNoError(kube.Update(ctx, app))
		// A material provider change invalidates the otherwise exact approval.
		changed := adoptionClone(t, before)
		changed["name"] = "Changed after observation"
		fixtureEqual(t, "SAML change probe", writer.request(http.MethodPut, base+"/clients/"+before["id"].(string), changed, nil), http.StatusNoContent)
		fixtureReconcile(f, ctx, r, app)
		fixtureGet(f, ctx, kube, app)
		if app.Status.Phase != "Conflict" {
			t.Fatal("stale SAML approval accepted")
		}
		fixtureEqual(t, "stale approval did not acquire owner", f.client("managed", entity)["attributes"].(map[string]any)[applications.OwnerAttribute], nil)
		app.Annotations[applications.MigrationObservationAnnotation] = app.Status.ObservedStateHash
		f.requireNoError(kube.Update(ctx, app))
		f.admin(http.MethodPut, base+"/events/config", map[string]any{"adminEventsEnabled": true, "adminEventsDetailsEnabled": false}, nil)
		fault := &failEvidenceStatusClient{Client: kube, fail: true}
		r.Client = fault
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err == nil {
			t.Fatal("migration status failure was ignored")
		}
		fixtureGet(f, ctx, kube, app)
		if app.Status.Phase == "Ready" {
			t.Fatal("failed migration status patch stored Ready")
		}
		fixtureEqual(t, "provider owner survives status failure", reader.read(base + "/clients/" + before["id"].(string))["attributes"].(map[string]any)[applications.OwnerAttribute], string(app.UID))
		writes := func() int {
			var events []map[string]any
			f.admin(http.MethodGet, base+"/admin-events?max=1000", nil, &events)
			return len(events)
		}
		iamconformance.NoMutation(t, writes, func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
			return err
		})
		fixtureGet(f, ctx, kube, app)
		if app.Status.Phase != "Ready" || app.Status.Protocol != "saml" {
			t.Fatal("fresh exact SAML migration failed")
		}
		fixtureEqual(t, "SAML migration retains exact UUID", f.client("managed", entity)["id"], before["id"])
	})

	f.run("group and native organization independent checkpoints", func(t *testing.T) {
		groupWriter, _ := adoptionScopedWriter(f, "group-owner-writer", "manage-users")
		orgWriter, _ := adoptionScopedWriter(f, "native-org-owner-writer", "manage-organizations")
		f.admin(http.MethodPost, base+"/groups", map[string]any{"name": "Existing", "attributes": map[string][]string{"native": {"keep"}}}, nil)
		group, err := writerKC.GetGroupByPath(ctx, "managed", "/Existing")
		f.requireNoError(err)
		path := base + "/groups/" + group.ID
		f.admin(http.MethodPost, path+"/children", map[string]any{"name": "Child"}, nil)
		leaf := reader.read(base + "/roles/existing-leaf")
		f.admin(http.MethodPost, path+"/role-mappings/realm", []any{leaf}, nil)
		children, mappings := reader.list(path+"/children"), reader.read(path+"/role-mappings")
		before := reader.read(path)
		next := adoptionClone(t, before)
		for key, value := range map[string]string{organization.OwnerName: "existing", organization.OwnerNamespace: "qualification", organization.OwnerUID: "probe-org"} {
			next["attributes"].(map[string]any)[key] = []any{value}
		}
		fixtureEqual(t, "inventory cannot mark group", reader.request(http.MethodPut, path, next, nil), http.StatusForbidden)
		fixtureEqual(t, "group marker-only update", groupWriter.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "group marker read-back", reader.read(path), next)
		fixtureEqual(t, "group children preserved", reader.list(path+"/children"), children)
		fixtureEqual(t, "group mappings preserved", reader.read(path+"/role-mappings"), mappings)
		f.requireNoError(writerKC.EnsureOrganizationsEnabled(ctx, "managed"))
		f.admin(http.MethodPost, base+"/organizations", map[string]any{"name": "Existing", "alias": "existing", "enabled": true, "domains": []any{map[string]any{"name": "existing.example.test"}}, "attributes": map[string][]string{"native": {"keep"}}}, nil)
		org, err := writerKC.GetOrganizationByAlias(ctx, "managed", "existing")
		f.requireNoError(err)
		orgPath := base + "/organizations/" + org.ID
		orgBefore := reader.read(orgPath)
		orgNext := adoptionClone(t, orgBefore)
		for key, value := range map[string]string{organization.OwnerName: "existing", organization.OwnerNamespace: "qualification", organization.OwnerUID: "probe-org"} {
			orgNext["attributes"].(map[string]any)[key] = []any{value}
		}
		fixtureEqual(t, "second checkpoint denied to inventory", reader.request(http.MethodPut, orgPath, orgNext, nil), http.StatusForbidden)
		fixtureEqual(t, "failed second checkpoint leaves group owned", reader.read(path), next)
		fixtureEqual(t, "failed second checkpoint leaves org untouched", reader.read(orgPath), orgBefore)
		// Discard acknowledgement/status; recover exclusively by fresh provider
		// reads. This is a primitive retry probe, not a transactional controller.
		fixtureEqual(t, "native organization owner-only update", orgWriter.request(http.MethodPut, orgPath, orgNext, nil), http.StatusNoContent)
		fixtureEqual(t, "native organization read-back", reader.read(orgPath), orgNext)
		fixtureEqual(t, "retry group marker no-op", groupWriter.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "retry organization marker no-op", orgWriter.request(http.MethodPut, orgPath, orgNext, nil), http.StatusNoContent)
		fixtureEqual(t, "native org delete", orgWriter.request(http.MethodDelete, orgPath, nil, nil), http.StatusNoContent)
		fixtureEqual(t, "native org deletion preserves structural group", reader.read(path), next)
		fixtureEqual(t, "group delete", groupWriter.request(http.MethodDelete, path, nil, nil), http.StatusNoContent)
		fixtureEqual(t, "group delete cascades child", reader.request(http.MethodGet, base+"/groups/"+children[0]["id"].(string), nil, nil), http.StatusNotFound)
	})

	f.run("realm identity and owner metadata do not make realm deletion safe", func(t *testing.T) {
		before := reader.read(base)
		if before["id"] == "" || before["id"] == nil {
			t.Fatal("realm has no stable ID")
		}
		next := adoptionClone(t, before)
		attrs, _ := next["attributes"].(map[string]any)
		if attrs == nil {
			attrs = map[string]any{}
		}
		attrs["hanko.sh/rfc-owner"] = "probe-realm"
		next["attributes"] = attrs
		fixtureEqual(t, "inventory cannot mark realm", reader.request(http.MethodPut, base, next, nil), http.StatusForbidden)
		fixtureEqual(t, "realm metadata PUT", writer.request(http.MethodPut, base, next, nil), http.StatusNoContent)
		after := reader.read(base)
		fixtureEqual(t, "realm UUID preserved", after["id"], before["id"])
		fixtureEqual(t, "realm marker round-trip", after["attributes"].(map[string]any)["hanko.sh/rfc-owner"], "probe-realm")
		fixtureEqual(t, "realm display name preserved", after["displayName"], before["displayName"])
		if len(reader.list(base+"/clients")) == 0 {
			t.Fatal("realm marker removed children")
		}
		f.admin(http.MethodPost, "/admin/realms", map[string]any{"realm": "adoption-delete-boundary", "enabled": true}, nil)
		f.admin(http.MethodPost, "/admin/realms/adoption-delete-boundary/clients", map[string]any{"clientId": "foreign-child"}, nil)
		child := f.client("adoption-delete-boundary", "foreign-child")
		f.grantClientRoles(writer.name, "adoption-delete-boundary", []string{"manage-realm", "view-clients"})
		fixtureEqual(t, "realm deletion primitive", writer.request(http.MethodDelete, "/admin/realms/adoption-delete-boundary", nil, nil), http.StatusNoContent)
		fixtureEqual(t, "realm deletion cascades unrelated client", f.admin(http.MethodGet, "/admin/realms/adoption-delete-boundary/clients/"+child["id"].(string), nil, nil), http.StatusNotFound)
	})

	f.run("broker opaque credential and mapper marker boundaries", func(t *testing.T) {
		writer, _ := adoptionScopedWriter(f, "broker-owner-writer", "manage-identity-providers")
		credential := fixtureSecret(t)
		f.secrets = append(f.secrets, credential)
		f.admin(http.MethodPost, base+"/identity-provider/instances", map[string]any{"alias": "existing-broker", "providerId": "oidc", "enabled": false, "config": map[string]string{"clientId": "broker", "clientSecret": credential, "authorizationUrl": "https://idp.example.test/auth", "tokenUrl": "https://idp.example.test/token", "native.future.option": "keep"}}, nil)
		path := base + "/identity-provider/instances/existing-broker"
		before := reader.read(path)
		if before["internalId"] == nil || before["internalId"] == "" {
			t.Fatal("broker lacks immutable internal identity")
		}
		cfg := before["config"].(map[string]any)
		if cfg["clientSecret"] == credential {
			t.Fatal("broker observation exposed credential (value withheld)")
		}
		next := adoptionClone(t, before)
		next["config"].(map[string]any)["hanko.sh/rfc-owner"] = "probe-broker"
		fixtureEqual(t, "inventory cannot mark broker", reader.request(http.MethodPut, path, next, nil), http.StatusForbidden)
		fixtureEqual(t, "broker experimental config marker", writer.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "broker marker representation round-trip only", reader.read(path), next)
		f.admin(http.MethodPost, path+"/mappers", map[string]any{"name": "existing-mapper", "identityProviderAlias": "existing-broker", "identityProviderMapper": "oidc-user-attribute-idp-mapper", "config": map[string]string{"claim": "department", "user.attribute": "department", "syncMode": "INHERIT"}}, nil)
		mappers := reader.list(path + "/mappers")
		mapper := adoptionClone(t, mappers[0])
		mapper["config"].(map[string]any)[applications.OwnerAttribute] = "probe-mapper"
		mapperPath := path + "/mappers/" + mapper["id"].(string)
		fixtureEqual(t, "mapper marker update", writer.request(http.MethodPut, mapperPath, mapper, nil), http.StatusNoContent)
		fixtureEqual(t, "mapper UUID/config preserved", reader.read(mapperPath), mapper)
		fixtureEqual(t, "mapper delete primitive", writer.request(http.MethodDelete, mapperPath, nil, nil), http.StatusNoContent)
		fixtureEqual(t, "mapper deletion preserves broker", reader.read(path), next)
	})

	f.run("selective authorization journal preserves foreign graph", func(t *testing.T) {
		writer, _ := adoptionScopedWriter(f, "journal-owner-writer", "manage-clients")
		f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": "existing-server", "protocol": "openid-connect", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": true, "attributes": map[string]string{applications.OwnerAttribute: "probe-app"}}, nil)
		cl := f.client("managed", "existing-server")
		path := base + "/clients/" + cl["id"].(string)
		authz := path + "/authz/resource-server"
		f.admin(http.MethodPost, authz+"/scope", map[string]any{"name": "portable-read"}, nil)
		scopes := reader.list(authz + "/scope")
		var selected map[string]any
		for _, s := range scopes {
			if s["name"] == "portable-read" {
				selected = s
			}
		}
		if selected == nil {
			t.Fatal("selected scope missing")
		}
		f.admin(http.MethodPost, authz+"/resource", map[string]any{"name": "foreign-resource", "type": "urn:foreign:resource", "scopes": []any{selected}}, nil)
		leaf := reader.read(base + "/roles/existing-leaf")
		f.admin(http.MethodPost, authz+"/policy/role", map[string]any{"name": "foreign-role", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "roles": []any{map[string]any{"id": leaf["id"], "required": false}}}, nil)
		rolePolicies := reader.list(authz + "/policy/role")
		f.admin(http.MethodPost, authz+"/policy/aggregate", map[string]any{"name": "foreign-native-aggregate", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "policies": []string{rolePolicies[0]["id"].(string)}}, nil)
		aggregates := reader.list(authz + "/policy/aggregate")
		f.admin(http.MethodPost, authz+"/permission/scope", map[string]any{"name": "foreign-permission", "scopes": []string{selected["id"].(string)}, "policies": []string{aggregates[0]["id"].(string)}, "decisionStrategy": "UNANIMOUS"}, nil)
		before := reader.read(path)
		resources, policies, permissions := reader.list(authz+"/resource?deep=true"), reader.list(authz+"/policy"), reader.list(authz+"/permission")
		if len(policies) == 0 || len(resources) == 0 || len(permissions) == 0 {
			t.Fatal("foreign native authorization graph missing")
		}
		journal := map[string]any{"version": 1, "ownerUID": "probe-server", "objects": map[string]any{"resourceServerID": cl["id"], "scopes": []any{map[string]any{"name": "portable-read", "id": selected["id"]}}}}
		next := adoptionClone(t, before)
		next["attributes"].(map[string]any)["hanko.sh/resource-server-ownership"] = string(fixtureJSON(t, journal))
		fixtureEqual(t, "reader cannot acquire journal", reader.request(http.MethodPut, path, next, nil), http.StatusForbidden)
		fixtureEqual(t, "journal-only update", writer.request(http.MethodPut, path, next, nil), http.StatusNoContent)
		fixtureEqual(t, "selective journal read-back", adoptionClone(t, reader.read(path)), next)
		fixtureEqual(t, "journal preserves scopes", reader.list(authz+"/scope"), scopes)
		fixtureEqual(t, "journal preserves native resources", reader.list(authz+"/resource?deep=true"), resources)
		fixtureEqual(t, "journal preserves native policies", reader.list(authz+"/policy"), policies)
		fixtureEqual(t, "journal preserves permissions", reader.list(authz+"/permission"), permissions)
		// The selected scope is shared by a foreign permission/resource. It
		// must not be used as a cleanup target: provider DELETE can alter those
		// foreign bindings. Characterize deletion only on an isolated scope.
		f.admin(http.MethodPost, authz+"/scope", map[string]any{"name": "isolated-delete-probe"}, nil)
		for _, s := range reader.list(authz + "/scope") {
			if s["name"] == "isolated-delete-probe" {
				fixtureEqual(t, "isolated scope delete", writer.request(http.MethodDelete, authz+"/scope/"+s["id"].(string), nil, nil), http.StatusNoContent)
			}
		}
		fixtureEqual(t, "selective deletion preserves native policy", reader.list(authz+"/policy"), policies)
		fixtureEqual(t, "selective deletion preserves foreign resource", reader.list(authz+"/resource?deep=true"), resources)
		fixtureEqual(t, "selective deletion preserves foreign permission", reader.list(authz+"/permission"), permissions)
		fixtureEqual(t, "selective deletion preserves selected scope", reader.list(authz+"/scope"), scopes)
		fixtureEqual(t, "selective deletion preserves backing client", reader.read(path)["id"], cl["id"])
	})

	f.run("HankoImport read-only route inventory", func(t *testing.T) {
		f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": "https://import.example.test/saml", "protocol": "saml", "enabled": true}, nil)
		// A trusted TLS proxy records only paths/methods, never bodies or bearer
		// headers. It fails any Admin mutation or credential endpoint outright.
		proxy, routes := newAdoptionInventoryProxy(t, f, reader.name, reader.secret)
		kube := newFakeClient(t)
		operation := &api.HankoImport{ObjectMeta: fixtureMeta("inventory"), Spec: api.HankoImportSpec{SourceRef: "source", Realms: []string{"managed"}}}
		f.requireNoError(kube.Create(ctx, operation))
		r := &controller.HankoImportReconciler{Client: kube, Scheme: newScheme(t), Pool: keycloak.NewPool(proxy)}
		fixtureReconcile(f, ctx, r, operation)
		fixtureGet(f, ctx, kube, operation)
		if operation.Status.Phase != "Done" {
			for _, c := range operation.Status.Conditions {
				t.Logf("Import condition %s / %s", c.Type, c.Reason)
			}
			t.Logf("Import fixture routes (no bodies/headers): %v", routes())
			t.Fatal("read-only import did not complete")
		}
		var apps api.HankoApplicationList
		f.requireNoError(kube.List(ctx, &apps, client.InNamespace(operation.Namespace)))
		for _, app := range apps.Items {
			if app.Spec.Mode != "Observe" || app.Spec.Protocol == "saml" {
				t.Fatal("import unexpectedly manages or imports SAML")
			}
		}
		f.requireNoCredentials("import status", fixtureJSON(t, operation.Status))
		f.requireNoCredentials("imported application inventory", fixtureJSON(t, apps))
		var realms api.HankoRealmList
		var accounts api.HankoServiceAccountList
		f.requireNoError(kube.List(ctx, &realms, client.InNamespace(operation.Namespace)))
		f.requireNoError(kube.List(ctx, &accounts, client.InNamespace(operation.Namespace)))
		f.requireNoCredentials("imported realm/broker inventory", fixtureJSON(t, realms))
		f.requireNoCredentials("imported account inventory", fixtureJSON(t, accounts))
		for _, route := range routes() {
			if strings.Contains(route, "client-secret") || (!strings.HasPrefix(route, "GET ") && route != "POST /realms/master/protocol/openid-connect/token") {
				t.Fatal("inventory attempted forbidden route")
			}
		}
		gap := false
		for _, finding := range operation.Status.Findings {
			gap = gap || finding.Code == "application_protocol_import_unsupported"
		}
		if !gap {
			t.Fatal("SAML discovery gap was hidden")
		}
		if !strings.Contains(strings.Join(routes(), "\n"), "/identity-provider/instances") {
			t.Fatal("broker inventory not exercised")
		}
	})
	t.Logf("Keycloak %s: exact identity and ownership-only primitives characterized; no production adoption implemented", f.version)
}
