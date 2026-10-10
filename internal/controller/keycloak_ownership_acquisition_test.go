//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Bootstrap only provisions foreign fixtures and scoped identities. Normal
// acquisition runs through production reconcilers with separate reader/writers.
func TestRealKeycloakOwnershipAcquisition(t *testing.T) {
	f := newKeycloakFixture(t)
	_, readSecret := f.serviceClient("ownership-reader")
	f.grantClientRoles("ownership-reader", "managed", []string{"view-realm", "view-clients"})
	_, clientSecret := f.serviceClient("ownership-client-writer")
	f.grantClientRoles("ownership-client-writer", "managed", []string{"view-realm", "manage-clients"})
	_, roleSecret := f.serviceClient("ownership-role-writer")
	f.grantClientRoles("ownership-role-writer", "managed", []string{"manage-realm"})
	endpoint, _ := url.Parse(f.baseURL)
	var mu sync.Mutex
	puts, credentials := 0, 0
	loseAck := false
	proxy := httputil.NewSingleHostReverseProxy(endpoint)
	proxy.Transport = f.http.Transport
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "client-secret") || strings.Contains(r.URL.Path, "service-account-user") {
			mu.Lock()
			credentials++
			mu.Unlock()
			http.Error(w, "credential route excluded from acquisition", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPut {
			mu.Lock()
			puts++
			lost := loseAck
			loseAck = false
			mu.Unlock()
			if lost {
				r.Host = endpoint.Host
				proxy.ServeHTTP(httptest.NewRecorder(), r)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		r.Host = endpoint.Host
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	clientWriter, err := keycloak.NewWithTLS(server.URL, "ownership-client-writer", clientSecret, ca)
	f.requireNoError(err)
	roleWriter, err := keycloak.NewWithTLS(server.URL, "ownership-role-writer", roleSecret, ca)
	f.requireNoError(err)
	base := "/admin/realms/managed"
	reader := adoptionProbe{f, "ownership-reader", readSecret}
	for _, capability := range []string{"spa", "web", "m2m", "saml", "role"} {
		f.run(capability+" lossless owner-only acquisition", func(t *testing.T) {
			ctx := context.Background()
			name := "reviewed-" + capability
			clientID := name
			if capability == "saml" {
				clientID = "https://reviewed.example.test/saml"
			}
			var target client.Object
			var before map[string]any
			var rolesBefore, mappersBefore []map[string]any
			path := base + "/roles/" + name
			meta := fixtureMeta(name)
			meta.UID = types.UID("ownership-" + capability)
			meta.Generation = 1
			meta.Annotations = map[string]string{adoption.SourceAnnotation: "source"}
			credential := fixtureSecret(t)
			f.secrets = append(f.secrets, credential)
			if capability == "role" {
				f.admin(http.MethodPost, base+"/roles", map[string]any{"name": name, "description": "Reviewed leaf"}, nil)
				before = reader.read(path)
				target = &api.HankoRole{ObjectMeta: meta, Spec: api.HankoRoleSpec{Mode: "Observe", RealmRef: "managed", Name: name, Description: "Reviewed leaf"}}
			} else {
				protocol := "openid-connect"
				attrs := map[string]string{}
				redirects := []string{"https://reviewed.example.test/callback"}
				if capability == "m2m" {
					redirects = []string{}
				}
				if capability == "saml" {
					protocol = "saml"
					attrs = map[string]string{"saml.server.signature": "true", "saml.assertion.signature": "true", "saml_name_id_format": "persistent", "saml.client.signature": "false", "saml.signature.algorithm": "RSA_SHA256", "saml_force_name_id_format": "true", "saml.force.post.binding": "true", "saml.authnstatement": "true", "saml.encrypt": "false", "saml.artifact.binding": "false", "saml.allow.ecp.flow": "false", "saml_assertion_consumer_url_post": "https://reviewed.example.test/callback", "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#"}
				}
				f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": clientID, "name": clientID, "protocol": protocol, "enabled": true, "publicClient": capability == "spa", "standardFlowEnabled": capability != "m2m", "serviceAccountsEnabled": capability == "m2m", "directAccessGrantsEnabled": false, "fullScopeAllowed": false, "secret": credential, "redirectUris": redirects, "webOrigins": []string{}, "attributes": attrs, "defaultClientScopes": []string{}, "optionalClientScopes": []string{}, "frontchannelLogout": true}, nil)
				cl := f.client("managed", clientID)
				path = base + "/clients/" + cl["id"].(string)
				before = reader.read(path)
				if capability != "saml" {
					defaults := before["attributes"].(map[string]any)
					for key, want := range map[string]string{"realm_client": "false", "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "false"} {
						fixtureEqual(t, "qualified canonical Keycloak default", defaults[key], want)
					}
				}
				// Bootstrap constructs a leaf without opaque attributes or native scopes.
				// The three exact qualified Keycloak defaults remain reviewed facts.
				clean := adoptionClone(t, before)
				clean["attributes"] = attrs
				f.admin(http.MethodPut, path, clean, nil)
				if capability == "m2m" {
					var scopes []map[string]any
					f.admin(http.MethodGet, path+"/default-client-scopes", nil, &scopes)
					for _, scope := range scopes {
						f.admin(http.MethodDelete, path+"/default-client-scopes/"+scope["id"].(string), nil, nil)
					}
				}
				before = reader.read(path)

				if capability == "web" {
					f.admin(http.MethodPost, path+"/roles", map[string]any{"name": "use", "description": "Reviewed client role"}, nil)
					f.admin(http.MethodGet, path+"/roles", nil, &rolesBefore)
					f.admin(http.MethodGet, path+"/protocol-mappers/models", nil, &mappersBefore)
					before = reader.read(path)
				}
				if capability == "m2m" {
					target = &api.HankoServiceAccount{ObjectMeta: meta, Spec: api.HankoServiceAccountSpec{Mode: "Observe", RealmRef: "managed", ClientID: clientID}}
				} else {
					app := &api.HankoApplication{ObjectMeta: meta, Spec: api.HankoApplicationSpec{Mode: "Observe", RealmRef: "managed", ClientID: clientID, Type: capability, RedirectURIs: redirects}}
					if capability == "saml" {
						app.Spec.Protocol, app.Spec.Type, app.Spec.RedirectURIs = "saml", "", nil
						app.Spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: redirects, NameIDFormat: "persistent"}
					}
					target = app
				}
			}
			storage := newFakeClient(t, target,
				&api.HankoRealm{ObjectMeta: fixtureMeta("managed"), Spec: api.HankoRealmSpec{DisplayName: "Managed"}},
				&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: meta.Namespace, UID: "source-uid"}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
				&corev1.Secret{ObjectMeta: fixtureMeta("reader"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("ownership-reader"), "HANKO_KC_CLIENT_SECRET": []byte(readSecret)}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: meta.Namespace, UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}})
			failureClient := &ownershipStatusFailureClient{Client: storage}
			var kube client.Client = failureClient
			var reconcile func() error
			switch target.(type) {
			case *api.HankoRole:
				r := &controller.HankoRoleReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(roleWriter)}
				reconcile = func() error {
					_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(target)})
					return err
				}
			case *api.HankoServiceAccount:
				r := &controller.HankoServiceAccountReconciler{Client: kube, APIReader: kube, OwnershipReader: kube, Pool: keycloak.NewPool(clientWriter)}
				reconcile = func() error {
					_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(target)})
					return err
				}
			default:
				r := newReconciler(t, kube, clientWriter)
				reconcile = func() error {
					_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(target)})
					return err
				}
			}
			f.requireNoError(reconcile())
			f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(target), target))
			candidate := ownershipCandidate(target)
			if candidate == nil {
				t.Fatalf("candidate missing, conditions: %+v", ownershipConditions(target))
			}
			if !candidate.Approvable {
				t.Fatalf("lossless candidate unavailable, findings: %+v", candidate.Findings)
			}
			a := target.GetAnnotations()
			a[adoption.ContractAnnotation], a[adoption.CandidateAnnotation] = string(adoption.Version), candidate.CandidateHash
			target.SetAnnotations(a)
			f.requireNoError(kube.Update(ctx, target))
			mu.Lock()
			start := puts
			loseAck = capability == "web"
			mu.Unlock()
			failureClient.fail = capability == "role"
			reconcileErr := reconcile()
			if capability == "role" {
				if reconcileErr == nil {
					t.Fatal("injected status failure not observed")
				}
				f.requireNoError(reconcile())
			} else {
				f.requireNoError(reconcileErr)
			}
			f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(target), target))
			receipt := ownershipReceipt(target)
			if receipt == nil || receipt.State != "Verified" {
				for _, d := range candidate.Diff {
					t.Logf("reviewed diff: field=%s code=%s classification=%s roundTrip=%s", d.Field, d.Code, d.Classification, d.RoundTrip)
				}
				if capability != "role" {
					snapshot, readErr := clientWriter.ReadClientOwnership(ctx, "managed", clientID)
					f.requireNoError(readErr)
					t.Logf("qualified native root: %v", snapshot.QualifiedLeaf())
				}
				t.Fatalf("acquisition not verified: %+v; conditions: %+v", receipt, ownershipConditions(target))
			}
			f.requireNoError(reconcile())
			mu.Lock()
			count := puts - start
			secretCalls := credentials
			mu.Unlock()
			if count != 1 || secretCalls != 0 || len(target.GetFinalizers()) != 0 {
				t.Fatal("acquisition mutated more than ownership")
			}
			after := reader.read(path)
			attributes, _ := after["attributes"].(map[string]any)
			delete(attributes, adoption.ReceiptKey)
			delete(attributes, adoption.ApplicationOwnerKey)
			delete(attributes, adoption.RoleOwnerKey)
			delete(attributes, adoption.ClientOwnerKindKey)
			delete(attributes, adoption.ClientOwnerUIDKey)
			if len(attributes) == 0 {
				delete(after, "attributes")
			}
			if attrs, ok := before["attributes"].(map[string]any); ok && len(attrs) == 0 {
				delete(before, "attributes")
			}
			fixtureEqual(t, "exact UUID and native leaf semantics preserved", adoptionClone(t, after), adoptionClone(t, before))
			if capability == "web" {
				var rolesAfter, mappersAfter []map[string]any
				f.admin(http.MethodGet, path+"/roles", nil, &rolesAfter)
				f.admin(http.MethodGet, path+"/protocol-mappers/models", nil, &mappersAfter)
				fixtureEqual(t, "client roles and UUIDs preserved", rolesAfter, rolesBefore)
				fixtureEqual(t, "qualified mapper configuration and UUID preserved", mappersAfter, mappersBefore)
			}
			data, _ := json.Marshal(target)
			f.requireNoCredentials("ownership status and receipt", data)
			fixtureEqual(t, "reader mutation denied", reader.request(http.MethodPut, path, before, nil), http.StatusForbidden)
			if capability != "role" {
				secretStatus := http.StatusForbidden
				if f.version == "26.7.5" {
					secretStatus = http.StatusOK // native view-clients limitation; operator never calls this route
				}
				fixtureEqual(t, "qualified native credential visibility", reader.request(http.MethodGet, path+"/client-secret", nil, nil), secretStatus)
				if capability == "web" || capability == "m2m" {
					var secret map[string]any
					f.admin(http.MethodGet, path+"/client-secret", nil, &secret)
					fixtureEqual(t, "credential preserved by acquisition", secret["value"], credential)
				}
			}
		})
	}
	for _, identity := range []adoptionProbe{{f, "ownership-client-writer", clientSecret}, {f, "ownership-role-writer", roleSecret}} {
		fixtureEqual(t, "no global realm creation", identity.request(http.MethodPost, "/admin/realms", map[string]any{"realm": "denied-acquisition"}, nil), http.StatusForbidden)
		fixtureEqual(t, "no user mutation", identity.request(http.MethodPost, base+"/users", map[string]any{"username": "denied-acquisition"}, nil), http.StatusForbidden)
	}
	// realm_client is synthesized back to false by Keycloak for these leaf
	// clients, even when a PUT requests true. The mock adversarial suite covers
	// a provider returning another value; both real versions assert false above.
	for i, scenario := range []string{"backchannel.logout.session.required", "backchannel.logout.revoke.offline.tokens", "stale semantic observation", "foreign owner", "mixed owner", "provider replacement", "target replacement", "opaque attribute", "opaque root", "opaque mapper"} {
		f.run("refuse "+scenario, func(t *testing.T) {
			ctx := context.Background()
			name := fmt.Sprintf("refused-leaf-%d", i)
			fixture := map[string]any{"clientId": name, "name": name, "protocol": "openid-connect", "enabled": true, "publicClient": true,
				"standardFlowEnabled": true, "serviceAccountsEnabled": false, "directAccessGrantsEnabled": false, "fullScopeAllowed": false,
				"frontchannelLogout": true, "redirectUris": []string{"https://reviewed.example.test/callback"}, "webOrigins": []string{},
				"defaultClientScopes": []string{}, "optionalClientScopes": []string{}}
			f.admin(http.MethodPost, base+"/clients", fixture, nil)
			provider := f.client("managed", name)
			path := base + "/clients/" + provider["id"].(string)
			meta := fixtureMeta(name)
			meta.UID, meta.Generation = types.UID("refused-"+name), 1
			meta.Annotations = map[string]string{adoption.SourceAnnotation: "source"}
			app := &api.HankoApplication{ObjectMeta: meta, Spec: api.HankoApplicationSpec{Mode: "Observe", RealmRef: "managed", ClientID: name, Type: "spa", RedirectURIs: []string{"https://reviewed.example.test/callback"}}}
			kube := newFakeClient(t, app, &api.HankoRealm{ObjectMeta: fixtureMeta("managed")},
				&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: meta.Namespace, UID: "source-uid"}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
				&corev1.Secret{ObjectMeta: fixtureMeta("reader"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("ownership-reader"), "HANKO_KC_CLIENT_SECRET": []byte(readSecret)}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: meta.Namespace, UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}})
			r := newReconciler(t, kube, clientWriter)
			reconcile := func() {
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
				f.requireNoError(err)
			}
			reconcile()
			f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(app), app))
			if app.Status.AdoptionCandidate == nil || !app.Status.AdoptionCandidate.Approvable {
				t.Fatal("initial lossless candidate missing")
			}
			hash := app.Status.AdoptionCandidate.CandidateHash
			app.Annotations[adoption.ContractAnnotation], app.Annotations[adoption.CandidateAnnotation] = string(adoption.Version), hash
			f.requireNoError(kube.Update(ctx, app))
			attrs := provider["attributes"].(map[string]any)
			switch scenario {
			case "realm_client", "backchannel.logout.session.required", "backchannel.logout.revoke.offline.tokens":
				attrs[scenario] = map[string]string{"true": "false", "false": "true"}[attrs[scenario].(string)]
			case "stale semantic observation":
				provider["enabled"] = false
			case "foreign owner":
				attrs[adoption.ApplicationOwnerKey] = "foreign-uid"
			case "mixed owner":
				attrs[adoption.ApplicationOwnerKey] = string(app.UID)
				attrs[adoption.ClientOwnerKindKey], attrs[adoption.ClientOwnerUIDKey] = "HankoServiceAccount", string(app.UID)
			case "opaque attribute":
				attrs["private.native"] = "private-native-sentinel"
			case "opaque root":
				provider["description"] = "unreviewed-root-sentinel"
			case "opaque mapper":
				f.admin(http.MethodPost, path+"/protocol-mappers/models", map[string]any{"name": "department", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": map[string]string{
					"claim.name": "department", "user.attribute": "department", "private.native": "opaque-mapper-sentinel"}}, nil)
			case "provider replacement":
				f.admin(http.MethodDelete, path, nil, nil)
				f.admin(http.MethodPost, base+"/clients", fixture, nil)
			case "target replacement":
				f.requireNoError(kube.Delete(ctx, app))
				app.ResourceVersion, app.UID = "", "replacement-uid"
				f.requireNoError(kube.Create(ctx, app))
			}
			if scenario != "provider replacement" && scenario != "target replacement" {
				f.admin(http.MethodPut, path, provider, nil)
			}
			mu.Lock()
			start := puts
			mu.Unlock()
			reconcile()
			f.requireNoError(kube.Get(ctx, client.ObjectKeyFromObject(app), app))
			mu.Lock()
			count := puts - start
			mu.Unlock()
			if count != 0 || app.Status.AdoptionReceipt == nil || app.Status.AdoptionReceipt.State == "Verified" {
				t.Fatal("changed or conflicting evidence authorized acquisition")
			}
			if app.Status.AdoptionCandidate != nil && app.Status.AdoptionCandidate.CandidateHash == hash {
				t.Fatal("changed reviewed state did not invalidate candidate hash")
			}
			data, _ := json.Marshal(app)
			if strings.Contains(string(data), "sentinel") {
				t.Fatal("opaque provider value leaked into evidence")
			}
		})
	}
}

type ownershipStatusFailureClient struct {
	client.Client
	fail bool
}

func (c *ownershipStatusFailureClient) Status() client.SubResourceWriter {
	return ownershipStatusFailureWriter{SubResourceWriter: c.Client.Status(), owner: c}
}

type ownershipStatusFailureWriter struct {
	client.SubResourceWriter
	owner *ownershipStatusFailureClient
}

func (w ownershipStatusFailureWriter) Patch(ctx context.Context, o client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if w.owner.fail {
		w.owner.fail = false
		return errors.New("injected status checkpoint failure")
	}
	return w.SubResourceWriter.Patch(ctx, o, patch, opts...)
}
func ownershipCandidate(o client.Object) *api.AdoptionCandidateStatus {
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Status.AdoptionCandidate
	case *api.HankoRole:
		return t.Status.AdoptionCandidate
	case *api.HankoServiceAccount:
		return t.Status.AdoptionCandidate
	}
	return nil
}
func ownershipReceipt(o client.Object) *api.AdoptionReceiptStatus {
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Status.AdoptionReceipt
	case *api.HankoRole:
		return t.Status.AdoptionReceipt
	case *api.HankoServiceAccount:
		return t.Status.AdoptionReceipt
	}
	return nil
}
func ownershipConditions(o client.Object) []metav1.Condition {
	switch t := o.(type) {
	case *api.HankoApplication:
		return t.Status.Conditions
	case *api.HankoRole:
		return t.Status.Conditions
	case *api.HankoServiceAccount:
		return t.Status.Conditions
	}
	return nil
}
