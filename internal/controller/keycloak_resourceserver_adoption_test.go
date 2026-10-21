//go:build keycloak_integration

package controller_test

import (
	"context"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealKeycloakResourceServerAggregateAcquisition(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	_, readSecret := f.serviceClient("aggregate-authz-reader")
	f.grantClientRoles("aggregate-authz-reader", "managed", []string{"view-realm", "view-clients", "view-authorization"})
	_, writeSecret := f.serviceClient("aggregate-authz-writer")
	f.grantClientRoles("aggregate-authz-writer", "managed", []string{"view-realm", "manage-clients", "manage-authorization"})
	endpoint, _ := url.Parse(f.baseURL)
	proxy := httputil.NewSingleHostReverseProxy(endpoint)
	proxy.Transport = f.http.Transport
	var mu sync.Mutex
	puts, forbidden := 0, 0
	loseAck := false
	manage := false
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "client-secret") || strings.Contains(r.URL.Path, "service-account-user") || strings.Contains(r.URL.Path, "/users") {
			mu.Lock()
			forbidden++
			mu.Unlock()
			w.WriteHeader(403)
			return
		}
		if r.Method != http.MethodGet && !strings.HasSuffix(r.URL.Path, "/token") {
			mu.Lock()
			managed := manage
			mu.Unlock()
			if managed && strings.Contains(r.URL.Path, "/authz/") {
				r.Host = endpoint.Host
				proxy.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodPut || strings.Contains(r.URL.Path, "/authz/") || !strings.Contains(r.URL.Path, "/clients/") {
				mu.Lock()
				forbidden++
				mu.Unlock()
				w.WriteHeader(403)
				return
			}
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
	t.Cleanup(relay.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw})
	writer, err := keycloak.NewWithTLS(relay.URL, "aggregate-authz-writer", writeSecret, ca)
	f.requireNoError(err)
	for _, fault := range []string{"normal", "lost-ack", "status-failure", "shared", "opaque", "stale-permission"} {
		f.run(fault, func(t *testing.T) {
			name := "reviewed-authz-" + fault
			mu.Lock()
			manage = false
			mu.Unlock()
			base := "/admin/realms/managed"
			application := &api.HankoApplication{ObjectMeta: fixtureMeta(name + "-app"), Spec: api.HankoApplicationSpec{Mode: "Observe", RealmRef: "managed", ClientID: name, Type: "m2m"}}
			appReceipt, _ := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoApplication", TargetUID: string(application.UID), CandidateHash: "sha256:" + strings.Repeat("a", 64)}).Canonical()
			f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": name, "name": name, "enabled": true, "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "fullScopeAllowed": false, "authorizationServicesEnabled": true, "attributes": map[string]string{adoption.ApplicationOwnerKey: string(application.UID), adoption.ReceiptKey: appReceipt}}, nil)
			backing := f.client("managed", name)
			clientID := backing["id"].(string)
			authz := base + "/clients/" + clientID + "/authz/resource-server"
			f.admin(http.MethodPost, base+"/roles", map[string]any{"name": name + "-reader"}, nil)
			var role map[string]any
			f.admin(http.MethodGet, base+"/roles/"+name+"-reader", nil, &role)
			f.admin(http.MethodPost, authz+"/scope", map[string]any{"name": "read", "displayName": "Read"}, nil)
			scopeID := nativeAuthorizationID(f, authz+"/scope", "read", "id")
			if fault == "opaque" {
				f.admin(http.MethodPut, authz+"/scope/"+scopeID, map[string]any{"id": scopeID, "name": "read", "displayName": "Read", "iconUri": "https://native.invalid/unqualified-icon"}, nil)
			}
			f.admin(http.MethodPost, authz+"/resource", map[string]any{"name": "invoices", "uris": []string{"/invoices/*"}, "scopes": []map[string]string{{"id": scopeID, "name": "read"}}}, nil)
			resourceID := nativeAuthorizationID(f, authz+"/resource", "invoices", "_id")
			policyName := "hanko:" + name + ":readers:realm_roles"
			f.admin(http.MethodPost, authz+"/policy/role", map[string]any{"name": policyName, "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "roles": []map[string]any{{"id": role["id"], "required": false}}}, nil)
			policyID := nativeAuthorizationID(f, authz+"/policy", policyName, "id")
			f.admin(http.MethodPost, authz+"/permission/scope", map[string]any{"name": "readers", "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "resources": []string{resourceID}, "scopes": []string{scopeID}, "policies": []string{policyID}}, nil)
			foreignDocuments := provisionForeignAuthorizationGraph(f, authz, role["id"].(string))
			if fault == "shared" {
				f.admin(http.MethodPost, authz+"/resource", map[string]any{"name": "foreign-before-review", "scopes": []map[string]string{{"id": scopeID, "name": "read"}}}, nil)
			}
			meta := fixtureMeta(name)
			meta.Annotations = map[string]string{adoption.SourceAnnotation: "source"}
			server := &api.HankoResourceServer{ObjectMeta: meta, Spec: api.HankoResourceServerSpec{Mode: "Observe", RealmRef: "managed", Audience: name, ApplicationRef: application.Name, Scopes: []api.AuthorizationScope{{Name: "read", Description: "Read"}}, Resources: []api.AuthorizationResource{{Name: "invoices", URIs: []string{"/invoices/*"}, Scopes: []string{"read"}}}, Permissions: []api.AuthorizationPermission{{Name: "readers", Scopes: []string{"read"}, Resources: []string{"invoices"}, Principals: []api.AuthorizationPrincipal{{Kind: "realm_role", Ref: name + "-reader"}}}}}}
			externalRealm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}
			externalRealm.Labels = map[string]string{"hanko.sh/imported-by": "external-inventory"}
			kube := newFakeClient(t, server, application, externalRealm, &api.HankoRole{ObjectMeta: fixtureMeta(name + "-reader"), Spec: api.HankoRoleSpec{RealmRef: "managed", Name: name + "-reader", Mode: "Observe"}},
				&api.HankoKeycloakInstance{ObjectMeta: fixtureMeta("source"), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
				&corev1.Secret{ObjectMeta: fixtureMeta("reader"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(relay.URL), "HANKO_KC_CLIENT_ID": []byte("aggregate-authz-reader"), "HANKO_KC_CLIENT_SECRET": []byte(readSecret)}},
				&corev1.Secret{ObjectMeta: fixtureMeta("ca"), Data: map[string][]byte{"ca.crt": ca}},
			)
			r := &controller.HankoResourceServerReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(writer)}
			reconcile := func() error {
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)})
				_ = kube.Get(ctx, client.ObjectKeyFromObject(server), server)
				return err
			}
			f.requireNoError(reconcile())
			candidate := server.Status.AdoptionCandidate
			if fault == "shared" || fault == "opaque" {
				if candidate != nil && candidate.Approvable {
					t.Fatal("unqualified or shared selected state was approvable")
				}
				current := f.client("managed", name)
				if _, present := current["attributes"].(map[string]any)["hanko.sh/resource-server-ownership"]; present {
					t.Fatal("refused candidate acquired a journal")
				}
				if len(server.Finalizers) != 0 {
					t.Fatal("refused Observe candidate gained lifecycle authority")
				}
				return
			}
			if candidate == nil || !candidate.Approvable {
				fields := map[string][]string{}
				for kind, path := range map[string]string{"scope": "/scope/" + scopeID, "resource": "/resource/" + resourceID, "policy": "/policy/role/" + policyID, "permission": "/permission/scope/" + nativeAuthorizationID(f, authz+"/permission", "readers", "id")} {
					var document map[string]any
					f.admin(http.MethodGet, authz+path, nil, &document)
					fields[kind] = slices.Sorted(maps.Keys(document))
				}
				t.Fatalf("selective graph candidate refused; native field names=%v", fields)
			}
			server.Annotations[adoption.ContractAnnotation] = string(adoption.Version)
			server.Annotations[adoption.CandidateAnnotation] = candidate.CandidateHash
			f.requireNoError(kube.Update(ctx, server))
			if fault == "stale-permission" {
				permissionID := nativeAuthorizationID(f, authz+"/permission", "readers", "id")
				var permission map[string]any
				f.admin(http.MethodGet, authz+"/permission/scope/"+permissionID, nil, &permission)
				permission["decisionStrategy"] = "UNANIMOUS"
				f.admin(http.MethodPut, authz+"/permission/scope/"+permissionID, permission, nil)
				f.requireNoError(reconcile())
				if server.Status.AdoptionReceipt == nil || server.Status.AdoptionReceipt.State != "Conflict" || server.Status.AdoptionCandidate.CandidateHash == candidate.CandidateHash {
					t.Fatal("changed permission semantics retained review authority")
				}
				if _, present := f.client("managed", name)["attributes"].(map[string]any)["hanko.sh/resource-server-ownership"]; present {
					t.Fatal("stale permission approval acquired selected IDs")
				}
				return
			}
			mu.Lock()
			puts, forbidden = 0, 0
			loseAck = fault == "lost-ack"
			mu.Unlock()
			failure := &ownershipStatusFailureClient{Client: kube, fail: fault == "status-failure"}
			r.Client = failure
			err = reconcile()
			if (err != nil) != (fault == "status-failure") {
				t.Fatal("unexpected aggregate transaction status failure", err)
			}
			f.requireNoError(reconcile())
			if server.Status.AdoptionReceipt == nil || server.Status.AdoptionReceipt.State != "Verified" || len(server.Finalizers) != 0 {
				t.Fatal("journal acquisition not verified Observe")
			}
			mu.Lock()
			count, denied := puts, forbidden
			mu.Unlock()
			fixtureEqual(t, "one owner-journal checkpoint", []int{count, denied}, []int{1, 0})
			verifyForeignAuthorizationGraph(t, f, foreignDocuments)
			after := f.client("managed", name)
			attrs := after["attributes"].(map[string]any)
			fixtureEqual(t, "Application receipt retained", attrs[adoption.ReceiptKey], appReceipt)
			delete(attrs, "hanko.sh/resource-server-ownership")
			fixtureEqual(t, "client semantics and UUID preserved", adoptionClone(t, after), adoptionClone(t, backing))
			f.requireNoCredentials("ResourceServer receipt status", fixtureJSON(t, server.Status))
			if fault == "normal" {
				mu.Lock()
				manage = true
				mu.Unlock()
				server.Spec.Mode = "Manage"
				f.requireNoError(kube.Update(ctx, server))
				// Status loss cannot discard or replace the provider-owned set.
				server.Status = api.HankoResourceServerStatus{}
				f.requireNoError(kube.Status().Update(ctx, server))
				f.requireNoError(reconcile())
				if server.Status.Phase != "Ready" || len(server.Status.ManagedObjects.Scopes) != 1 {
					t.Fatal("explicit Manage did not recover the selected journal", server.Status.Phase)
				}
				server.Spec.Scopes[0].Description = "Reviewed change"
				f.requireNoError(kube.Update(ctx, server))
				f.requireNoError(reconcile())
				var repaired map[string]any
				f.admin(http.MethodGet, authz+"/scope/"+scopeID, nil, &repaired)
				fixtureEqual(t, "owned scope repaired", repaired["displayName"], "Reviewed change")
				verifyForeignAuthorizationGraph(t, f, foreignDocuments)
				f.admin(http.MethodPost, authz+"/resource", map[string]any{"name": "foreign-shared", "scopes": []map[string]string{{"id": scopeID, "name": "read"}}}, nil)
				foreignID := nativeAuthorizationID(f, authz+"/resource", "foreign-shared", "_id")
				f.requireNoError(kube.Delete(ctx, server))
				if err := reconcile(); err == nil {
					t.Fatal("foreign incoming dependency did not hold cleanup")
				}
				if len(server.Finalizers) != 1 {
					t.Fatal("unsafe graph cleanup released lifecycle")
				}
				f.admin(http.MethodDelete, authz+"/resource/"+foreignID, nil, nil)
				f.requireNoError(reconcile())
				fixtureEqual(t, "owned graph scope safely absent", f.admin(http.MethodGet, authz+"/scope/"+scopeID, nil, nil), http.StatusNotFound)
				remaining := f.client("managed", name)
				fixtureEqual(t, "Authorization Services retained for foreign graph", remaining["authorizationServicesEnabled"], true)
				fixtureEqual(t, "Application receipt survives child cleanup", remaining["attributes"].(map[string]any)[adoption.ReceiptKey], appReceipt)
				verifyForeignAuthorizationGraph(t, f, foreignDocuments)
			}
		})
	}
	for _, probe := range []adoptionProbe{{f, "aggregate-authz-reader", readSecret}, {f, "aggregate-authz-writer", writeSecret}} {
		fixtureEqual(t, "no realm deletion", probe.request(http.MethodDelete, "/admin/realms/managed", nil, nil), http.StatusForbidden)
		fixtureEqual(t, "no realm security mutation", probe.request(http.MethodPut, "/admin/realms/managed", map[string]any{"sslRequired": "none"}, nil), http.StatusForbidden)
		fixtureEqual(t, "no global realm creation", probe.request(http.MethodPost, "/admin/realms", map[string]any{"realm": "denied-authz"}, nil), http.StatusForbidden)
	}
}

func provisionForeignAuthorizationGraph(f *keycloakFixture, authz, roleID string) map[string]map[string]any {
	f.admin(http.MethodPost, authz+"/resource", map[string]any{"name": "foreign-resource", "uris": []string{"/foreign"}}, nil)
	resourceID := nativeAuthorizationID(f, authz+"/resource", "foreign-resource", "_id")
	f.admin(http.MethodPost, authz+"/policy/role", map[string]any{"name": "foreign-role-policy", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "roles": []map[string]any{{"id": roleID, "required": false}}}, nil)
	policyID := nativeAuthorizationID(f, authz+"/policy", "foreign-role-policy", "id")
	f.admin(http.MethodPost, authz+"/policy/aggregate", map[string]any{"name": "foreign-native-aggregate", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "policies": []string{policyID}}, nil)
	aggregateID := nativeAuthorizationID(f, authz+"/policy", "foreign-native-aggregate", "id")
	documents := map[string]map[string]any{}
	for _, path := range []string{authz + "/resource/" + resourceID, authz + "/policy/role/" + policyID, authz + "/policy/aggregate/" + aggregateID} {
		var document map[string]any
		f.admin(http.MethodGet, path, nil, &document)
		documents[path] = document
	}
	return documents
}

func verifyForeignAuthorizationGraph(t *testing.T, f *keycloakFixture, documents map[string]map[string]any) {
	t.Helper()
	for path, expected := range documents {
		var document map[string]any
		f.admin(http.MethodGet, path, nil, &document)
		fixtureEqual(t, "foreign native graph document and UUID retained", document, expected)
	}
}

func nativeAuthorizationID(f *keycloakFixture, path, name, idKey string) string {
	var objects []map[string]any
	f.admin(http.MethodGet, path+"?first=0&max=100", nil, &objects)
	id := ""
	for _, object := range objects {
		if object["name"] == name {
			current, ok := object[idKey].(string)
			if !ok || id != "" {
				f.t.Fatal("ambiguous bootstrap authorization object")
			}
			id = current
		}
	}
	if id == "" {
		f.t.Fatal("bootstrap authorization object missing")
	}
	return id
}
