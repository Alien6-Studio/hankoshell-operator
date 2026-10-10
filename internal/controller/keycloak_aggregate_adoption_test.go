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
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealKeycloakOrganizationAggregateAcquisition(t *testing.T) {
	f := newKeycloakFixture(t)
	ctx := context.Background()
	f.admin(http.MethodPut, "/admin/realms/managed", map[string]any{"organizationsEnabled": true}, nil)
	_, readSecret := f.serviceClient("aggregate-org-reader")
	f.grantClientRoles("aggregate-org-reader", "managed", []string{"view-realm", "view-users", "view-organizations", "view-identity-providers", "view-clients"})
	_, writeSecret := f.serviceClient("aggregate-org-writer")
	f.grantClientRoles("aggregate-org-writer", "managed", []string{"view-realm", "manage-users", "manage-organizations", "view-identity-providers", "view-clients"})
	endpoint, _ := url.Parse(f.baseURL)
	proxy := httputil.NewSingleHostReverseProxy(endpoint)
	proxy.Transport = f.http.Transport
	var mu sync.Mutex
	groupPuts, nativePuts, forbidden := 0, 0, 0
	denyNative, loseAck := false, false
	manage := false
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		managed := manage
		mu.Unlock()
		boundedMembership := managed && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/members") && r.URL.Query().Get("first") == "0" && r.URL.Query().Get("max") == "1"
		if strings.Contains(r.URL.Path, "/members") && !boundedMembership || strings.Contains(r.URL.Path, "/users") || strings.Contains(r.URL.Path, "client-secret") {
			mu.Lock()
			forbidden++
			mu.Unlock()
			w.WriteHeader(403)
			return
		}
		if r.Method != http.MethodGet && !strings.HasSuffix(r.URL.Path, "/token") {
			mu.Lock()
			if managed && r.Method == http.MethodDelete && (strings.Contains(r.URL.Path, "/organizations/") || strings.Contains(r.URL.Path, "/groups/")) {
				mu.Unlock()
				r.Host = endpoint.Host
				proxy.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodPut {
				forbidden++
				mu.Unlock()
				w.WriteHeader(403)
				return
			}
			native := strings.Contains(r.URL.Path, "/organizations/")
			if native {
				nativePuts++
			} else if strings.Contains(r.URL.Path, "/groups/") {
				groupPuts++
			} else {
				forbidden++
				mu.Unlock()
				w.WriteHeader(403)
				return
			}
			denied, lost := native && denyNative, loseAck
			loseAck = false
			mu.Unlock()
			if denied {
				w.WriteHeader(403)
				return
			}
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
	writer, err := keycloak.NewWithTLS(relay.URL, "aggregate-org-writer", writeSecret, ca)
	f.requireNoError(err)
	observer, err := keycloak.NewWithTLS(relay.URL, "aggregate-org-reader", readSecret, ca)
	f.requireNoError(err)
	for _, fault := range []string{"normal", "partial", "lost-ack", "status-failure"} {
		f.run(fault, func(t *testing.T) {
			name := "reviewed-aggregate-" + fault
			base := "/admin/realms/managed"
			mu.Lock()
			manage = false
			mu.Unlock()
			f.admin(http.MethodPost, base+"/groups", map[string]any{"name": name, "attributes": map[string][]string{"trunx_slug": {name}, "locale": {"fr"}}}, nil)
			var group map[string]any
			f.admin(http.MethodGet, base+"/group-by-path/"+name, nil, &group)
			groupID := group["id"].(string)
			f.admin(http.MethodPost, base+"/groups/"+groupID+"/children", map[string]any{"name": "Foreign"}, nil)
			f.admin(http.MethodPost, base+"/organizations", map[string]any{"name": name, "alias": name, "enabled": true, "attributes": map[string][]string{"locale": {"en"}}, "domains": []map[string]any{{"name": name + ".example.test", "verified": true}}}, nil)
			var listed []map[string]any
			f.admin(http.MethodGet, base+"/organizations?max=100", nil, &listed)
			orgID := ""
			for _, native := range listed {
				if native["alias"] == name {
					orgID = native["id"].(string)
				}
			}
			if orgID == "" {
				t.Fatal("bootstrap native Organization missing")
			}
			var foreignMember string
			var foreignRole map[string]any
			if fault == "normal" {
				foreignMember, foreignRole = provisionOrganizationForeignState(f, groupID, orgID, name)
			}
			var beforeGroup, beforeNative map[string]any
			f.admin(http.MethodGet, base+"/groups/"+groupID, nil, &beforeGroup)
			f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, &beforeNative)
			_, err := observer.ReadOrganizationOwnership(ctx, "managed", "/"+name, name)
			f.requireNoError(err)
			meta := fixtureMeta(name)
			meta.Annotations = map[string]string{adoption.SourceAnnotation: "source"}
			org := &api.HankoOrganization{ObjectMeta: meta, Spec: api.HankoOrganizationSpec{Mode: "Observe", RealmRef: "managed", Name: name, Slug: name, Domains: []string{name + ".example.test"}}}
			externalRealm := &api.HankoRealm{ObjectMeta: fixtureMeta("managed")}
			externalRealm.Labels = map[string]string{"hanko.sh/imported-by": "external-inventory"}
			kube := newFakeClient(t, org,
				externalRealm,
				&api.HankoKeycloakInstance{ObjectMeta: fixtureMeta("source"), Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
				&corev1.Secret{ObjectMeta: fixtureMeta("reader"), Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(relay.URL), "HANKO_KC_CLIENT_ID": []byte("aggregate-org-reader"), "HANKO_KC_CLIENT_SECRET": []byte(readSecret)}},
				&corev1.Secret{ObjectMeta: fixtureMeta("ca"), Data: map[string][]byte{"ca.crt": ca}},
			)
			r := &controller.HankoOrganizationReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(writer)}
			reconcile := func() error {
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)})
				_ = kube.Get(ctx, client.ObjectKeyFromObject(org), org)
				return err
			}
			f.requireNoError(reconcile())
			candidate := org.Status.AdoptionCandidate
			if candidate == nil || !candidate.Approvable {
				t.Fatalf("aggregate candidate refused: groupFields=%v nativeFields=%v findings=%v", slices.Sorted(maps.Keys(beforeGroup)), slices.Sorted(maps.Keys(beforeNative)), candidate.Findings)
			}
			org.Annotations[adoption.ContractAnnotation] = string(adoption.Version)
			org.Annotations[adoption.CandidateAnnotation] = candidate.CandidateHash
			f.requireNoError(kube.Update(ctx, org))
			mu.Lock()
			groupPuts, nativePuts, forbidden = 0, 0, 0
			denyNative = fault == "partial"
			loseAck = fault == "lost-ack"
			mu.Unlock()
			statusFailure := &ownershipStatusFailureClient{Client: kube, fail: fault == "status-failure"}
			r.Client = statusFailure
			err = reconcile()
			if (err != nil) != (fault == "status-failure") {
				t.Fatal("unexpected transaction failure", err)
			}
			if fault == "partial" {
				if org.Status.AdoptionReceipt == nil || org.Status.AdoptionReceipt.State != "Partial" {
					t.Fatal("missing partial checkpoint")
				}
				mu.Lock()
				denyNative = false
				mu.Unlock()
			}
			f.requireNoError(reconcile())
			if org.Status.AdoptionReceipt == nil || org.Status.AdoptionReceipt.State != "Verified" || len(org.Finalizers) != 0 {
				var groupNow, nativeNow map[string]any
				f.admin(http.MethodGet, base+"/groups/"+groupID, nil, &groupNow)
				f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, &nativeNow)
				t.Logf("business equality: group=%v native=%v", reflect.DeepEqual(organizationBusinessSnapshot(t, groupNow), organizationBusinessSnapshot(t, beforeGroup)), reflect.DeepEqual(organizationBusinessSnapshot(t, nativeNow), organizationBusinessSnapshot(t, beforeNative)))
				t.Fatal("aggregate not verified Observe", org.Status)
			}
			mu.Lock()
			g, n, b := groupPuts, nativePuts, forbidden
			mu.Unlock()
			expected := 1
			if fault == "partial" {
				expected = 2
			}
			if g != 1 || n != expected || b != 0 {
				t.Fatalf("unexpected checkpoint calls: group=%d native=%d forbidden=%d", g, n, b)
			}
			var afterGroup, afterNative map[string]any
			f.admin(http.MethodGet, base+"/groups/"+groupID, nil, &afterGroup)
			f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, &afterNative)
			fixtureEqual(t, "group business representation and UUID preserved", organizationBusinessSnapshot(t, afterGroup), organizationBusinessSnapshot(t, beforeGroup))
			fixtureEqual(t, "native Organization business representation and UUID preserved", organizationBusinessSnapshot(t, afterNative), organizationBusinessSnapshot(t, beforeNative))
			f.requireNoCredentials("aggregate status", fixtureJSON(t, org.Status))
			mu.Lock()
			manage = true
			mu.Unlock()
			org.Spec.Mode = "Manage"
			f.requireNoError(kube.Update(ctx, org))
			f.requireNoError(reconcile())
			if org.Status.Phase != "Ready" || len(org.Finalizers) != 1 {
				t.Fatal("explicit Manage did not acquire lifecycle", org.Status.Phase)
			}
			mu.Lock()
			g, n = groupPuts, nativePuts
			mu.Unlock()
			f.requireNoError(reconcile())
			mu.Lock()
			fixtureEqual(t, "unchanged adopted Manage performs no semantic PUT", []int{groupPuts, nativePuts}, []int{g, n})
			mu.Unlock()
			f.admin(http.MethodGet, base+"/groups/"+groupID, nil, &afterGroup)
			f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, &afterNative)
			fixtureEqual(t, "Manage preserves group foreign state", organizationBusinessSnapshot(t, afterGroup), organizationBusinessSnapshot(t, beforeGroup))
			fixtureEqual(t, "Manage preserves native foreign state", organizationBusinessSnapshot(t, afterNative), organizationBusinessSnapshot(t, beforeNative))
			if fault == "normal" {
				// Drift only a Hanko-managed scalar, preserving native locale and
				// domain metadata through the subsequent semantic PUT.
				afterNative["enabled"] = false
				f.admin(http.MethodPut, base+"/organizations/"+orgID, afterNative, nil)
				f.requireNoError(reconcile())
				f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, &afterNative)
				fixtureEqual(t, "semantic repair preserves complete native state", organizationBusinessSnapshot(t, afterNative), organizationBusinessSnapshot(t, beforeNative))
				qualifyOrganizationCleanup(f, ctx, kube, org, groupID, orgID, foreignMember, foreignRole, name+"-broker", reconcile)
			}
		})
	}
	for _, probe := range []adoptionProbe{{f, "aggregate-org-reader", readSecret}, {f, "aggregate-org-writer", writeSecret}} {
		fixtureEqual(t, "no realm deletion", probe.request(http.MethodDelete, "/admin/realms/managed", nil, nil), http.StatusForbidden)
		fixtureEqual(t, "no realm security mutation", probe.request(http.MethodPut, "/admin/realms/managed", map[string]any{"sslRequired": "none"}, nil), http.StatusForbidden)
		fixtureEqual(t, "no global realm creation", probe.request(http.MethodPost, "/admin/realms", map[string]any{"realm": "denied-aggregate"}, nil), http.StatusForbidden)
	}
}

func provisionOrganizationForeignState(f *keycloakFixture, groupID, orgID, name string) (string, map[string]any) {
	base := "/admin/realms/managed"
	f.admin(http.MethodPost, base+"/users", map[string]any{"username": name + "-member", "enabled": true}, nil)
	var users []map[string]any
	f.admin(http.MethodGet, base+"/users?username="+name+"-member", nil, &users)
	if len(users) != 1 {
		f.t.Fatal("bootstrap cleanup member missing")
	}
	uid := users[0]["id"].(string)
	f.admin(http.MethodPut, base+"/users/"+uid+"/groups/"+groupID, nil, nil)
	f.admin(http.MethodPost, base+"/organizations/"+orgID+"/members", uid, nil)
	f.admin(http.MethodPost, base+"/roles", map[string]any{"name": name + "-foreign-role"}, nil)
	var role map[string]any
	f.admin(http.MethodGet, base+"/roles/"+name+"-foreign-role", nil, &role)
	f.admin(http.MethodPost, base+"/groups/"+groupID+"/role-mappings/realm", []any{role}, nil)
	f.admin(http.MethodPost, base+"/clients", map[string]any{"clientId": name + "-foreign-client", "protocol": "openid-connect", "publicClient": true}, nil)
	foreignClient := f.client("managed", name+"-foreign-client")
	clientID := foreignClient["id"].(string)
	f.admin(http.MethodPost, base+"/clients/"+clientID+"/roles", map[string]any{"name": "foreign-client-role"}, nil)
	var clientRole map[string]any
	f.admin(http.MethodGet, base+"/clients/"+clientID+"/roles/foreign-client-role", nil, &clientRole)
	f.admin(http.MethodPost, base+"/groups/"+groupID+"/role-mappings/clients/"+clientID, []any{clientRole}, nil)
	alias := name + "-broker"
	f.admin(http.MethodPost, base+"/identity-provider/instances", map[string]any{"alias": alias, "providerId": "oidc", "enabled": false, "config": map[string]string{"clientId": name, "authorizationUrl": "https://idp.invalid/authorize", "tokenUrl": "https://idp.invalid/token"}}, nil)
	request, err := http.NewRequest(http.MethodPost, f.baseURL+base+"/organizations/"+orgID+"/identity-providers", strings.NewReader(alias))
	f.requireNoError(err)
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	response, err := f.http.Do(request)
	f.requireNoError(err)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		f.t.Fatalf("bootstrap native broker relationship: HTTP %d", response.StatusCode)
	}
	return uid, role
}

func qualifyOrganizationCleanup(f *keycloakFixture, ctx context.Context, kube client.Client, org *api.HankoOrganization, groupID, orgID, uid string, role map[string]any, alias string, reconcile func() error) {
	t := f.t
	base := "/admin/realms/managed"
	f.requireNoError(reconcile())
	f.requireNoError(kube.Delete(ctx, org))
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	var children []map[string]any
	f.admin(http.MethodGet, base+"/groups/"+groupID+"/children?max=100", nil, &children)
	if len(children) != 1 {
		t.Fatal("foreign child lost during Manage")
	}
	f.admin(http.MethodDelete, base+"/groups/"+children[0]["id"].(string), nil, nil)
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	f.admin(http.MethodDelete, base+"/users/"+uid+"/groups/"+groupID, nil, nil)
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	f.admin(http.MethodDelete, base+"/groups/"+groupID+"/role-mappings/realm", []any{role}, nil)
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	var mappings struct {
		ClientMappings map[string]struct {
			ID       string
			Mappings []map[string]any
		}
	}
	f.admin(http.MethodGet, base+"/groups/"+groupID+"/role-mappings", nil, &mappings)
	if len(mappings.ClientMappings) != 1 {
		t.Fatal("foreign client role mapping lost during Manage")
	}
	for _, mapping := range mappings.ClientMappings {
		f.admin(http.MethodDelete, base+"/groups/"+groupID+"/role-mappings/clients/"+mapping.ID, mapping.Mappings, nil)
	}
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	f.admin(http.MethodDelete, base+"/organizations/"+orgID+"/members/"+uid, nil, nil)
	f.requireNoError(reconcile())
	requireOrganizationCondition(t, org, "Synced", "False", "CleanupConflict")
	f.admin(http.MethodDelete, base+"/organizations/"+orgID+"/identity-providers/"+alias, nil, nil)
	f.requireNoError(reconcile())
	fixtureEqual(t, "safe group deletion", f.admin(http.MethodGet, base+"/groups/"+groupID, nil, nil), http.StatusNotFound)
	fixtureEqual(t, "safe native deletion", f.admin(http.MethodGet, base+"/organizations/"+orgID, nil, nil), http.StatusNotFound)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(org), &api.HankoOrganization{}); !apierrors.IsNotFound(err) {
		t.Fatal("successful cleanup did not finalize the CR")
	}
}

func organizationBusinessSnapshot(t *testing.T, document map[string]any) map[string]any {
	result := adoptionClone(t, document)
	delete(result, "access")
	if attrs, ok := result["attributes"].(map[string]any); ok {
		for _, key := range []string{organization.OwnerName, organization.OwnerNamespace, organization.OwnerUID, adoption.ReceiptKey} {
			delete(attrs, key)
		}
		if len(attrs) == 0 {
			delete(result, "attributes")
		}
	}
	return result
}
