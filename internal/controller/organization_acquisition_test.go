package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type organizationAcquisitionFixture struct {
	t                                     *testing.T
	mu                                    sync.Mutex
	group, native                         map[string]any
	groupPuts, nativePuts, forbiddenReads int
	denyNative, loseAck                   bool
	kube                                  client.Client
	org                                   *api.HankoOrganization
	writer                                *keycloak.Client
}

func newOrganizationAcquisitionFixture(t *testing.T) *organizationAcquisitionFixture {
	t.Helper()
	f := &organizationAcquisitionFixture{t: t,
		group:  map[string]any{"id": "group-id", "name": "Team", "path": "/Team", "attributes": map[string]any{"trunx_slug": []string{"team"}}},
		native: map[string]any{"id": "org-id", "name": "Team", "alias": "team", "enabled": true, "domains": []any{map[string]any{"name": "team.example.test", "verified": true}}, "attributes": map[string]any{}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	f.org = &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: "team", Namespace: "auth", UID: "target-uid", Generation: 1, Annotations: map[string]string{adoption.SourceAnnotation: "source"}}, Spec: api.HankoOrganizationSpec{Mode: ModeObserve, RealmRef: "realm", Name: "Team", Slug: "team", Domains: []string{"team.example.test"}}}
	f.kube = controllerTestClient(controllerTestScheme(t), f.org,
		&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "auth", UID: "source-uid"}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "auth"}, Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(server.URL), "HANKO_KC_CLIENT_ID": []byte("observer"), "HANKO_KC_CLIENT_SECRET": []byte("reader-credential-sentinel")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "auth", UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}},
	)
	var err error
	f.writer, err = keycloak.NewWithTLS(server.URL, "writer", "writer-credential-sentinel", ca)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *organizationAcquisitionFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/token") {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": r.Form.Get("client_id"), "expires_in": 300})
		return
	}
	if strings.Contains(r.URL.Path, "/members") || strings.Contains(r.URL.Path, "/users") || strings.Contains(r.URL.Path, "client-secret") {
		f.forbiddenReads++
		w.WriteHeader(403)
		return
	}
	if r.Method == http.MethodPut && r.Header.Get("Authorization") == "Bearer writer" {
		var target *map[string]any
		switch r.URL.Path {
		case "/admin/realms/realm/groups/group-id":
			f.groupPuts++
			target = &f.group
		case "/admin/realms/realm/organizations/org-id":
			f.nativePuts++
			if f.denyNative {
				w.WriteHeader(403)
				return
			}
			target = &f.native
		default:
			f.t.Error("unexpected semantic write", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		var next map[string]any
		if json.NewDecoder(r.Body).Decode(&next) != nil {
			f.t.Error("invalid checkpoint")
			w.WriteHeader(400)
			return
		}
		if target == &f.group {
			for _, key := range []string{"path", "parentId", "subGroups", "subGroupCount", "realmRoles", "clientRoles"} {
				if value, ok := f.group[key]; ok {
					next[key] = value
				}
			}
		}
		*target = next
		if f.loseAck {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if r.Method != http.MethodGet {
		f.t.Error("unexpected write", r.Method, r.URL.Path)
		w.WriteHeader(403)
		return
	}
	var value any
	switch strings.ReplaceAll(r.URL.Path, "replacement-group-id", "group-id") {
	case "/admin/realms/realm":
		value = map[string]any{"id": "realm-uuid", "realm": "realm", "enabled": true, "organizationsEnabled": true}
	case "/admin/realms/realm/group-by-path/Team", "/admin/realms/realm/groups/group-id":
		value = f.group
	case "/admin/realms/realm/groups/group-id/children":
		value = []map[string]any{{"id": "foreign-child", "name": "Foreign", "path": "/Team/Foreign", "attributes": map[string]any{"opaque": []string{"child-secret-sentinel"}}}}
	case "/admin/realms/realm/groups/group-id/role-mappings":
		value = map[string]any{"realmMappings": []any{}, "clientMappings": map[string]any{}}
	case "/admin/realms/realm/organizations":
		value = []map[string]any{f.native}
	case "/admin/realms/realm/organizations/org-id":
		value = f.native
	case "/admin/realms/realm/organizations/org-id/identity-providers":
		value = []any{}
	default:
		f.t.Error("unexpected read", r.URL.Path)
		w.WriteHeader(404)
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}
func (f *organizationAcquisitionFixture) approve() {
	f.t.Helper()
	c := refreshTargetCandidate(context.Background(), f.kube, f.kube, f.org)
	if c == nil || !c.Approvable {
		f.t.Fatalf("candidate unqualified: %+v", c)
	}
	f.org.Annotations[adoption.ContractAnnotation] = string(adoption.Version)
	f.org.Annotations[adoption.CandidateAnnotation] = c.CandidateHash
	if err := f.kube.Update(context.Background(), f.org); err != nil {
		f.t.Fatal(err)
	}
}
func (f *organizationAcquisitionFixture) run() error {
	r := &HankoOrganizationReconciler{Client: f.kube, APIReader: f.kube, Pool: keycloak.NewPool(f.writer), ProjectionMode: hankoapi.ProjectionEnabled, Positions: forbiddenOrganizationProjection{f.t}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.org)})
	return err
}
func (f *organizationAcquisitionFixture) status() *api.HankoOrganization {
	f.t.Helper()
	current := &api.HankoOrganization{}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.org), current); err != nil {
		f.t.Fatal(err)
	}
	f.org = current
	return current
}

type forbiddenOrganizationProjection struct{ t *testing.T }

func (p forbiddenOrganizationProjection) EnsurePosition(context.Context, string, hankoapi.PositionSpec) (string, error) {
	p.t.Error("Observe called Position projection")
	return "", nil
}
func (p forbiddenOrganizationProjection) DeletePosition(context.Context, string, string) error {
	p.t.Error("Observe called Position cleanup")
	return nil
}

func TestOrganizationAcquisitionRecoversIndependentCheckpoints(t *testing.T) {
	for _, fault := range []string{"none", "lost ACK", "native denied", "status failure", "existing owned group"} {
		t.Run(fault, func(t *testing.T) {
			f := newOrganizationAcquisitionFixture(t)
			if fault == "existing owned group" {
				attrs := f.group["attributes"].(map[string]any)
				attrs[organization.OwnerName] = []string{f.org.Name}
				attrs[organization.OwnerNamespace] = []string{f.org.Namespace}
				attrs[organization.OwnerUID] = []string{string(f.org.UID)}
			}
			f.approve()
			f.loseAck = fault == "lost ACK"
			f.denyNative = fault == "native denied"
			if fault == "status failure" {
				f.kube = &failAcquisitionStatus{Client: f.kube, failures: 1}
			}
			err := f.run()
			if (err != nil) != (fault == "status failure") {
				t.Fatal(err)
			}
			if fault == "native denied" {
				current := f.status()
				if current.Status.AdoptionReceipt == nil || current.Status.AdoptionReceipt.State != "Partial" || f.groupPuts != 1 || f.nativePuts != 1 {
					t.Fatal("partial checkpoint not retained")
				}
				f.denyNative = false
			}
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			current := f.status()
			if current.Status.AdoptionReceipt == nil || current.Status.AdoptionReceipt.State != "Verified" {
				t.Fatal("aggregate not verified", current.Status)
			}
			expectedNative := 1
			if fault == "native denied" {
				expectedNative = 2
			}
			if f.groupPuts != 1 || f.nativePuts != expectedNative || f.forbiddenReads != 0 || len(current.Finalizers) != 0 {
				t.Fatal("duplicate/unsafe acquisition", f.groupPuts, f.nativePuts, f.forbiddenReads, current.Finalizers)
			}
			groupReceipt := f.group["attributes"].(map[string]any)[adoption.ReceiptKey]
			nativeReceipt := f.native["attributes"].(map[string]any)[adoption.ReceiptKey]
			a, _ := json.Marshal(groupReceipt)
			b, _ := json.Marshal(nativeReceipt)
			if string(a) != string(b) {
				t.Fatal("aggregate members carry different receipts")
			}
			evidence, _ := json.Marshal(current.Status)
			if strings.Contains(string(evidence), "child-secret-sentinel") {
				t.Fatal("native child value escaped projection")
			}
		})
	}
}

func TestOrganizationObserveAndImportedLatchMakeNoProviderOrProjectionWrites(t *testing.T) {
	for _, imported := range []bool{false, true} {
		f := newOrganizationAcquisitionFixture(t)
		if imported {
			f.org.Spec.Mode = ModeManage
			f.org.Labels = map[string]string{importedByLabel: "inventory"}
			delete(f.org.Annotations, adoption.SourceAnnotation)
		}
		f.org.Finalizers = []string{orgFinalizerName}
		if err := f.kube.Update(context.Background(), f.org); err != nil {
			t.Fatal(err)
		}
		if err := f.run(); err != nil {
			t.Fatal(err)
		}
		current := f.status()
		if len(current.Finalizers) != 0 || f.groupPuts != 0 || f.nativePuts != 0 || f.forbiddenReads != 0 {
			t.Fatal("Observe did not drop destructive participation without writes")
		}
		if imported {
			continue
		}
		if err := f.run(); err != nil {
			t.Fatal(err)
		}
		current = f.status()
		if conditionReason(current.Status.Conditions, "Projection") != "ObserveOnly" || current.Status.GroupID != "group-id" || f.groupPuts != 0 || f.nativePuts != 0 {
			t.Fatal("Observe contract inconsistent")
		}
	}
}

func TestOrganizationAcquisitionRefusesForeignMemberAndOpaqueNativeEvidence(t *testing.T) {
	for _, fault := range []string{"foreign UID", "opaque attribute", "changed UUID", "changed path"} {
		t.Run(fault, func(t *testing.T) {
			f := newOrganizationAcquisitionFixture(t)
			f.approve()
			switch fault {
			case "foreign UID":
				f.native["attributes"] = map[string]any{organization.OwnerName: []string{f.org.Name}, organization.OwnerNamespace: []string{f.org.Namespace}, organization.OwnerUID: []string{"foreign-uid"}}
			case "opaque attribute":
				f.group["attributes"].(map[string]any)["innocent.key"] = []string{"credential-sentinel"}
			case "changed UUID":
				f.group["id"] = "replacement-group-id"
			case "changed path":
				f.group["path"] = "/Moved/Team"
			}
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			current := f.status()
			if current.Status.AdoptionReceipt != nil && current.Status.AdoptionReceipt.State == "Verified" || f.groupPuts != 0 || f.nativePuts != 0 {
				t.Fatal("unsafe aggregate acquired")
			}
			evidence, _ := json.Marshal(current.Status)
			sentinelHash := sha256.Sum256([]byte("credential-sentinel"))
			if strings.Contains(string(evidence), "credential-sentinel") || strings.Contains(string(evidence), hex.EncodeToString(sentinelHash[:])) {
				t.Fatal("secret or secret-derived hash escaped")
			}
		})
	}
}

func TestOrganizationPartialCheckpointCannotBorrowOwnershipFromForgedStatus(t *testing.T) {
	f := newOrganizationAcquisitionFixture(t)
	f.approve()
	f.denyNative = true
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	current := f.status()
	if current.Status.AdoptionReceipt == nil || current.Status.AdoptionReceipt.State != "Partial" {
		t.Fatal("missing partial checkpoint")
	}
	f.denyNative = false
	f.native["attributes"] = map[string]any{organization.OwnerName: []string{f.org.Name}, organization.OwnerNamespace: []string{f.org.Namespace}, organization.OwnerUID: []string{"foreign-uid"}}
	current.Status.AdoptionReceipt.State = "Verified"
	current.Status.OrgID = "forged-native-id"
	if err := f.kube.Status().Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	current = f.status()
	if current.Status.AdoptionReceipt.State == "Verified" || f.groupPuts != 1 || f.nativePuts != 1 || len(current.Finalizers) != 0 {
		t.Fatal("partial group checkpoint or forged status overrode foreign native owner")
	}
}

func TestOrganizationExistingCheckpointsRejectReplacementTargetUID(t *testing.T) {
	f := newOrganizationAcquisitionFixture(t)
	f.approve()
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	current := f.status()
	if err := f.kube.Delete(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	replacement := current.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-target-uid"
	if err := f.kube.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	f.org = replacement
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	current = f.status()
	if current.Status.AdoptionReceipt == nil || current.Status.AdoptionReceipt.State == "Verified" || f.groupPuts != 1 || f.nativePuts != 1 || len(current.Finalizers) != 0 {
		t.Fatal("replacement target inherited aggregate ownership")
	}
}

func TestOrganizationHierarchyUsesFreshAncestorUIDAndProviderIdentity(t *testing.T) {
	parent := &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: "auth", UID: "parent-uid"}, Spec: api.HankoOrganizationSpec{Name: "Parent", RealmRef: "realm"}, Status: api.HankoOrganizationStatus{GroupID: "forged-status-id"}}
	child := &api.HankoOrganization{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "auth", UID: "child-uid"}, Spec: api.HankoOrganizationSpec{Name: "Child", ParentRef: "parent", RealmRef: "realm"}}
	kube := controllerTestClient(controllerTestScheme(t), parent, child)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/admin/realms/realm/group-by-path/Parent" {
			t.Error("hierarchy performed an unexpected operation")
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "current-parent-id", "name": "Parent", "path": "/Parent"})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	kc, err := keycloak.NewWithTLS(server.URL, "writer", "private-credential", ca)
	if err != nil {
		t.Fatal(err)
	}
	path, id, bindings, err := organizationAdoptionPath(context.Background(), kube, kc, child)
	if err != nil || path != "/Parent/Child" || id != "current-parent-id" || len(bindings) != 1 || bindings[0] != "parent-uid/parent" {
		t.Fatal("ancestor status supplied authority", path, id, bindings, err)
	}
	parent.Spec.ParentRef = child.Name
	if err := kube.Update(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := organizationAdoptionPath(context.Background(), kube, kc, child); err == nil {
		t.Fatal("cyclic hierarchy accepted")
	}
}
