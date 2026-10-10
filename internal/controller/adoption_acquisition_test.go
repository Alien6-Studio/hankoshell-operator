package controller

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type acquisitionFixture struct {
	t                                     *testing.T
	mu                                    sync.Mutex
	document                              map[string]any
	mappers                               []map[string]any
	puts, credentialCalls, observerWrites int
	lostAck, partial                      bool
	server                                *httptest.Server
	kube                                  client.Client
	writer                                *keycloak.Client
	target                                client.Object
}

func newAcquisitionFixture(t *testing.T, kind, protocol string) *acquisitionFixture {
	t.Helper()
	f := &acquisitionFixture{t: t, mappers: []map[string]any{}}
	meta := metav1.ObjectMeta{Name: "target", Namespace: "auth", UID: "target-uid", Generation: 1, Annotations: map[string]string{adoption.SourceAnnotation: "source"}}
	attrs := map[string]any{}
	if kind == "HankoRole" {
		f.document = map[string]any{"id": "role-uuid", "name": "reader", "description": "Reviewed", "containerId": "realm-uuid", "clientRole": false, "composite": false, "attributes": attrs}
		f.target = &api.HankoRole{ObjectMeta: meta, Spec: api.HankoRoleSpec{Mode: ModeObserve, RealmRef: "realm", Name: "reader", Description: "Reviewed"}}
	} else {
		f.document = map[string]any{"id": "client-uuid", "clientId": "client", "name": "client", "protocol": "openid-connect", "enabled": true, "publicClient": true, "standardFlowEnabled": true, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "redirectUris": []any{"https://app.example.test/cb"}, "webOrigins": []any{"+"}, "attributes": attrs}
		if kind == "HankoServiceAccount" {
			f.document["publicClient"], f.document["standardFlowEnabled"], f.document["serviceAccountsEnabled"] = false, false, true
			f.document["redirectUris"] = []any{}
			f.target = &api.HankoServiceAccount{ObjectMeta: meta, Spec: api.HankoServiceAccountSpec{Mode: ModeObserve, RealmRef: "realm", ClientID: "client"}}
		} else {
			app := &api.HankoApplication{ObjectMeta: meta, Spec: api.HankoApplicationSpec{Mode: ModeObserve, RealmRef: "realm", ClientID: "client", Type: "spa", RedirectURIs: []string{"https://app.example.test/cb"}}}
			if protocol == "saml" {
				f.document["protocol"], f.document["publicClient"], f.document["webOrigins"] = "saml", false, []any{}
				attrs["saml_name_id_format"], attrs["saml.assertion.signature"], attrs["saml.server.signature"] = "persistent", "true", "true"
				app.Spec.Protocol, app.Spec.Type, app.Spec.RedirectURIs = "saml", "", nil
				app.Spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: []string{"https://app.example.test/cb"}, NameIDFormat: "persistent"}
			}
			f.target = app
		}
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	f.kube = controllerTestClient(controllerTestScheme(t), f.target,
		&api.HankoKeycloakInstance{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "auth", UID: "source-uid"}, Spec: api.HankoKeycloakInstanceSpec{Mode: "external", AdminRef: corev1.LocalObjectReference{Name: "reader"}, TLSCARef: "ca"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "auth"}, Data: map[string][]byte{"HANKO_KEYCLOAK_URL": []byte(f.server.URL), "HANKO_KC_CLIENT_ID": []byte("observer"), "HANKO_KC_CLIENT_SECRET": []byte("reader-credential-sentinel")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "auth", UID: "ca-uid"}, Data: map[string][]byte{"ca.crt": ca}})
	var err error
	f.writer, err = keycloak.NewWithTLS(f.server.URL, "writer", "writer-credential-sentinel", ca)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *acquisitionFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/token") {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": r.Form.Get("client_id"), "expires_in": 300})
		return
	}
	if strings.Contains(r.URL.Path, "client-secret") || strings.Contains(r.URL.Path, "service-account-user") {
		f.credentialCalls++
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Header.Get("Authorization") == "Bearer observer" {
		f.observerWrites++
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut && (r.URL.Path == "/admin/realms/realm/clients/client-uuid" || r.URL.Path == "/admin/realms/realm/roles/reader") {
		var next map[string]any
		if json.NewDecoder(r.Body).Decode(&next) != nil {
			f.t.Error("invalid ownership PUT")
			w.WriteHeader(400)
			return
		}
		if _, copied := next["secret"]; copied {
			f.t.Error("credential copied into ownership PUT")
		}
		if value, exists := f.document["serviceAccountsEnabled"]; exists {
			if _, resent := next["serviceAccountsEnabled"]; resent {
				f.t.Error("service-account enablement resent in owner-only PUT")
			}
			next["serviceAccountsEnabled"] = value
		}
		f.document, f.puts = next, f.puts+1
		if f.partial {
			f.document["description"] = "concurrent edit"
			f.document["enabled"] = false
		}
		if f.lostAck {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var value any
	switch r.URL.Path {
	case "/admin/realms/realm":
		value = map[string]any{"id": "realm-uuid", "realm": "realm", "enabled": true}
	case "/admin/realms/realm/clients":
		value = []any{map[string]any{"id": f.document["id"], "clientId": "client"}}
	case "/admin/realms/realm/clients/client-uuid", "/admin/realms/realm/roles/reader":
		value = f.document
	case "/admin/realms/realm/clients/client-uuid/protocol-mappers/models":
		value = f.mappers
	case "/admin/realms/realm/clients/client-uuid/roles", "/admin/realms/realm/clients/client-uuid/scope-mappings/realm", "/admin/realms/realm/roles/reader/composites/realm":
		value = []any{}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}
func (f *acquisitionFixture) approve() {
	f.t.Helper()
	c := refreshTargetCandidate(context.Background(), f.kube, f.kube, f.target)
	if c == nil || !c.Approvable {
		f.t.Fatalf("lossless fixture not approvable: %+v", c)
	}
	_ = f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.target), f.target)
	a := f.target.GetAnnotations()
	a[adoption.ContractAnnotation], a[adoption.CandidateAnnotation] = string(adoption.Version), c.CandidateHash
	f.target.SetAnnotations(a)
	if err := f.kube.Update(context.Background(), f.target); err != nil {
		f.t.Fatal(err)
	}
}
func (f *acquisitionFixture) run() error {
	f.t.Helper()
	handled, _, err := reconcileOwnershipAcquisition(context.Background(), f.kube, f.kube, f.target, f.writer, nil)
	if !handled {
		f.t.Error("approval not consumed by separate transaction")
	}
	return err
}
func (f *acquisitionFixture) status() (*api.AdoptionReceiptStatus, []metav1.Condition) {
	f.t.Helper()
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.target), f.target); err != nil {
		f.t.Fatal(err)
	}
	switch t := f.target.(type) {
	case *api.HankoApplication:
		return t.Status.AdoptionReceipt, t.Status.Conditions
	case *api.HankoRole:
		return t.Status.AdoptionReceipt, t.Status.Conditions
	case *api.HankoServiceAccount:
		return t.Status.AdoptionReceipt, t.Status.Conditions
	}
	return nil, nil
}
func TestOwnershipAcquisitionLeafTransactions(t *testing.T) {
	for _, c := range []struct{ kind, protocol string }{{"HankoApplication", "oidc"}, {"HankoApplication", "saml"}, {"HankoRole", ""}, {"HankoServiceAccount", "oidc"}} {
		t.Run(c.kind+c.protocol, func(t *testing.T) {
			f := newAcquisitionFixture(t, c.kind, c.protocol)
			f.approve()
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			s, conditions := f.status()
			if s == nil || s.State != "Verified" || conditionReason(conditions, "OwnershipAdopted") != "AdoptionVerified" {
				t.Fatal("receipt not verified", s, conditions)
			}
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			if f.puts != 1 || f.credentialCalls != 0 || f.observerWrites != 0 || len(f.target.GetFinalizers()) != 0 {
				t.Fatal("owner-only transaction mutated extra state")
			}
			status, _ := json.Marshal(f.target)
			if strings.Contains(string(status), "credential-sentinel") {
				t.Fatal("credential in status")
			}
		})
	}
}

func TestOwnershipAcquisitionChangedCanonicalDefaultsRefuseWrites(t *testing.T) {
	for key, canonical := range map[string]string{"realm_client": "false", "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "false"} {
		t.Run(key, func(t *testing.T) {
			f := newAcquisitionFixture(t, "HankoApplication", "oidc")
			attrs := f.document["attributes"].(map[string]any)
			attrs[key] = canonical
			f.approve()
			approved := f.target.GetAnnotations()[adoption.CandidateAnnotation]
			attrs[key] = map[string]string{"true": "false", "false": "true"}[canonical]
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			s, conditions := f.status()
			candidate := f.target.(*api.HankoApplication).Status.AdoptionCandidate
			if s == nil || s.State != "Conflict" || conditionReason(conditions, "OwnershipAdopted") != "AdoptionUnsupported" || candidate == nil || candidate.Approvable || candidate.CandidateHash == approved || f.puts != 0 {
				t.Fatal("changed canonical default did not invalidate approval")
			}
		})
	}
}
func TestOwnershipAcquisitionRefusals(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*acquisitionFixture)
	}{
		{"wrong hash", func(f *acquisitionFixture) {
			f.target.GetAnnotations()[adoption.CandidateAnnotation] = "sha256:" + strings.Repeat("a", 64)
		}},
		{"future contract", func(f *acquisitionFixture) { f.target.GetAnnotations()[adoption.ContractAnnotation] = "future" }},
		{"wrong source", func(f *acquisitionFixture) { f.target.GetAnnotations()[adoption.SourceAnnotation] = "missing" }},
		{"legacy conflict", func(f *acquisitionFixture) {
			f.target.GetAnnotations()["hanko.sh/migrate-keycloak-client-uuid"] = "client-uuid"
		}},
		{"changed generation", func(f *acquisitionFixture) { f.target.SetGeneration(2) }},
		{"changed spec", func(f *acquisitionFixture) {
			f.target.(*api.HankoApplication).Spec.RedirectURIs = []string{"https://changed.example.test/cb"}
		}},
		{"foreign owner", func(f *acquisitionFixture) {
			f.document["attributes"].(map[string]any)[adoption.ApplicationOwnerKey] = "foreign"
		}},
		{"cross kind", func(f *acquisitionFixture) {
			f.document["attributes"].(map[string]any)[adoption.ClientOwnerKindKey] = "HankoServiceAccount"
		}},
		{"opaque native", func(f *acquisitionFixture) {
			f.document["attributes"].(map[string]any)["native.option"] = "secret-sentinel"
		}},
		{"opaque root", func(f *acquisitionFixture) { f.document["nativeNewSetting"] = true }},
		{"opaque mapper", func(f *acquisitionFixture) {
			f.mappers = []map[string]any{{"id": "native-id", "name": "native", "protocolMapper": "future", "config": map[string]any{"native": "secret-sentinel"}}}
		}},
		{"malformed receipt", func(f *acquisitionFixture) { f.document["attributes"].(map[string]any)[adoption.ReceiptKey] = "{}" }},
		{"provider replacement", func(f *acquisitionFixture) { f.document["id"] = "replacement" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newAcquisitionFixture(t, "HankoApplication", "oidc")
			f.approve()
			c.change(f)
			if err := f.kube.Update(context.Background(), f.target); err != nil {
				t.Fatal(err)
			}
			// Forge favorable status: it must never supply missing authority.
			app := f.target.(*api.HankoApplication)
			app.Status.AdoptionReceipt = &api.AdoptionReceiptStatus{ContractVersion: string(adoption.Version), CandidateHash: app.Annotations[adoption.CandidateAnnotation], State: "Verified"}
			if err := f.kube.Status().Update(context.Background(), app); err != nil {
				t.Fatal(err)
			}
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			_, conditions := f.status()
			if conditionReason(conditions, "OwnershipAdopted") == "AdoptionVerified" || f.puts != 0 || f.credentialCalls != 0 {
				t.Fatal("unsafe approval performed acquisition")
			}
		})
	}
}

type failAcquisitionStatus struct {
	client.Client
	failures int
}

func (c *failAcquisitionStatus) Status() client.SubResourceWriter {
	return &failAcquisitionStatusWriter{c.Client.Status(), c}
}

type failAcquisitionStatusWriter struct {
	client.SubResourceWriter
	parent *failAcquisitionStatus
}

func (w *failAcquisitionStatusWriter) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
	if w.parent.failures > 0 {
		w.parent.failures--
		return errors.New("status persistence unavailable")
	}
	return w.SubResourceWriter.Patch(ctx, o, p, opts...)
}
func TestOwnershipAcquisitionReceiptRecovery(t *testing.T) {
	for _, fault := range []string{"lost ack", "status patch", "partial"} {
		t.Run(fault, func(t *testing.T) {
			f := newAcquisitionFixture(t, "HankoApplication", "oidc")
			f.approve()
			f.lostAck, f.partial = fault == "lost ack", fault == "partial"
			if fault == "status patch" {
				f.kube = &failAcquisitionStatus{Client: f.kube, failures: 1}
			}
			err := f.run()
			if (err != nil) != (fault == "status patch") {
				t.Fatal("unexpected transaction error", err)
			}
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			s, _ := f.status()
			want := "Verified"
			if fault == "partial" {
				want = "Partial"
			}
			if f.puts != 1 || s == nil || s.State != want {
				t.Fatal("receipt recovery replayed PUT or lost checkpoint", f.puts, s)
			}
			app := f.target.(*api.HankoApplication)
			app.Spec.Mode, app.Generation = ModeManage, 2
			app.Annotations = nil
			if err := f.kube.Update(context.Background(), app); err != nil {
				t.Fatal(err)
			}
			handled, _, err := reconcileOwnershipAcquisition(context.Background(), f.kube, f.kube, app, f.writer, nil)
			if err != nil {
				t.Fatal(err)
			}
			if handled != (fault == "partial") || f.puts != 1 {
				t.Fatal("durable checkpoint did not distinguish qualified Manage from partial ownership")
			}
		})
	}
}

func TestOwnershipAcquisitionFreshIdentityBoundary(t *testing.T) {
	t.Run("changed source import latch", func(t *testing.T) {
		f := newAcquisitionFixture(t, "HankoRole", "")
		f.approve()
		f.target.SetLabels(map[string]string{importedByLabel: "inventory"})
		if err := f.kube.Create(context.Background(), &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}, Spec: api.HankoImportSpec{SourceRef: "other-source"}}); err != nil {
			t.Fatal(err)
		}
		if err := f.kube.Update(context.Background(), f.target); err != nil {
			t.Fatal(err)
		}
		if err := f.run(); err != nil {
			t.Fatal(err)
		}
		_, conditions := f.status()
		if conditionReason(conditions, "OwnershipAdopted") != "AdoptionIdentityChanged" || f.puts != 0 {
			t.Fatal("source/import disagreement authorized writes")
		}
	})
	t.Run("writer endpoint differs", func(t *testing.T) {
		f := newAcquisitionFixture(t, "HankoRole", "")
		other := newAcquisitionFixture(t, "HankoRole", "")
		f.approve()
		f.writer = other.writer
		if err := f.run(); err != nil {
			t.Fatal(err)
		}
		_, conditions := f.status()
		if conditionReason(conditions, "OwnershipAdopted") != "AdoptionIdentityChanged" || f.puts != 0 || other.puts != 0 {
			t.Fatal("reader/writer identity mismatch authorized writes")
		}
	})
	t.Run("metadata changed at write boundary", func(t *testing.T) {
		f := newAcquisitionFixture(t, "HankoRole", "")
		f.approve()
		guard := func(ctx context.Context, o client.Object, _ *keycloak.Client) error {
			current := &api.HankoRole{}
			if err := f.kube.Get(ctx, client.ObjectKeyFromObject(o), current); err != nil {
				return err
			}
			current.Annotations[adoption.CandidateAnnotation] = "sha256:" + strings.Repeat("b", 64)
			return f.kube.Update(ctx, current)
		}
		_, _, _ = reconcileOwnershipAcquisition(context.Background(), f.kube, f.kube, f.target, f.writer, guard)
		if f.puts != 0 {
			t.Fatal("annotation race authorized owner PUT")
		}
	})
	t.Run("already owned is not retroactively receipted", func(t *testing.T) {
		f := newAcquisitionFixture(t, "HankoRole", "")
		f.approve()
		f.document["attributes"].(map[string]any)[adoption.RoleOwnerKey] = []string{"target-uid"}
		if err := f.run(); err != nil {
			t.Fatal(err)
		}
		receipt, conditions := f.status()
		if receipt != nil || conditionReason(conditions, "OwnershipAdopted") != "AlreadyOwned" || f.puts != 0 {
			t.Fatal("existing ownership changed for cosmetic receipt")
		}
	})
}
