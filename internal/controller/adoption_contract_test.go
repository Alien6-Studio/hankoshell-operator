package controller

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestAdoptionInventoryNeverIntroducesProviderWriteCalls(t *testing.T) {
	files, err := filepath.Glob("adoption_*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"CredentialClientID": true, "RestrictToInventory": true, "BaseURL": true, "InventoryClients": true, "InventoryRealmRoles": true, "InventoryClientRoles": true, "InventoryRoleChildren": true, "InventoryGroups": true, "InventoryGroupRoles": true, "InventoryOrganizations": true, "InventoryOrganizationsEnabled": true, "InventoryAuthorization": true, "GetRealm": true, "GetRealmRole": true, "GetRealmRoleCompositeNames": true, "GetApplication": true, "ListClientProtocolMappers": true, "GetClientRealmRoleScopes": true, "ListIdentityProviders": true, "ListIdentityProviderMappers": true}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(tree, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			transaction := file == "adoption_acquisition.go" && map[string]bool{"ReadClientOwnership": true, "ReadRoleOwnership": true, "MarkApplicationAdoption": true, "MarkRoleAdoption": true, "MarkServiceAccountAdoption": true}[selector.Sel.Name]
			qualifiedRead := file == "adoption_refresh.go" && selector.Sel.Name == "ReadClientOwnership"
			if ok && receiver.Name == "kc" && !allowed[selector.Sel.Name] && !transaction && !qualifiedRead {
				t.Errorf("unreviewed provider operation %s in %s", selector.Sel.Name, file)
			}
			return true
		})
	}
	// Keep the pure evidence package incapable of transport or provider writes.
	entries, err := os.ReadDir("../adoption")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "_test.go") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), "../adoption/"+entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range tree.Imports {
			if strings.Contains(imp.Path.Value, "keycloak") || strings.Contains(imp.Path.Value, "controller-runtime") || strings.Contains(imp.Path.Value, "net/http") {
				t.Fatal("evidence package acquired runtime authority")
			}
		}
	}
}
func TestImportSourceRefIsAuthoritativeEvenWithWriterPool(t *testing.T) {
	writerCalls := 0
	writer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writerCalls++; w.WriteHeader(http.StatusForbidden) }))
	defer writer.Close()
	readerCalls := 0
	reader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readerCalls++
		if r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("client_id") != "inventory-reader" {
				t.Error("writer credential used")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 300})
			return
		}
		if r.URL.Path == "/admin/realms" {
			_ = json.NewEncoder(w).Encode([]keycloak.Realm{})
			return
		}
		t.Error("unexpected provider operation")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer reader.Close()
	scheme := controllerTestScheme(t)
	operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "test"}, Spec: api.HankoImportSpec{SourceRef: "source", DryRun: true}}
	kube := controllerTestClient(scheme, operation)
	provisionImportTestSource(t, kube, operation, reader.URL)
	var secret corev1.Secret
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "inventory-reader"}, &secret); err != nil {
		t.Fatal(err)
	}
	secret.Data["HANKO_KC_CLIENT_ID"] = []byte("inventory-reader")
	if err := kube.Update(context.Background(), &secret); err != nil {
		t.Fatal(err)
	}
	r := &HankoImportReconciler{Client: kube, APIReader: kube, Pool: keycloak.NewPool(keycloak.New(writer.URL, "writer", "writer-secret", keycloak.WithInsecureHTTP()))}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(operation)}); err != nil {
		t.Fatal(err)
	}
	if writerCalls != 0 || readerCalls == 0 {
		t.Fatal("sourceRef reader did not exclusively handle inventory")
	}
	missing := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "missing-source", Namespace: "test"}, Spec: api.HankoImportSpec{SourceRef: "absent"}}
	if err := kube.Create(context.Background(), missing); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(missing)}); err != nil {
		t.Fatal(err)
	}
	if writerCalls != 0 {
		t.Fatal("missing source fell back to writer")
	}
	var got api.HankoImport
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(missing), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Failed" || conditionReason(got.Status.Conditions, "InventoryComplete") != "Incomplete" {
		t.Fatal("missing source did not fail coverage closed")
	}
}
func TestAdoptionCredentialsExcludedAndSAMLQualified(t *testing.T) {
	c := keycloak.InventoryClient{Application: keycloak.Application{ID: "client-id", ClientID: "https://sp.example.test", Protocol: "saml", Enabled: true, RedirectURIs: []string{"https://sp.example.test/acs"}, Attributes: map[string]string{"saml_name_id_format": "persistent", "saml.assertion.signature": "true", "saml.server.signature": "true", "saml.client.signature": "true", "saml.signing.certificate": "certificate-secret-sentinel", "innocent.future.option": "client-secret-sentinel"}}}
	spec, ok := importedApplicationSpec("realm", c, nil, nil)
	if !ok || spec.Protocol != "saml" || spec.Mode != ModeObserve || spec.SAML == nil {
		t.Fatal("qualified SAML Observe generation missing")
	}
	item := newInventoryItem("application", "realm", c.ID, c.ClientID)
	observeClientAttributes(item, c)
	target := adoption.TargetIdentity{Kind: "HankoApplication", Namespace: "auth", Name: "saml", UID: "target"}
	p := adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "source"}, Origin: "https://keycloak.example.test", RealmID: "realm", Trust: "public-ca", ObjectIDs: item.ids}
	before := adoption.Build(target, p, item.observation, nil)
	if !before.Complete || before.Approvable {
		t.Fatal("native request signing/certificate must block approval without hiding classified observation")
	}
	c.Attributes["saml.signing.certificate"] = "rotated-certificate-sentinel"
	c.Attributes["innocent.future.option"] = "rotated-client-secret-sentinel"
	item = newInventoryItem("application", "realm", c.ID, c.ClientID)
	observeClientAttributes(item, c)
	after := adoption.Build(target, p, item.observation, nil)
	if before.ObservationHash != after.ObservationHash || before.CandidateHash != after.CandidateHash {
		t.Fatal("opaque credential rotation changed public evidence")
	}
	b, _ := json.Marshal(before)
	for _, secret := range []string{"certificate-secret-sentinel", "client-secret-sentinel"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("credential bytes escaped typed projection")
		}
	}
	cfg := safeBrokerConfig(map[string]string{"issuer": "https://idp.example.test", "clientSecret": "broker-secret-sentinel", "future.option": "bearer-token-sentinel", "authorizationUrl": "https://user:password@idp.example.test"})
	b, _ = json.Marshal(cfg)
	if strings.Contains(string(b), "sentinel") || len(cfg) != 1 {
		t.Fatal("broker projection exported unreviewed config")
	}
}

func TestInventoryCandidateNoOpAndFreshTargetBoundary(t *testing.T) {
	ctx := context.Background()
	object := &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "auth", UID: "target-uid", Generation: 1, Labels: map[string]string{importedByLabel: "inventory"}}, Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "client", Type: "spa", Mode: ModeObserve}}
	kube := controllerTestClient(controllerTestScheme(t), object)
	reconciler := &HankoImportReconciler{Client: kube, APIReader: kube}
	operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}}
	item := newInventoryItem("application", "realm", "provider-uuid", "client")
	item.fact("owner", textValue("unmarked"))
	target, desired := reconciler.currentInventoryTarget(ctx, operation, item)
	provider := adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "instance"}, Origin: "https://keycloak.example.test", RealmID: "realm", Trust: "public-ca"}
	candidate := adoption.Build(target, provider, item.observation, desired)
	if !reconciler.patchInventoryCandidate(ctx, target, candidate) {
		t.Fatal("fresh candidate not published")
	}
	got := &api.HankoApplication{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(object), got); err != nil {
		t.Fatal(err)
	}
	version := got.ResourceVersion
	if !reconciler.patchInventoryCandidate(ctx, target, candidate) {
		t.Fatal("semantic no-op failed")
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(object), got); err != nil {
		t.Fatal(err)
	}
	if got.ResourceVersion != version {
		t.Fatal("semantic no-op rewrote status")
	}
	got.Generation++
	got.Spec.RedirectURIs = []string{"https://changed.example.test"}
	if err := kube.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if reconciler.patchInventoryCandidate(ctx, target, candidate) {
		t.Fatal("changed spec accepted stale evidence")
	}
	next, desired := reconciler.currentInventoryTarget(ctx, operation, item)
	if candidate.CandidateHash == adoption.Build(next, provider, item.observation, desired).CandidateHash {
		t.Fatal("current desired spec not bound to candidate")
	}
	got.Labels["hanko.sh/tenant"] = "changed-connection"
	if err := kube.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if reconciler.patchInventoryCandidate(ctx, next, adoption.Build(next, provider, item.observation, desired)) {
		t.Fatal("connection-selecting metadata accepted stale candidate")
	}
	if err := kube.Delete(ctx, got); err != nil {
		t.Fatal(err)
	}
	replacement := object.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-uid"
	if err := kube.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if reconciler.patchInventoryCandidate(ctx, target, candidate) {
		t.Fatal("same-name replacement accepted stale evidence")
	}
}
func TestInventorySAMLAndTypedMapperSafeProjection(t *testing.T) {
	for _, value := range []string{"https://", "https://sp.example.test:0/acs", "https://sp.example.test:99999/acs", "https://user:pass@sp.example.test/acs", "https://sp.example.test/acs?token=private", "https://sp.example.test/acs#fragment"} {
		if safeSAMLACS(value) {
			t.Fatal("unqualified SAML ACS accepted")
		}
	}
	mapper := keycloak.IdentityProviderMapper{IdentityProviderMapper: "oidc-user-attribute-idp-mapper", Config: map[string]string{"claim": "department", "user.attribute": "department", "syncMode": "IMPORT", "innocent": "secret-sentinel"}}
	data, _ := json.Marshal(safeInventoryIDPMapper(mapper))
	if strings.Contains(string(data), "sentinel") || len(safeInventoryIDPMapper(mapper)) != 3 {
		t.Fatal("mapper escaped closed safe config")
	}
	mapper.IdentityProviderMapper = "unqualified-native"
	if len(safeInventoryIDPMapper(mapper)) != 0 {
		t.Fatal("unknown mapper config treated as portable")
	}
}

func TestImportSummaryIdentityBudgetFailsClosed(t *testing.T) {
	operation := &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}}
	operation.Status.Coverage.Complete = true
	item := newInventoryItem("realm", strings.Repeat("r", adoption.MaxReferenceBytes+1), strings.Repeat("i", adoption.MaxProviderIDBytes+1), "safe")
	inventory := &realmAdoptionInventory{complete: true, items: []*adoptionInventoryItem{item}, provider: adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "instance"}, Origin: "https://keycloak.example.test", RealmID: "realm", Trust: "public-ca"}}
	reconciler := &HankoImportReconciler{Client: controllerTestClient(controllerTestScheme(t))}
	reconciler.publishImportEvidence(context.Background(), operation, []importedRealmData{{inventory: inventory}})
	if operation.Status.Coverage.Complete || !operation.Status.Coverage.Truncated || len(operation.Status.Inventory) != 1 {
		t.Fatal("oversized identity was not classified as truncated coverage")
	}
	summary := operation.Status.Inventory[0]
	if summary.Realm != "" || summary.ProviderID != "" || summary.Complete || summary.Approvable || len(summary.Findings) == 0 {
		t.Fatal("oversized raw identity escaped the bounded public summary")
	}
}

func TestExpectedNativeKeysStillRejectPrivateValues(t *testing.T) {
	item := newInventoryItem("application", "realm", "provider-id", "app")
	client := keycloak.InventoryClient{Application: keycloak.Application{ID: "provider-id", ClientID: "app", Attributes: map[string]string{"saml_assertion_consumer_url_post": "https://user:password-sentinel@sp.example.test/acs", "saml_name_id_format": "opaque-secret-sentinel", "post.logout.redirect.uris": "https://app.example.test/callback?token=bearer-sentinel"}}}
	observeClientAttributes(item, client)
	mapper := keycloak.ProtocolMapper{ID: "mapper", Name: "mapper", ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{"user.attribute": "department", "claim.name": "department", "jsonType.label": "private-value-sentinel"}}
	observeInventoryMappers(item, []keycloak.ProtocolMapper{mapper})
	if _, qualified := importedTokenClaim(mapper); qualified {
		t.Fatal("unreviewed JSON type exported to a declaration")
	}
	if _, qualified := importedApplicationSpec("realm", client, nil, nil); qualified {
		t.Fatal("credential-bearing callback copied into declaration")
	}
	data, _ := json.Marshal(item.observation)
	if strings.Contains(string(data), "sentinel") {
		t.Fatal("expected native config key bypassed safe typed values")
	}
}

func TestOnlyQualifiedKeycloakDefaultsAreCanonicalAndNonBlocking(t *testing.T) {
	target := adoption.TargetIdentity{Kind: "HankoApplication", Namespace: "auth", Name: "client", UID: "target"}
	provider := adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "source"}, Origin: "https://keycloak.example.test", Trust: "public-ca", RealmID: "realm"}
	build := func(attributes map[string]string) *api.AdoptionCandidateStatus {
		item := newInventoryItem("application", "realm", "client-id", "client")
		observeClientAttributes(item, keycloak.InventoryClient{Application: keycloak.Application{Attributes: attributes}})
		return candidateStatus(adoption.Build(target, provider, item.observation, nil))
	}
	for key, canonical := range map[string]string{"realm_client": "false", "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "false"} {
		t.Run(key, func(t *testing.T) {
			known := build(map[string]string{key: canonical})
			if !known.Approvable || len(known.Diff) != 1 || !qualifiedDefaultDiff(known.Diff[0]) {
				t.Fatal("exact default not represented read-only", known.Diff)
			}
			if adoptionCandidateFailure(known, adoption.Approval{CandidateHash: known.CandidateHash}) != "" {
				t.Fatal("qualified default blocked acquisition")
			}
			for _, unsafe := range []string{"", "TRUE", "ambiguous-secret-sentinel", map[string]string{"true": "false", "false": "true"}[canonical]} {
				changed := build(map[string]string{key: unsafe})
				if changed.Approvable || changed.CandidateHash == known.CandidateHash || adoptionCandidateFailure(changed, adoption.Approval{CandidateHash: known.CandidateHash}) == "" {
					t.Fatal("changed default accepted")
				}
				data, _ := json.Marshal(changed)
				if strings.Contains(string(data), "sentinel") {
					t.Fatal("unqualified default value escaped public evidence")
				}
			}
			absent := build(nil)
			if absent.CandidateHash == known.CandidateHash {
				t.Fatal("default presence not hashed")
			}
		})
	}
	other := build(map[string]string{"other.native": "false"})
	if other.Approvable {
		t.Fatal("default exception expanded to another native attribute")
	}
}

func TestMapperOwnerBoundaryUsesFreshTargetAndKind(t *testing.T) {
	for _, test := range []struct {
		kind, owner string
		conflict    bool
	}{{"application", "target-uid", false}, {"application", "foreign-owner-sentinel", true}, {"service-account", "target-uid", true}} {
		t.Run(test.kind+test.owner, func(t *testing.T) {
			metadata := metav1.ObjectMeta{Name: "target", Namespace: "auth", UID: "target-uid", Labels: map[string]string{importedByLabel: "inventory"}}
			var object client.Object = &api.HankoApplication{ObjectMeta: metadata, Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "client", Type: "spa", Mode: ModeObserve}}
			if test.kind == "service-account" {
				object = &api.HankoServiceAccount{ObjectMeta: metadata, Spec: api.HankoServiceAccountSpec{RealmRef: "realm", ClientID: "client"}}
			}
			kube := controllerTestClient(controllerTestScheme(t), object)
			item := newInventoryItem(test.kind, "realm", "provider", "client")
			mapper := keycloak.ProtocolMapper{ID: "mapper", Name: "department", ProtocolMapper: "oidc-usermodel-attribute-mapper", Config: map[string]string{"user.attribute": "department", "claim.name": "department", applications.OwnerAttribute: test.owner}}
			observeInventoryMappers(item, []keycloak.ProtocolMapper{mapper})
			reconciler := &HankoImportReconciler{Client: kube, APIReader: kube}
			target, desired := reconciler.currentInventoryTarget(context.Background(), &api.HankoImport{ObjectMeta: metav1.ObjectMeta{Name: "inventory", Namespace: "auth"}}, item)
			provider := adoption.ProviderIdentity{Instance: adoption.TargetIdentity{UID: "instance"}, Origin: "https://keycloak.example.test", RealmID: "realm", Trust: "public-ca", ObjectIDs: item.ids}
			candidate := adoption.Build(target, provider, item.observation, desired)
			conflict := false
			for _, entry := range candidate.Diff {
				if entry.Domain == "protocol-mapper" && entry.Field == "owner" {
					conflict = entry.Classification == adoption.Conflicting
				}
			}
			if conflict != test.conflict || (conflict && candidate.Approvable) {
				t.Fatal("mapper ownership boundary was ignored or treated as the wrong target kind")
			}
			data, _ := json.Marshal(candidate)
			if strings.Contains(string(data), "foreign-owner-sentinel") {
				t.Fatal("raw foreign owner marker escaped public evidence")
			}
		})
	}
}
