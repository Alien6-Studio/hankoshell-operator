package workloadtrust

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testPlan(t testing.TB) Plan {
	t.Helper()
	h := Digest("test", "public")
	p, err := Compile(Intent{RealmRef: "managed", Alias: "cluster", Issuer: "https://cluster.example.test", NamespaceUID: "namespace-uid", CAHash: h, MaxAge: 600}, References{Owner: "trust-uid", Generation: 1, RealmID: "realm-uuid", ProviderID: "provider-uuid", SourceHash: h, FreshReferencesHash: h, FlowHash: h, DependenciesHash: h})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanRejectsUnqualifiedInputsAndStaleAuthority(t *testing.T) {
	p := testPlan(t)
	if err := p.Validate(p); err != nil {
		t.Fatalf("current compiled plan rejected: %v", err)
	}
	forged := p
	forged.refs.Owner = ""
	if forged.Validate(forged) == nil {
		t.Fatal("matching forged identity skipped reference validation")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Plan
	if err := json.Unmarshal(encoded, &decoded); err != nil { //nolint:staticcheck // Public identity must not hydrate private execution authority.
		t.Fatal(err)
	}
	if decoded.Validate(p) == nil || p.Identity() == decoded.Identity() {
		t.Fatal("public identity serialization reconstructed execution authority")
	}
	for _, age := range []int64{0, 599, 3601} {
		i := p.Intent()
		i.MaxAge = age
		if _, err := Compile(i, p.References()); err == nil {
			t.Fatal("invalid age accepted")
		}
	}
	i := p.Intent()
	i.DiscoveryURL = "https://override.example.test"
	if _, err := Compile(i, p.References()); err == nil {
		t.Fatal("unqualified override accepted")
	}
	i.QualifiedVersion = "26.7.5"
	if _, err := Compile(i, p.References()); err == nil {
		t.Fatal("26.7 override accepted")
	}
	i.QualifiedVersion = "26.8.0"
	if _, err := Compile(i, p.References()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*References){func(r *References) { r.Generation++ }, func(r *References) { r.Owner = "replaced" }, func(r *References) { r.ProviderID = "replaced" }, func(r *References) { r.RealmID = "replaced" }, func(r *References) { r.SourceHash = Digest("changed", 1) }, func(r *References) { r.DependenciesHash = Digest("changed", 1) }, func(r *References) { r.FreshReferencesHash = Digest("changed", 1) }, func(r *References) { r.FlowHash = Digest("changed", 1) }} {
		r := p.References()
		change(&r)
		q, err := Compile(p.Intent(), r)
		if err != nil || p.Validate(q) == nil {
			t.Fatal("stale authority not rejected")
		}
	}
}

func TestJournalCheckpointAndAgeReviewBindCurrentIdentity(t *testing.T) {
	p := testPlan(t)
	state := Digest("state", 1)
	value, err := p.Journal(state, "Applied")
	if err != nil {
		t.Fatal(err)
	}
	j, err := ParseJournal(value)
	if err != nil || !j.Matches(p, state) || j.Matches(p, Digest("state", 2)) {
		t.Fatal("journal binding")
	}
	for _, v := range []string{value + " {}", strings.Replace(value, `"Applied"`, `"unknown"`, 1), strings.Replace(value, `"owner":`, `"extra":1,"owner":`, 1)} {
		if _, err := ParseJournal(v); err == nil {
			t.Fatal("ambiguous journal accepted")
		}
	}
	cp, err := p.Checkpoint("Owned")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCheckpoint(cp)
	if err != nil || !c.Matches(p) {
		t.Fatal("checkpoint binding")
	}
	r := p.References()
	r.SourceHash = Digest("other", 1)
	q, _ := Compile(p.Intent(), r)
	if c.Matches(q) {
		t.Fatal("checkpoint follows different backend")
	}
	approved, _ := json.Marshal(p.AgeReview(3600))
	if p.ApproveAge(string(approved), 3600) != nil || q.ApproveAge(string(approved), 3600) == nil || p.ApproveAge(string(approved), 1200) == nil || p.ApproveAge(string(approved)+" {}", 3600) == nil {
		t.Fatal("age review accepted stale authority")
	}
	duplicate := strings.Replace(string(approved), `"contract":`, `"contract":"hanko.sh/iam-contract/v1alpha1","contract":`, 1)
	if p.ApproveAge(duplicate, 3600) == nil {
		t.Fatal("duplicate approval authority accepted")
	}
	if len(PlannedProviderID("trust", "realm", "source")) != 36 || PlannedProviderID("trust", "realm", "source") == PlannedProviderID("trust", "realm", "other") {
		t.Fatal("planned UUID binding")
	}
}

func TestAnchorUsesPublicDERAndRejectsAmbiguity(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	cert := s.Certificate()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	h, err := APICAHash(data)
	if err != nil {
		t.Fatal(err)
	}
	formatted := append([]byte("\n"), data...)
	formatted = append(formatted, data...)
	other, err := APICAHash(formatted)
	if err != nil || h != other {
		t.Fatal("PEM formatting changes anchor")
	}
	for _, bad := range [][]byte{nil, []byte("garbage"), append(data, []byte("garbage")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("withheld")})} {
		if _, err := APICAHash(bad); err == nil {
			t.Fatal("ambiguous CA accepted")
		}
	}
}

func TestHTTPSInputsRejectAmbiguousAddresses(t *testing.T) {
	for _, bad := range []string{"http://cluster.test", "https://user@cluster.test", "https://cluster.test?x=1", "https://cluster.test#fragment", "https://CLUSTER.test", "https://cluster.test/a/../b", "https://cluster.test/a%2Fb", "https://cluster.test:0", "https://cluster.test:0443", "https://cluster.test//path"} {
		if ValidHTTPS(bad) {
			t.Errorf("accepted %s", bad)
		}
	}
	for _, good := range []string{"https://cluster.test", "https://cluster.test:6443", "https://127.0.0.1:443", "https://[::1]:443/path"} {
		if !ValidHTTPS(good) {
			t.Errorf("refused %s", good)
		}
	}
}
