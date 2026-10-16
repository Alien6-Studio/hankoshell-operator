package authentik

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamconformance"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const testUUID = "00000000-0000-4000-8000-000000000001"

func testConnection(endpoint string) Connection {
	return Connection{SchemaVersion: 1, Provider: "authentik", Version: Version, Endpoint: endpoint, Realm: "portable", TokenSecret: "provider-token", AuthorizationFlow: testUUID, InvalidationFlow: testUUID, SigningKey: testUUID, ScopeMappings: []string{testUUID}}
}
func testIntent() applications.Intent {
	return applications.Intent{RealmRef: "portable", ClientID: "portable-spa", Pattern: "spa", RedirectURIs: []string{"https://app.example/callback", "https://app.example/other"}}
}
func testPlan(t *testing.T, i applications.Intent, owner string, connection Connection) applications.Plan {
	t.Helper()
	p, err := applications.CompileForBackend(iamcontract.Authentik, i, applications.ResolvedReferences{Realm: "portable", Owner: owner, PublicBase: connection.Endpoint, ConnectionIdentity: connection.Identity()}, Evidence(), iamcontract.Preconditions{ResourceUID: owner})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type memoryServer struct {
	p          *provider
	a          *application
	writes     int
	failMethod string
	failPath   string
	ackLost    bool
	secret     string
	foreign    bool
	denied     bool
	incomplete bool
}

func (m *memoryServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+m.secret {
		w.WriteHeader(401)
		return
	}
	if m.denied {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(m.secret))
		return
	}
	if r.Method != http.MethodGet {
		m.writes++
	}
	if r.Method == m.failMethod && r.URL.Path == m.failPath && !m.ackLost {
		w.WriteHeader(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	output := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/api/v3/providers/oauth2/" {
		if r.Method == http.MethodGet {
			results := []provider{}
			if m.p != nil {
				results = append(results, *m.p)
			}
			count := len(results)
			if m.incomplete {
				count++
			}
			output(providerList{Pagination: pagination{Count: count}, Results: results})
			return
		}
		var p provider
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			w.WriteHeader(400)
			return
		}
		p.PK = 7
		m.p = &p
		if m.ackLost {
			m.ackLost = false
			w.WriteHeader(503)
			return
		}
		output(p)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v3/providers/oauth2/7/") {
		if r.Method == http.MethodDelete {
			m.p = nil
			w.WriteHeader(204)
			return
		}
		var p provider
		_ = json.NewDecoder(r.Body).Decode(&p)
		p.PK = 7
		m.p = &p
		output(p)
		return
	}
	if r.URL.Path == "/api/v3/core/applications/" {
		var a application
		_ = json.NewDecoder(r.Body).Decode(&a)
		a.PK = testUUID
		m.a = &a
		if m.ackLost {
			m.ackLost = false
			w.WriteHeader(503)
			return
		}
		output(a)
		return
	}
	if m.a == nil {
		w.WriteHeader(404)
		return
	}
	if r.Method == http.MethodGet {
		a := *m.a
		if m.foreign {
			a.Marker = "foreign"
		}
		output(a)
		return
	}
	if r.Method == http.MethodDelete {
		m.a = nil
		w.WriteHeader(204)
		return
	}
	var a application
	_ = json.NewDecoder(r.Body).Decode(&a)
	a.PK = testUUID
	m.a = &a
	output(a)
}
func newTestDriver(t *testing.T, m *memoryServer) (*Driver, *httptest.Server) {
	t.Helper()
	m.secret = "SENTINEL-remote-credential-withheld"
	s := httptest.NewTLSServer(http.HandlerFunc(m.handler))
	t.Cleanup(s.Close)
	c, err := NewClient(s.URL, m.secret, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDriver(c, testConnection(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}
func TestApplicationConformance(t *testing.T) {
	ctx := context.Background()
	m := &memoryServer{}
	d, _ := newTestDriver(t, m)
	i := testIntent()
	p := testPlan(t, i, "owner-a", d.connection)
	iamconformance.Run(t, iamconformance.Fixture{
		Compile: func(reverse bool) iamcontract.PlanIdentity {
			copy := i
			if reverse {
				copy.RedirectURIs = append([]string(nil), i.RedirectURIs...)
				slices.Reverse(copy.RedirectURIs)
			}
			return testPlan(t, copy, "owner-a", d.connection).Identity()
		},
		Refuse: func() error {
			bad := i
			bad.Pattern = "m2m"
			_, err := d.Ensure(ctx, testPlan(t, bad, "owner-a", d.connection))
			return err
		},
		Writes:         func() int { return m.writes },
		Manage:         func() error { _, err := d.Ensure(ctx, p); return err },
		Observe:        func() error { _, err := d.Observe(ctx, p); return err },
		DriftAndRepair: func() error { m.p.Redirects = nil; _, err := d.Ensure(ctx, p); return err },
		Foreign:        func() error { _, err := d.Ensure(ctx, testPlan(t, i, "owner-b", d.connection)); return err },
		DeleteOwned:    func() error { return d.DeleteOwned(ctx, p) },
		VerifyDeleted: func() error {
			s, err := d.Observe(ctx, p)
			if err == nil && s.Present {
				return fmt.Errorf("not deleted")
			}
			return err
		},
	})
}
func TestJournalRecoveryAtEveryWriteBoundary(t *testing.T) {
	for _, path := range []string{"/api/v3/providers/oauth2/", "/api/v3/core/applications/"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			m := &memoryServer{failMethod: http.MethodPost, failPath: path}
			d, _ := newTestDriver(t, m)
			p := testPlan(t, testIntent(), "owner", d.connection)
			if _, err := d.Ensure(ctx, p); err == nil {
				t.Fatal("failed write accepted")
			}
			m.failMethod = ""
			m.ackLost = true
			if _, err := d.Ensure(ctx, p); err == nil {
				t.Fatal("lost acknowledgement accepted")
			}
			// A fresh driver models process loss. Recovery discovers the owned partial
			// graph and never creates another provider for the same client ID.
			restarted, err := NewDriver(d.client, d.connection)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Ensure(ctx, p); err != nil {
				t.Fatal(err)
			}
			id := m.p.PK
			writes := m.writes
			if _, err := restarted.Ensure(ctx, p); err != nil || m.writes != writes || m.p.PK != id {
				t.Fatal("recovery was not idempotent")
			}
		})
	}
}
func TestFailClosedBoundariesAndPrivacy(t *testing.T) {
	ctx := context.Background()
	m := &memoryServer{}
	d, s := newTestDriver(t, m)
	p := testPlan(t, testIntent(), "owner", d.connection)
	if _, err := d.Ensure(ctx, p); err != nil {
		t.Fatal(err)
	}
	m.foreign = true
	iamconformance.NoMutation(t, func() int { return m.writes }, func() error {
		if err := d.DeleteOwned(ctx, p); !errors.Is(err, ErrConflict) {
			t.Fatal("foreign deletion accepted")
		}
		return nil
	})
	m.foreign = false
	m.incomplete = true
	if _, err := d.Ensure(ctx, p); !errors.Is(err, ErrResponse) {
		t.Fatal("partial provider inventory accepted")
	}
	m.incomplete = false
	m.denied = true
	_, err := d.Ensure(ctx, p)
	if !errors.Is(err, ErrForbidden) {
		t.Fatal("permission failure lost typed status")
	}
	iamconformance.NoSecrets(t, []string{m.secret}, err.Error(), p, p.Evidence())
	m.denied = false
	// A Keycloak execution plan is never accepted by this adapter.
	kc, err := applications.Compile(testIntent(), applications.ResolvedReferences{Realm: "portable", Owner: "owner"}, applications.KeycloakEvidence(), iamcontract.Preconditions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Ensure(ctx, kc); !errors.Is(err, iamcontract.ErrRejected) {
		t.Fatal("cross-provider execution accepted")
	}
	if marker(s.URL, "owner") == marker("https://different.example", "owner") {
		t.Fatal("ownership crossed provider origins")
	}
}
func TestTransportRejectsRedirectsRoutesAndOversizedResponses(t *testing.T) {
	mode := "redirect"
	foreignRequests := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignRequests++; w.WriteHeader(200) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "redirect" {
			http.Redirect(w, r, target.URL, http.StatusFound)
		} else {
			_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
		}
	}))
	defer server.Close()
	c, err := NewClient(server.URL, "private-sentinel", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var result providerList
	query := url.Values{"client_id": {"safe"}, "page_size": {"2"}}
	if err := c.request(context.Background(), http.MethodGet, "/api/v3/providers/oauth2/", query, nil, &result); !errors.Is(err, ErrTransport) {
		t.Fatal("redirect accepted")
	}
	if foreignRequests != 0 {
		t.Fatal("credential reached foreign host")
	}
	mode = "oversized"
	if err := c.request(context.Background(), http.MethodGet, "/api/v3/providers/oauth2/", query, nil, &result); !errors.Is(err, ErrResponse) {
		t.Fatal("oversized response accepted")
	}
	for _, path := range []string{"/api/v3/core/users/", "/api/v3/providers/oauth2/../users/", "https://evil.example/", "/api/v3/providers/oauth2/1/%2e%2e/"} {
		if err := c.request(context.Background(), http.MethodDelete, path, nil, nil, nil); !errors.Is(err, ErrRoute) {
			t.Fatal("unsafe route accepted")
		}
	}
	for _, endpoint := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/api", "https://example.test?secret=x"} {
		if _, err := NewClient(endpoint, "private-sentinel", nil); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
}

func TestUnsupportedFieldsNeverReachProvider(t *testing.T) {
	m := &memoryServer{}
	driver, _ := newTestDriver(t, m)
	cases := []func(*applications.Intent, *applications.ResolvedReferences){
		func(i *applications.Intent, _ *applications.ResolvedReferences) { i.ClientID = "bad\nidentity" },
		func(i *applications.Intent, _ *applications.ResolvedReferences) { i.Theme = "native" },
		func(i *applications.Intent, _ *applications.ResolvedReferences) {
			i.Claims = []applications.Claim{{Name: "scope", Claim: "scope"}}
		},
		func(i *applications.Intent, _ *applications.ResolvedReferences) {
			i.Rotation = &applications.Rotation{}
		},
		func(i *applications.Intent, _ *applications.ResolvedReferences) {
			i.PostLogoutURIs = []string{"https://example.test/logout"}
		},
		func(i *applications.Intent, _ *applications.ResolvedReferences) {
			i.RedirectURIs = []string{"http://example.test/callback"}
		},
		func(i *applications.Intent, _ *applications.ResolvedReferences) {
			i.RedirectURIs = []string{"https://user:pass@example.test/callback"}
		},
		func(_ *applications.Intent, r *applications.ResolvedReferences) { r.Realm = "another-identity-domain" },
	}
	for _, mutate := range cases {
		i := testIntent()
		r := applications.ResolvedReferences{Realm: "portable", Owner: "owner", PublicBase: driver.connection.Endpoint, ConnectionIdentity: driver.connection.Identity()}
		mutate(&i, &r)
		p, err := applications.CompileForBackend(iamcontract.Authentik, i, r, Evidence(), iamcontract.Preconditions{})
		if err != nil {
			continue
		} // The compiler is also allowed to refuse before the adapter.
		iamconformance.NoMutation(t, func() int { return m.writes }, func() error {
			if _, err := driver.Ensure(t.Context(), p); err == nil {
				t.Fatal("unsupported field reached provider")
			}
			return nil
		})
	}
	connection := driver.connection
	connection.Version = "unqualified"
	if _, err := NewDriver(driver.client, connection); err == nil {
		t.Fatal("unqualified provider version accepted")
	}
	connection = driver.connection
	connection.ScopeMappings = nil
	if connection.Validate() == nil {
		t.Fatal("implicit OIDC scope mappings accepted")
	}
	if _, err := applications.CompileForBackend("future", testIntent(), applications.ResolvedReferences{Realm: "portable", Owner: "owner"}, Evidence(), iamcontract.Preconditions{}); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestPlanCannotBeReusedWithDifferentConnectionAuthority(t *testing.T) {
	m := &memoryServer{}
	driver, _ := newTestDriver(t, m)
	plan := testPlan(t, testIntent(), "owner", driver.connection)
	changed := driver.connection
	changed.AuthorizationFlow = "00000000-0000-4000-8000-000000000002"
	other, err := NewDriver(driver.client, changed)
	if err != nil {
		t.Fatal(err)
	}
	iamconformance.NoMutation(t, func() int { return m.writes }, func() error {
		if _, err := other.Ensure(t.Context(), plan); !errors.Is(err, ErrUnsupported) {
			t.Fatal("sealed execution reused different connection authority")
		}
		return nil
	})
	duplicate := driver.connection
	duplicate.ScopeMappings = append(append([]string(nil), duplicate.ScopeMappings...), duplicate.ScopeMappings[0])
	if duplicate.Validate() == nil {
		t.Fatal("duplicate provider scope binding was accepted")
	}
}
