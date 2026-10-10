package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCleanupMembershipExistenceReadsStayBoundedAndOutsideInventory(t *testing.T) {
	reads := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			_, _ = w.Write([]byte(`{"access_token":"fixture-token","expires_in":300}`))
			return
		}
		reads++
		if r.Method != http.MethodGet || r.URL.Query().Get("max") != "1" || r.URL.Query().Get("first") != "0" {
			t.Error("unsafe membership query")
		}
		_, _ = w.Write([]byte(`[{"id":"user-sentinel","username":"private-member-sentinel"}]`))
	}))
	defer s.Close()
	c := New(s.URL, "operator", "secret", WithInsecureHTTP())
	for _, read := range []func(context.Context, string, string) (bool, error){c.HasGroupMembers, c.HasOrganizationMembers} {
		present, err := read(context.Background(), "realm", "object")
		if err != nil || !present {
			t.Fatal("bounded existence not observed", err)
		}
	}
	for _, query := range []string{"", "?max=100", "?first=0&max=1&max=100", "?first=0&max=1&search=private"} {
		req, _ := http.NewRequest(http.MethodGet, s.URL+"/admin/realms/realm/groups/object/members"+query, nil)
		if _, err := c.do(req); err == nil {
			t.Fatal("unbounded membership query accepted", query)
		}
	}
	c.RestrictToInventory()
	if _, err := c.HasGroupMembers(context.Background(), "realm", "object"); err == nil {
		t.Fatal("inventory read a group member")
	}
	if _, err := c.HasOrganizationMembers(context.Background(), "realm", "object"); err == nil {
		t.Fatal("inventory read an organization member")
	}
	if reads != 2 {
		t.Fatal("unsafe membership query reached provider", reads)
	}
}
