package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMutationGuardRunsBeforeEveryProviderWrite(t *testing.T) {
	writes, checks := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			writes++
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	base := New(server.URL+"/auth", "writer", "fixture", WithInsecureHTTP())
	refused := errors.New("local authority expired")
	allowed := true
	guarded := base.WithMutationGuard(func(context.Context) error {
		checks++
		if !allowed {
			return refused
		}
		return nil
	})
	request := func(c *Client, method, path string) error {
		req, err := http.NewRequestWithContext(context.Background(), method, server.URL+"/auth"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := c.do(req)
		if response != nil {
			response.Body.Close()
		}
		return err
	}
	if err := request(guarded, http.MethodGet, "/admin/realms/managed"); err != nil {
		t.Fatal(err)
	}
	if err := request(guarded, http.MethodPost, "/realms/master/protocol/openid-connect/token"); err != nil {
		t.Fatal(err)
	}
	if checks != 0 {
		t.Fatal("read/token acquisition consumed mutation authority")
	}
	if err := request(guarded, http.MethodPut, "/admin/realms/managed"); err != nil {
		t.Fatal(err)
	}
	allowed = false // expires after read/first write, before another write.
	for _, c := range []*Client{guarded, guarded.WithMutationGuard(nil)} {
		if err := request(c, http.MethodPut, "/admin/realms/managed"); !errors.Is(err, refused) {
			t.Fatalf("expired authority reached provider: %v", err)
		}
	}
	if writes != 1 || checks != 3 {
		t.Fatal("mutation guard skipped")
	}
	if err := request(base, http.MethodPut, "/admin/realms/managed"); err != nil || writes != 2 {
		t.Fatal("tenant guard contaminated installation client")
	}
	var missing *Client
	if missing.WithMutationGuard(nil) != nil {
		t.Fatal("missing connection acquired authority")
	}
}
