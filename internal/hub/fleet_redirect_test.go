package hub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFleetAuthenticatedRoutesNeverFollowRedirects(t *testing.T) {
	forwarded := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forbidden" {
			forwarded++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/forbidden", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	transport := server.Client()
	c := NewFleetClient(server.URL, "tenant", "disposable", transport)
	if _, err := c.ReportStatus(context.Background(), OperatorStatus{}); err == nil {
		t.Fatal("redirect accepted as a heartbeat")
	}
	if _, err := c.PrepareRotation(context.Background(), "rotation"); err == nil {
		t.Fatal("redirect accepted as credential rotation")
	}
	if err := c.ConfirmRotation(context.Background()); err == nil {
		t.Fatal("redirect accepted as credential confirmation")
	}
	if forwarded != 0 || transport.CheckRedirect != nil {
		t.Fatal("Fleet forwarded authority or changed another client")
	}
}
