package hub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFleetTransportRequiresExactHTTPSAndNoRedirects(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.URL.Path != "/api/v1/bundles/latest" || req.Header.Get("Accept") != "application/vnd.hanko.fleet-plan+json" ||
			req.Header.Get("Authorization") != "Bearer fixture" || req.Header.Get("X-Tenant-ID") != "tenant" {
			t.Error("signed transport lost its route or scoped credentials")
		}
		_, _ = w.Write([]byte(`{"opaque":"signed bytes"}`))
	}))
	defer server.Close()
	client := NewWithHTTPClient(server.URL, "tenant", "fixture", server.Client())
	body, err := client.FetchFleetPlan(context.Background())
	if err != nil || string(body) != `{"opaque":"signed bytes"}` || requests != 1 {
		t.Fatalf("signed bytes were not returned intact: %v", err)
	}
	for _, endpoint := range []string{"http://hub.invalid", "://invalid", server.URL + "?token=private", server.URL + "#private", "https://user:private@hub.invalid"} {
		if _, err := NewWithHTTPClient(endpoint, "tenant", "fixture", server.Client()).FetchFleetPlan(context.Background()); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe endpoint accepted or copied to the error")
		}
	}
	redirected := 0
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		redirected++
		http.Redirect(w, req, server.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if _, err := NewWithHTTPClient(redirect.URL, "tenant", "fixture", redirect.Client()).FetchFleetPlan(context.Background()); err == nil || redirected != 1 || requests != 1 {
		t.Fatal("signed transport followed a redirect")
	}
}

func TestFleetTransportBoundsAndSanitizesFailures(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
		body := &measuredHubBody{Reader: strings.NewReader(strings.Repeat("private", maxBundleEnvelopeBytes))}
		_, err := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", measuredHubClient(status, body)).FetchFleetPlan(context.Background())
		if err == nil || strings.Contains(err.Error(), "private") || !body.closed || body.read > maxBundleEnvelopeBytes+1 || (status != http.StatusOK && body.read != 0) {
			t.Fatal("unbounded or unsafe remote response")
		}
	}
	transport := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("private transport detail")
	})}
	if _, err := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", transport).FetchFleetPlan(context.Background()); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("transport error exposed remote detail")
	}
	body := &measuredHubBody{Reader: failingReader{}}
	if _, err := NewWithHTTPClient("https://hub.invalid", "tenant", "fixture", measuredHubClient(http.StatusOK, body)).FetchFleetPlan(context.Background()); err == nil || !body.closed {
		t.Fatal("broken stream accepted")
	}
}
