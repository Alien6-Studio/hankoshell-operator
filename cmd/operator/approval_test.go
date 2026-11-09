package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOnlyUnapprovedOLMInstallationsWaitForApproval(t *testing.T) {
	pending := runtimeConfig{installationRequired: true, installationConfigMap: "approved-contract"}
	if !pending.awaitsInstallationApproval() {
		t.Fatal("bundle installation without a Subscription approval must wait instead of exiting")
	}
	for name, config := range map[string]runtimeConfig{
		"helm":               {},
		"approved":           {installationRequired: true, installationConfigMap: "approved-contract", installationDigest: "approved-hash"},
		"no-configmap":       {installationRequired: true},
		"contract-file":      {installationRequired: true, installationContract: "/contract.json"},
		"check-only":         {installationRequired: true, installationConfigMap: "approved-contract", installationCheckOnly: true},
		"not-required":       {installationConfigMap: "approved-contract"},
		"digest-without-map": {installationRequired: true, installationDigest: "approved-hash"},
	} {
		if config.awaitsInstallationApproval() {
			t.Fatalf("%s configuration must verify or fail, not wait: %#v", name, config)
		}
		if name != "helm" && name != "approved" {
			if err := verifyInstallation(config); err == nil {
				t.Fatalf("%s configuration was silently accepted", name)
			}
		}
	}
}

func TestApprovalPendingProbesReportTheWaitAndNothingElse(t *testing.T) {
	server := httptest.NewServer(approvalPendingHandler())
	t.Cleanup(server.Close)
	for _, path := range []string{"/healthz", "/readyz", "/readyz?exclude=leader"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "installation approval pending") {
			t.Fatalf("%s: status %d body %q", path, response.StatusCode, body)
		}
	}
	for _, path := range []string{"/metrics", "/", "/healthz/extra"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s served while awaiting approval: %d", path, response.StatusCode)
		}
	}
}

func TestAwaitInstallationApprovalServesUntilShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- awaitInstallationApproval(ctx, addr) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("readiness while pending = %d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("orderly shutdown returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("approval wait did not stop on shutdown")
	}
}
