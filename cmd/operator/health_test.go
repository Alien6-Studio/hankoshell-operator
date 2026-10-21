package main

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestServingAndLeaderReadinessAreIndependent(t *testing.T) {
	elected := make(chan struct{})
	health := &runtimeHealth{elected: elected}
	request := httptest.NewRequest("GET", "/readyz", nil)
	if health.servingCheck(request) == nil || health.leaderCheck(request) == nil {
		t.Fatal("unstarted manager is ready")
	}
	health.serving.Store(true)
	if health.servingCheck(request) != nil || health.leaderCheck(request) == nil {
		t.Fatal("standby serving and reconciliation readiness conflated")
	}
	close(elected)
	if health.leaderCheck(request) != nil {
		t.Fatal("elected serving replica not reconciliation-ready")
	}
	health.serving.Store(false)
	if health.leaderCheck(request) == nil {
		t.Fatal("stopped elected manager is ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := health.Start(ctx); err != nil || health.servingCheck(request) == nil {
		t.Fatal("shutdown did not withdraw readiness")
	}
}
