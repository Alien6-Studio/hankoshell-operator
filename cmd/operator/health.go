package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

type runtimeHealth struct {
	serving atomic.Bool
	elected <-chan struct{}
}

func (*runtimeHealth) NeedLeaderElection() bool { return false }
func (h *runtimeHealth) Start(ctx context.Context) error {
	h.serving.Store(true)
	defer h.serving.Store(false)
	defer observability.Default.Leader(false)
	select {
	case <-ctx.Done():
		return nil
	case <-h.elected:
		observability.Default.Leader(true)
	}
	<-ctx.Done()
	return nil
}
func (h *runtimeHealth) servingCheck(_ *http.Request) error {
	if !h.serving.Load() {
		return errors.New("manager cache is not serving")
	}
	return nil
}
func (h *runtimeHealth) leaderCheck(req *http.Request) error {
	if err := h.servingCheck(req); err != nil {
		return err
	}
	select {
	case <-h.elected:
		return nil
	default:
		return errors.New("replica has not acquired the reconciliation lease")
	}
}
func providerCheck(kc *keycloak.Client) healthz.Checker {
	return func(req *http.Request) error {
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()
		if _, err := kc.ServerVersion(ctx); err != nil {
			return errors.New("provider readiness unavailable")
		}
		return nil
	}
}
func setupHealthChecks(mgr ctrl.Manager, kc *keycloak.Client, namespace string, metricsEnabled bool) {
	h := &runtimeHealth{elected: mgr.Elected()}
	fatalIfError(mgr.Add(h), "unable to register runtime readiness")
	if metricsEnabled {
		fatalIfError(mgr.Add(controller.NewOperationalInventory(mgr.GetAPIReader(), namespace)), "unable to register bounded operational inventory")
	}
	fatalIfError(mgr.AddHealthzCheck("healthz", healthz.Ping), "unable to set up health check")
	fatalIfError(mgr.AddReadyzCheck("serving", h.servingCheck), "unable to set up serving check")
	fatalIfError(mgr.AddReadyzCheck("leader", h.leaderCheck), "unable to set up leader check")
	if !spokeMode() {
		fatalIfError(mgr.AddReadyzCheck("keycloak", providerCheck(kc)), "unable to set up provider check")
	}
}
