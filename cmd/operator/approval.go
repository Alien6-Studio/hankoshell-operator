package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	approvalPendingMessage = "installation approval pending: the Subscription has not supplied HANKO_INSTALLATION_CONTRACT_SHA256"
	approvalPendingAction  = "supply the approved Subscription configuration from docs/operatorhub.md; OLM then rolls out a pod that verifies the installation protections and starts"
	approvalReminderPeriod = 5 * time.Minute
)

// awaitsInstallationApproval reports whether an OLM installation requires the
// administrator-approved contract while its Subscription has not yet supplied
// the independently approved SHA-256. The public bundle ships an empty digest so
// the CSV installs before the approval; the operator then serves probes only.
// Every other incomplete verification configuration still fails startup.
func (config runtimeConfig) awaitsInstallationApproval() bool {
	return config.installationRequired && !config.installationCheckOnly &&
		config.installationDigest == "" && config.installationContract == "" && config.installationConfigMap != ""
}

// approvalPendingHandler answers the liveness and readiness probes while the
// operator waits for the approved Subscription configuration. The process holds
// no Kubernetes, provider or Hub client and runs no controller or election in
// this state. Readiness lets OLM complete the CSV so a later Subscription
// configuration change reaches the Deployment and replaces this pod.
func approvalPendingHandler() http.Handler {
	mux := http.NewServeMux()
	respond := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(approvalPendingMessage + "\n"))
	}
	mux.HandleFunc("GET /healthz", respond)
	mux.HandleFunc("GET /readyz", respond)
	return mux
}

// awaitInstallationApproval serves the probes and logs the pending approval
// until the context ends. It returns nil on an orderly shutdown.
func awaitInstallationApproval(ctx context.Context, addr string) error {
	server := &http.Server{Addr: addr, Handler: approvalPendingHandler(), ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}()
	logger := ctrl.Log.WithName("installation")
	logger.Info(approvalPendingMessage, "action", approvalPendingAction)
	reminder := time.NewTicker(approvalReminderPeriod)
	defer reminder.Stop()
	for {
		select {
		case err := <-failed:
			return fmt.Errorf("approval-pending probe server: %w", err)
		case <-reminder.C:
			logger.Info(approvalPendingMessage, "action", approvalPendingAction)
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdown); err != nil {
				return fmt.Errorf("approval-pending probe server shutdown: %w", err)
			}
			return nil
		}
	}
}
