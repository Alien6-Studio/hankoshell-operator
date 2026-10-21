package controller

import (
	"context"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type observedReconciler struct {
	kind     string
	delegate reconcile.Reconciler
}

func observeReconciler(kind string, delegate reconcile.Reconciler) reconcile.Reconciler {
	return observedReconciler{kind: kind, delegate: delegate}
}

func (r observedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	started := time.Now()
	defer func() {
		outcome := "success"
		if failure := recover(); failure != nil {
			observability.Default.Reconcile(r.kind, "panic", time.Since(started))
			panic(failure)
		}
		if err != nil {
			outcome = "error"
		} else if result.RequeueAfter > 0 {
			outcome = "requeue"
		}
		observability.Default.Reconcile(r.kind, outcome, time.Since(started))
	}()
	return r.delegate.Reconcile(ctx, req)
}
