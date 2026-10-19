package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestObservedReconcilerPreservesResultErrorAndPanic(t *testing.T) {
	sentinel := errors.New("secret-sentinel")
	for _, test := range []struct {
		result ctrl.Result
		err    error
	}{{}, {result: ctrl.Result{RequeueAfter: time.Second}}, {err: sentinel}} {
		inner := reconcile.Func(func(context.Context, ctrl.Request) (ctrl.Result, error) { return test.result, test.err })
		result, err := observeReconciler("HankoApplication", inner).Reconcile(context.Background(), ctrl.Request{})
		if result != test.result || err != test.err {
			t.Fatal("instrumentation changed reconciliation")
		}
	}
	defer func() {
		if recover() != sentinel {
			t.Fatal("instrumentation swallowed or changed panic")
		}
	}()
	inner := reconcile.Func(func(context.Context, ctrl.Request) (ctrl.Result, error) { panic(sentinel) })
	_, _ = observeReconciler("HankoApplication", inner).Reconcile(context.Background(), ctrl.Request{})
}
