package controller

import (
	"context"
	"errors"
	"os"
	"strconv"

	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	runtimecontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const iamPeriodicPriority = -200

// Only the four IAM controllers with request-local reconciliation state opt in.
// Infrastructure, transactions, imports, Fleet and shared trust stay serial.
// Controller-runtime continues to serialize each individual workqueue key.
func iamControllerOptions() (runtimecontroller.Options, error) {
	workers := 1
	if value, present := os.LookupEnv("HANKO_IAM_MAX_CONCURRENT_RECONCILES"); present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 8 || strconv.Itoa(parsed) != value {
			return runtimecontroller.Options{}, errors.New("HANKO_IAM_MAX_CONCURRENT_RECONCILES must be an integer from 1 to 8")
		}
		workers = parsed
	}
	// Cold initial-list work and live changes share FIFO priority zero. Only
	// periodic successful reconciliation moves to the background. A transient
	// failure must not wait behind a thousand background resyncs to recover.
	priority := true
	return runtimecontroller.Options{MaxConcurrentReconciles: workers, UsePriorityQueue: &priority,
		RateLimiter: workqueue.DefaultTypedControllerRateLimiter[reconcile.Request](), NewQueue: newIAMQueue}, nil
}

// Delegate synchronization, coalescing, delayed work, backoff and metrics to the
// upstream queue. This immutable adapter only normalizes the upstream initial
// list/resync priority, which otherwise starves cold recovery behind live wakes.
type iamQueue struct {
	priorityqueue.PriorityQueue[reconcile.Request]
}

func newIAMQueue(name string, limiter workqueue.TypedRateLimiter[reconcile.Request]) workqueue.TypedRateLimitingInterface[reconcile.Request] {
	return iamQueue{priorityqueue.New(name, func(options *priorityqueue.Opts[reconcile.Request]) {
		options.RateLimiter = limiter
		options.Log = ctrl.Log.WithName("iam-queue").WithValues("controller", name)
	})}
}

func (q iamQueue) AddWithOpts(options priorityqueue.AddOpts, requests ...reconcile.Request) {
	if options.Priority != nil && *options.Priority == handler.LowPriority {
		priority := 0
		options.Priority = &priority
	}
	q.PriorityQueue.AddWithOpts(options, requests...)
}

func scheduleIAMReconciler(delegate reconcile.Reconciler) reconcile.Reconciler {
	return reconcile.Func(func(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
		result, err := delegate.Reconcile(ctx, request)
		if err != nil || result.RequeueAfter > 0 {
			priority := 0
			if err == nil && result.Priority != nil {
				priority = *result.Priority
			} else if err == nil && result.RequeueAfter >= requeueInterval {
				priority = iamPeriodicPriority
			}
			result.Priority = &priority
		}
		return result, err
	})
}
