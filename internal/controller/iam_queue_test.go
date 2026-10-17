package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func iamTestQueue(t *testing.T, limiter workqueue.TypedRateLimiter[reconcile.Request]) priorityqueue.PriorityQueue[reconcile.Request] {
	t.Helper()
	q := newIAMQueue(t.Name(), limiter).(priorityqueue.PriorityQueue[reconcile.Request])
	t.Cleanup(q.ShutDown)
	return q
}

func iamRequest(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "auth", Name: name}}
}

func iamTake(t *testing.T, q priorityqueue.PriorityQueue[reconcile.Request]) (reconcile.Request, int) {
	t.Helper()
	type item struct {
		request  reconcile.Request
		priority int
		shutdown bool
	}
	ready := make(chan item, 1)
	go func() { request, priority, shutdown := q.GetWithPriority(); ready <- item{request, priority, shutdown} }()
	select {
	case value := <-ready:
		if value.shutdown {
			t.Fatal("queue shut down before expected work")
		}
		return value.request, value.priority
	case <-time.After(5 * time.Second):
		t.Fatal("ready queue work did not arrive")
		return reconcile.Request{}, 0
	}
}

func TestIAMFreshChangesAndInitialListBypassThousandPeriodicResyncs(t *testing.T) {
	q := iamTestQueue(t, workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	background := iamPeriodicPriority
	for index := range 1000 {
		q.AddWithOpts(priorityqueue.AddOpts{Priority: &background}, iamRequest(fmt.Sprintf("periodic-%04d", index)))
	}
	// Exercise the actual upstream handler's initial-list priority, rather than
	// inventing a test enqueue path that misses the original starvation bug.
	h := &handler.EnqueueRequestForObject{}
	h.Create(context.Background(), event.CreateEvent{IsInInitialList: true,
		Object: &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "cold"}}}, q)
	q.Add(iamRequest("changed"))
	for _, want := range []string{"cold", "changed", "periodic-0000"} {
		request, priority := iamTake(t, q)
		if request.Name != want || want != "periodic-0000" && priority != 0 || want == "periodic-0000" && priority != background {
			t.Fatal("fresh work waited behind periodic work or initial-list work lost FIFO order", request, priority)
		}
		q.Done(request)
	}
}

func TestIAMColdBacklogIsNotStarvedByContinuousLiveDependencyWakes(t *testing.T) {
	q := iamTestQueue(t, workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	h := &handler.EnqueueRequestForObject{}
	for index := range 1000 {
		h.Create(context.Background(), event.CreateEvent{IsInInitialList: true,
			Object: &api.HankoApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: fmt.Sprintf("cold-%04d", index)}}}, q)
	}
	for index := range 1000 {
		q.Add(iamRequest(fmt.Sprintf("dependency-%04d", index)))
		request, priority := iamTake(t, q)
		if request.Name != fmt.Sprintf("cold-%04d", index) || priority != 0 {
			t.Fatal("live dependency wakes starved cold recovery", request, priority)
		}
		q.Done(request)
	}
	request, _ := iamTake(t, q)
	if request.Name != "dependency-0000" {
		t.Fatal("live dependency work was lost")
	}
	q.Done(request)
}

func TestIAMFreshEventPromotesDelayedPeriodicWorkWithoutDuplicates(t *testing.T) {
	q := iamTestQueue(t, workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	request := iamRequest("changed")
	background := iamPeriodicPriority
	q.AddWithOpts(priorityqueue.AddOpts{Priority: &background, After: time.Hour}, request)
	q.Add(request)
	q.Add(request)
	got, priority := iamTake(t, q)
	if got != request || priority != 0 {
		t.Fatal("spec event did not promote and accelerate delayed work")
	}
	// A wake during processing must stay locked until Done, then become one
	// additional attempt, regardless of how many duplicate events arrived.
	q.Add(request)
	q.Add(request)
	other := iamRequest("other")
	q.Add(other)
	got, _ = iamTake(t, q)
	if got != other {
		t.Fatal("same key was handed to two workers simultaneously")
	}
	q.Done(other)
	q.Done(request)
	got, _ = iamTake(t, q)
	if got != request {
		t.Fatal("coalesced in-flight wake was lost")
	}
	q.Done(request)
	if q.Len() != 0 {
		t.Fatal("event promotion duplicated queue work")
	}
}

func TestIAMRetryKeepsBackoffAndLeavesPeriodicPriority(t *testing.T) {
	delay := 30 * time.Millisecond
	limiter := workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](delay, time.Second)
	q := iamTestQueue(t, limiter)
	request := iamRequest("retry")
	background := iamPeriodicPriority
	q.AddWithOpts(priorityqueue.AddOpts{Priority: &background}, request)
	got, _ := iamTake(t, q)
	failure := errors.New("fixture refusal")
	r := scheduleIAMReconciler(reconcile.Func(func(context.Context, ctrl.Request) (ctrl.Result, error) {
		return ctrl.Result{RequeueAfter: requeueOnError}, failure
	}))
	result, err := r.Reconcile(context.Background(), got)
	if err != failure || result.Priority == nil || *result.Priority != 0 {
		t.Fatal("failed periodic work kept background priority")
	}
	started := time.Now()
	q.AddWithOpts(priorityqueue.AddOpts{RateLimited: true, Priority: result.Priority}, got)
	q.Done(got)
	got, priority := iamTake(t, q)
	if got != request || priority != 0 || time.Since(started) < delay || q.NumRequeues(got) != 1 {
		t.Fatal("retry priority bypassed backoff or lost retry accounting")
	}
	q.Forget(got)
	q.Done(got)
}

func TestIAMSchedulerPreservesErrorsDelaysAndShortCheckpoints(t *testing.T) {
	failure := errors.New("fixture failure")
	for _, test := range []struct {
		name     string
		result   ctrl.Result
		err      error
		priority int
	}{
		{name: "no follow-up"},
		{name: "checkpoint", result: ctrl.Result{RequeueAfter: requeueImmediately}},
		{name: "pending reference", result: ctrl.Result{RequeueAfter: requeueOnError}},
		{name: "periodic", result: ctrl.Result{RequeueAfter: requeueInterval}, priority: iamPeriodicPriority},
		{name: "jittered periodic", result: ctrl.Result{RequeueAfter: requeueInterval + requeueJitter}, priority: iamPeriodicPriority},
		{name: "error from periodic", result: ctrl.Result{RequeueAfter: requeueInterval}, err: failure},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := scheduleIAMReconciler(reconcile.Func(func(context.Context, ctrl.Request) (ctrl.Result, error) { return test.result, test.err }))
			got, err := r.Reconcile(context.Background(), ctrl.Request{})
			unchanged := got
			unchanged.Priority = test.result.Priority
			if unchanged != test.result || err != test.err {
				t.Fatal("scheduler changed retry semantics")
			}
			if got.RequeueAfter == 0 && err == nil {
				if got != test.result {
					t.Fatal("scheduler created work from an empty result")
				}
			} else if got.Priority == nil || *got.Priority != test.priority {
				t.Fatal("wrong scheduling class")
			}
		})
	}
}
