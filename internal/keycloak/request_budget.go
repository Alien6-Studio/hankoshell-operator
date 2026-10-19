package keycloak

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const maxKeycloakInFlight = 8
const keycloakRequestsPerSecond = 50

var errRequestBudget = errors.New("keycloak request budget exceeds caller deadline")

// A budget belongs to one credential client, including token requests. It is
// deliberately not a cross-tenant or cross-replica throughput qualification.
type requestBudget struct {
	slots  chan struct{}
	rate   *rate.Limiter
	mu     sync.Mutex
	until  time.Time
	status int
	guards chan struct{}
}

// An admitted mutation may perform authority reads, including token renewal.
// Keep one of the eight HTTP slots available to that work even when every
// concurrent caller is a guarded writer. Readers still share the 50/s budget.
func (b *requestBudget) acquireGuard(ctx context.Context) (func(), error) {
	b.mu.Lock()
	if b.guards == nil {
		b.guards = make(chan struct{}, maxKeycloakInFlight-1)
	}
	queue := b.guards
	b.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case queue <- struct{}{}:
		return func() { <-queue }, nil
	}
}

func (b *requestBudget) acquire(ctx context.Context) (func(), error) {
	b.mu.Lock()
	if b.slots == nil {
		b.slots = make(chan struct{}, maxKeycloakInFlight)
		b.rate = rate.NewLimiter(keycloakRequestsPerSecond, keycloakRequestsPerSecond)
	}
	b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b.slots <- struct{}{}:
	}
	release := func() { <-b.slots }
	if err := b.refusal(ctx); err != nil {
		release()
		return nil, err
	}
	if err := b.rate.Wait(ctx); err != nil {
		release()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errRequestBudget
	}
	if err := b.refusal(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (b *requestBudget) refusal(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Now().Before(b.until) {
		return &StatusError{Code: b.status}
	}
	return nil
}

func (b *requestBudget) observe(response *http.Response) {
	if response.StatusCode != http.StatusTooManyRequests && response.StatusCode != http.StatusServiceUnavailable {
		return
	}
	// A 503 without a provider hint retains the controller's normal backoff.
	// This includes lost acknowledgements whose recovery must re-observe state.
	if response.StatusCode == http.StatusServiceUnavailable && response.Header.Get("Retry-After") == "" {
		return
	}
	now := time.Now()
	until := now.Add(retryDelay(response.Header.Get("Retry-After"), now))
	b.mu.Lock()
	defer b.mu.Unlock()
	if until.After(b.until) {
		b.until, b.status = until, response.StatusCode
	}
}

func retryDelay(value string, now time.Time) time.Duration {
	const maximum = 5 * time.Minute
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err == nil {
		if seconds >= uint64(maximum/time.Second) {
			return maximum
		}
		return max(time.Second, time.Duration(seconds)*time.Second)
	}
	if date, err := http.ParseTime(value); err == nil {
		return min(maximum, max(time.Second, date.Sub(now)))
	}
	return time.Second
}
