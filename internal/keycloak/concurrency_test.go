package keycloak

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func concurrencyClient(handler func(*http.Request) (*http.Response, error)) *Client {
	c := New("https://keycloak.invalid", "operator", "credential-sentinel")
	c.httpClient.Transport = responseRoundTripper(handler)
	return c
}

func concurrencyResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func tokenWave(t *testing.T, c *Client, count int, wantError bool) {
	t.Helper()
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			token, err := c.bearerToken(t.Context())
			if (err != nil) != wantError || !wantError && token == "" {
				t.Error("unexpected refresh outcome")
			}
		})
	}
	wg.Wait()
}

func TestTokenRefreshCoalescesThousandCallerWavesAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			time.Sleep(time.Millisecond)
			return concurrencyResponse(200, `{"access_token":"test-token","expires_in":2}`), nil
		})
		for wave := 1; wave <= 3; wave++ {
			tokenWave(t, c, 1000, false)
			if calls.Load() != int32(wave) {
				t.Fatalf("wave %d made %d credential requests", wave, calls.Load())
			}
			time.Sleep(1100 * time.Millisecond)
		}
	})
}

func TestTokenRefreshFailureDoesNotCauseCredentialStorm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return concurrencyResponse(401, "credential-sentinel"), nil
		})
		tokenWave(t, c, 1000, true)
		tokenWave(t, c, 1000, true)
		if calls.Load() != 1 {
			t.Fatal("failed refresh was issued per queued caller")
		}
		time.Sleep(time.Second)
		tokenWave(t, c, 1000, true)
		if calls.Load() != 2 {
			t.Fatal("refresh did not become eligible after cooldown")
		}
	})
}

func TestTokenWaiterCancellationDoesNotCancelRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-release
			return concurrencyResponse(200, `{"access_token":"test-token","expires_in":60}`), nil
		})
		done := make(chan error, 1)
		go func() { _, err := c.bearerToken(t.Context()); done <- err }()
		<-entered
		ctx, cancel := context.WithCancel(t.Context())
		waiting := make(chan error, 1)
		go func() { _, err := c.bearerToken(ctx); waiting <- err }()
		synctest.Wait()
		cancel()
		if !errors.Is(<-waiting, context.Canceled) {
			t.Fatal("waiting caller could not cancel")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal("waiter canceled the shared refresh")
		}
	})
}

func TestTokenInvalidationFencesInFlightRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-release
			return concurrencyResponse(200, `{"access_token":"stale-token","expires_in":60}`), nil
		})
		done := make(chan error, 1)
		go func() { _, err := c.bearerToken(t.Context()); done <- err }()
		<-entered
		c.invalidateToken()
		close(release)
		if !errors.Is(<-done, errTokenInvalidated) || c.token != "" {
			t.Fatal("invalidated refresh repopulated cache")
		}
	})
}

func TestFreshPermissionTokenNeverJoinsPriorObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			time.Sleep(time.Millisecond)
			return concurrencyResponse(200, `{"access_token":"test-token","expires_in":60}`), nil
		})
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				if _, err := c.fetchToken(t.Context()); err != nil {
					t.Error("fresh observation failed")
				}
			})
		}
		wg.Wait()
		if calls.Load() != 20 {
			t.Fatal("fresh permission decision reused a prior token")
		}
	})
}

func TestRequestBudgetBoundsNetworkAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{}, maxKeycloakInFlight)
		release := make(chan struct{})
		var calls atomic.Int32
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			entered <- struct{}{}
			<-release
			return concurrencyResponse(200, `[]`), nil
		})
		c.token, c.tokenExpiry = "test-token", time.Now().Add(time.Hour)
		var wg sync.WaitGroup
		for range maxKeycloakInFlight {
			wg.Go(func() {
				if _, err := c.ListRealms(t.Context()); err != nil {
					t.Error(err)
				}
			})
		}
		for range maxKeycloakInFlight {
			<-entered
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { _, err := c.ListRealms(ctx); done <- err }()
		synctest.Wait()
		cancel()
		if !errors.Is(<-done, context.Canceled) || calls.Load() != maxKeycloakInFlight {
			t.Fatal("queued cancellation reached the provider")
		}
		close(release)
		wg.Wait()
	})
}

func TestThrottleCooldownNoReplayAndAutomaticEligibility(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				c := concurrencyClient(func(*http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						response := concurrencyResponse(status, "credential-sentinel")
						response.Header.Set("Retry-After", "2")
						return response, nil
					}
					return concurrencyResponse(201, ""), nil
				})
				c.token, c.tokenExpiry = "test-token", time.Now().Add(time.Hour)
				for range 1000 {
					err := c.CreateRealm(t.Context(), RealmSpec{ID: "load-fixture"})
					var typed *StatusError
					if !errors.As(err, &typed) || typed.Code != status || strings.Contains(err.Error(), "sentinel") {
						t.Fatal("throttle lost its bounded numeric status")
					}
				}
				if calls.Load() != 1 {
					t.Fatal("throttled write was replayed or new work bypassed cooldown")
				}
				time.Sleep(2 * time.Second)
				if err := c.CreateRealm(t.Context(), RealmSpec{ID: "load-fixture"}); err != nil || calls.Load() != 2 {
					t.Fatal("new reconciliation did not recover after cooldown")
				}
			})
		})
	}
}

func TestRetryAfterIsBoundedAndDoesNotTrustNativeText(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", time.Second}, {"0", time.Second}, {"-1", time.Second}, {"2", 2 * time.Second},
		{"9999999999999999999", 5 * time.Minute}, {"credential-sentinel", time.Second},
		{now.Add(10 * time.Second).Format(http.TimeFormat), 10 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), time.Second},
		{now.Add(time.Hour).Format(http.TimeFormat), 5 * time.Minute},
	} {
		if actual := retryDelay(tc.value, now); actual != tc.want {
			t.Errorf("Retry-After yielded %s, want %s", actual, tc.want)
		}
	}
}

func TestGuardedViewsShareRefreshAndThrottling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := concurrencyClient(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			if request.Method == http.MethodPost {
				return concurrencyResponse(200, `{"access_token":"test-token","expires_in":60}`), nil
			}
			response := concurrencyResponse(429, "private-sentinel")
			response.Header.Set("Retry-After", "30")
			return response, nil
		})
		guarded := c.WithMutationGuard(nil).WithMutationGuard(nil)
		tokenWave(t, c, 1000, false)
		tokenWave(t, guarded, 1000, false)
		_, _ = c.ListRealms(t.Context())
		_, err := guarded.ListRealms(t.Context())
		var status *StatusError
		if !errors.As(err, &status) || status.Code != 429 || calls.Load() != 2 {
			t.Fatal("guarded view bypassed shared refresh or cooldown")
		}
		guarded.invalidateToken()
		if c.token != "" {
			t.Fatal("guarded invalidation did not reach shared credential state")
		}
	})
}

func TestRequestRateIsBoundedAcrossGuardedViews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := concurrencyClient(func(*http.Request) (*http.Response, error) {
			return concurrencyResponse(200, `[]`), nil
		})
		c.token, c.tokenExpiry = "test-token", time.Now().Add(time.Hour)
		guarded := c.WithMutationGuard(nil)
		started := time.Now()
		var wg sync.WaitGroup
		for index := range 100 {
			connection := c
			if index%2 == 1 {
				connection = guarded
			}
			wg.Go(func() {
				if _, err := connection.ListRealms(t.Context()); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if time.Since(started) < time.Second {
			t.Fatal("100 requests exceeded the shared 50/s, burst 50 budget")
		}
	})
}

func TestQueuedMutationRechecksAuthorityAfterWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{}, maxKeycloakInFlight)
		release := make(chan struct{})
		var writes atomic.Int32
		c := concurrencyClient(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet {
				writes.Add(1)
				return concurrencyResponse(201, ""), nil
			}
			entered <- struct{}{}
			<-release
			return concurrencyResponse(200, `[]`), nil
		})
		c.token, c.tokenExpiry = "test-token", time.Now().Add(time.Hour)
		var denied atomic.Bool
		revoked := errors.New("authority revoked")
		guarded := c.WithMutationGuard(func(context.Context) error {
			if denied.Load() {
				return revoked
			}
			return nil
		})
		var wg sync.WaitGroup
		for range maxKeycloakInFlight {
			wg.Go(func() { _, _ = c.ListRealms(t.Context()) })
		}
		for range maxKeycloakInFlight {
			<-entered
		}
		done := make(chan error, 1)
		go func() { done <- guarded.CreateRealm(t.Context(), RealmSpec{ID: "queued"}) }()
		synctest.Wait()
		denied.Store(true)
		close(release)
		if !errors.Is(<-done, revoked) || writes.Load() != 0 {
			t.Fatal("queued write used authority observed before waiting")
		}
		wg.Wait()
	})
}
