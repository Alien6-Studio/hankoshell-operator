package keycloak

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Guarded views share the credential cache and budget. Constructing a new view
// must not bypass cooldowns or multiply token refreshes for the same connection.
type clientSession struct {
	mu                    sync.Mutex
	token                 string
	tokenExpiry           time.Time
	tokenFlight           *tokenRefresh
	tokenEpoch            uint64
	tokenRetryAt          time.Time
	tokenError            error
	requests              requestBudget
	delegationTransaction chan struct{}
}

type tokenRefresh struct {
	done  chan struct{}
	token string
	err   error
}

var errTokenInvalidated = errors.New("keycloak token changed during refresh")
var errRequestTokenStale = errors.New("keycloak request token became stale before I/O")

// Helpers prepare the request before queueing and mutation guards. A guard can
// renew the shared token through its own authority reads; bind the current
// cached credential only after that work. Never authenticate while holding an
// outer request slot or automatically retry a potentially accepted write.
func (c *Client) rebindRequestToken(req *http.Request) error {
	if !strings.HasPrefix(req.Header.Get(authorizationHeader), bearerPrefix) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || !time.Now().Before(c.tokenExpiry) {
		return errRequestTokenStale
	}
	req.Header.Set(authorizationHeader, bearerPrefix+c.token)
	return nil
}

// bearerToken coalesces cache misses, including failed refreshes. A canceled
// waiter can leave without acquiring the mutex or canceling another request.
func (c *Client) bearerToken(ctx context.Context) (string, error) {
	return c.refreshToken(ctx, false)
}

// fetchToken forces a newly issued observation, even when another refresh is
// active. Fleet permission decisions must never reuse an earlier observation.
func (c *Client) fetchToken(ctx context.Context) (string, error) {
	return c.refreshToken(ctx, true)
}

func (c *Client) refreshToken(ctx context.Context, fresh bool) (string, error) {
	if c == nil {
		return "", errors.New("keycloak client is unavailable")
	}
	if c.endpointError != nil {
		return "", c.endpointError
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		c.mu.Lock()
		if !fresh && c.token != "" && time.Now().Before(c.tokenExpiry) {
			token := c.token
			c.mu.Unlock()
			return token, nil
		}
		if time.Now().Before(c.tokenRetryAt) {
			err := c.tokenError
			c.mu.Unlock()
			return "", err
		}
		flight := c.tokenFlight
		if flight == nil {
			flight = &tokenRefresh{done: make(chan struct{})}
			c.tokenFlight = flight
			epoch := c.tokenEpoch
			c.mu.Unlock()
			return c.completeRefresh(ctx, flight, epoch)
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-flight.done:
			if !fresh {
				return flight.token, flight.err
			}
		}
	}
}

func (c *Client) completeRefresh(ctx context.Context, flight *tokenRefresh, epoch uint64) (string, error) {
	token, expiry, err := c.requestToken(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokenEpoch != epoch {
		token, err = "", errTokenInvalidated
	} else if err == nil {
		c.token, c.tokenExpiry = token, expiry
		c.tokenError, c.tokenRetryAt = nil, time.Time{}
	} else if ctx.Err() == nil {
		// Invalid credentials and unavailable endpoints must not trigger one
		// new credential request per queued object. Cancellation is caller-local.
		c.tokenError, c.tokenRetryAt = err, time.Now().Add(time.Second)
	}
	flight.token, flight.err = token, err
	c.tokenFlight = nil
	close(flight.done)
	return token, err
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.tokenExpiry = "", time.Time{}
	c.tokenError, c.tokenRetryAt = nil, time.Time{}
	c.tokenEpoch++
}
