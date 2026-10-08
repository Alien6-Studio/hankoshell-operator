package keycloak_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func newTestClient(url string) *keycloak.Client {
	return keycloak.New(url, "id", "secret")
}

func TestPool_GetReturnsDefault(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	got := pool.Get("no-such-key")
	if got != def {
		t.Error("Get on empty pool must return the default client")
	}
}

func TestPool_RegisterAndGet(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	c := newTestClient("http://tenant-specific")
	pool.Register("ns/name", c)

	got := pool.Get("ns/name")
	if got != c {
		t.Error("Get after Register must return the registered client")
	}
}

func TestPool_GetUnknownKeyFallsBack(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	c := newTestClient("http://tenant-specific")
	pool.Register("ns/name", c)

	got := pool.Get("ns/other")
	if got != def {
		t.Error("Get with unknown key must return the default client")
	}
}

func TestPool_RemoveRestoresDefault(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	c := newTestClient("http://tenant-specific")
	pool.Register("ns/name", c)
	pool.Remove("ns/name")

	got := pool.Get("ns/name")
	if got != def {
		t.Error("Get after Remove must return the default client again")
	}
}

func TestPool_Concurrent(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("ns/tenant-%d", i)
			c := newTestClient(fmt.Sprintf("http://tenant-%d", i))

			pool.Register(key, c)
			got := pool.Get(key)
			if got != c {
				t.Errorf("goroutine %d: Get returned wrong client", i)
			}
			pool.Remove(key)
			// After removal, result is either default or still the client
			// depending on race timing — we just ensure no panic/data race.
			_ = pool.Get(key)
		}(i)
	}

	wg.Wait()
}
