package keycloak_test

import (
	"context"
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

	got := pool.Get("")
	if got != def {
		t.Error("Get with empty key must return the default client")
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

func TestPool_GetUnknownKeyFailsClosed(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	c := newTestClient("http://tenant-specific")
	pool.Register("ns/name", c)

	got := pool.Get("ns/other")
	if got != nil {
		t.Error("Get with unknown key must not return the default client")
	}
}

func TestPool_RemoveRevokesRegistration(t *testing.T) {
	def := newTestClient("http://default")
	pool := keycloak.NewPool(def)

	c := newTestClient("http://tenant-specific")
	pool.Register("ns/name", c)
	pool.Remove("ns/name")

	got := pool.Get("ns/name")
	if got != nil {
		t.Error("Get after Remove must not return the default client")
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
			if pool.Get(key) != nil {
				t.Error("removed tenant retained a client")
			}
		}(i)
	}

	wg.Wait()
}

func TestPool_RealmIsolationRequiresExplicitRegistration(t *testing.T) {
	def := newTestClient("https://shared.example")
	pool := keycloak.NewPool(def)
	if pool.Get("ns/realm-tenant") != nil {
		t.Fatal("unregistered realm tenant reached shared client")
	}
	pool.RegisterShared("ns/realm-tenant")
	if pool.Get("ns/realm-tenant") != def || pool.Get("other/realm-tenant") != nil {
		t.Fatal("shared registration crossed tenant or namespace boundary")
	}
	pool.Remove("ns/realm-tenant")
	if pool.Get("ns/realm-tenant") != nil || pool.Get("") != def {
		t.Fatal("revoking a tenant changed the installation default")
	}
}

func TestMissingPoolAndClientFailClosed(t *testing.T) {
	var pool *keycloak.Pool
	pool.Remove("ns/tenant")
	pool.RegisterShared("ns/tenant")
	if pool.Get("ns/tenant") != nil {
		t.Fatal("nil registry returned a client")
	}
	var kc *keycloak.Client
	if kc.BaseURL() != "" {
		t.Fatal("nil client published an endpoint")
	}
	if _, err := kc.GetRealm(context.Background(), "test"); err == nil {
		t.Fatal("missing client accepted a provider read")
	}
}
