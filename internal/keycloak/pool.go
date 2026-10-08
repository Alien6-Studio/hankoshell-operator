package keycloak

import "sync"

// Pool is a thread-safe registry of Keycloak clients indexed by tenant key
// (namespace/name). A default client is returned for tenants that do not have
// a dedicated Keycloak instance (realm isolation mode).
type Pool struct {
	mu       sync.RWMutex
	clients  map[string]*Client
	defaultC *Client
}

// NewPool creates a Pool with the given default client.
func NewPool(defaultClient *Client) *Pool {
	return &Pool{
		clients:  make(map[string]*Client),
		defaultC: defaultClient,
	}
}

// Get returns the dedicated client for tenantKey if one is registered,
// otherwise returns the pool's default client.
func (p *Pool) Get(tenantKey string) *Client {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c, ok := p.clients[tenantKey]; ok {
		return c
	}
	return p.defaultC
}

// Register stores a dedicated Keycloak client under tenantKey.
func (p *Pool) Register(tenantKey string, c *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[tenantKey] = c
}

// Remove unregisters the client for tenantKey. Subsequent Get calls for that
// key will fall back to the default client.
func (p *Pool) Remove(tenantKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, tenantKey)
}
