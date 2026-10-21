package keycloak

import "sync"

// Pool is a thread-safe registry of Keycloak clients indexed by tenant key
// (namespace/name). Named tenants must be registered explicitly, including those
// using the shared client in realm isolation mode.
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

// Get returns only the registered client for a named tenant. The empty key is
// reserved for unlabelled resources using the installation's default client.
// Missing registrations fail closed; they never fall back to another provider.
func (p *Pool) Get(tenantKey string) *Client {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if tenantKey == "" {
		return p.defaultC
	}
	return p.clients[tenantKey]
}

// Register stores a dedicated Keycloak client under tenantKey.
func (p *Pool) Register(tenantKey string, c *Client) {
	if p == nil || tenantKey == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[tenantKey] = c
}

// RegisterShared explicitly authorizes a realm-isolated tenant to use the
// installation's default client. It does not authorize unknown tenants.
func (p *Pool) RegisterShared(tenantKey string) {
	if p == nil || tenantKey == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[tenantKey] = p.defaultC
}

// Remove unregisters the client for tenantKey. Subsequent named lookups return nil.
func (p *Pool) Remove(tenantKey string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, tenantKey)
}
