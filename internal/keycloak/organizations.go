package keycloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

var ErrOrganizationOwnershipConflict = errors.New("keycloak organization ownership conflict")

const (
	organizationsPath        = "/organizations"
	organizationsSegment     = "/organizations/"
	identityProvidersSegment = "/identity-providers"
	// organizationsPageSize bounds each list request while the client walks the
	// whole collection; Keycloak caps unbounded listings server-side.
	organizationsPageSize = 100
)

// OrganizationDomain is one internet domain owned by an organization. A domain
// cannot be shared by two organizations within the same realm.
type OrganizationDomain struct {
	// Name is the domain name, e.g. "alien6.com".
	Name string `json:"name"`
	// Verified reports whether the domain ownership has been verified.
	Verified bool `json:"verified,omitempty"`
}

// Organization is the subset of the Keycloak organization representation the
// operator manages. It models the isolation half of a Hanko organization: the
// tenant root carrying the stable alias, its domains and (later) the linked
// identity provider. Structure below the root stays in nested groups.
type Organization struct {
	// ID is the Keycloak-assigned organization UUID.
	ID string `json:"id,omitempty"`
	// Name is the organization's display name.
	Name string `json:"name"`
	// Alias is the stable, URL-safe identifier, unique within the realm. It is
	// the key of the token "organization" claim and must never change.
	Alias string `json:"alias,omitempty"`
	// Enabled reports whether the organization is active.
	Enabled bool `json:"enabled"`
	// Domains are the internet domains owned by this organization.
	Domains []OrganizationDomain `json:"domains,omitempty"`
	// Attributes carry the Kubernetes ownership marker used before adoption,
	// mutation, identity-provider changes or deletion in the authority realm.
	Attributes map[string][]string `json:"attributes,omitempty"`
}

// OrganizationSpec is the desired state of a Keycloak organization managed by
// the operator.
type OrganizationSpec struct {
	// Alias is the stable identifier; adoption of an existing organization
	// matches on it, never on the display name.
	Alias string
	// Name is the display name, free to evolve without breaking the alias.
	Name string
	// Domains lists the domain names owned by the organization.
	Domains []string
	// Attributes are merged into the provider representation on create/update.
	Attributes map[string][]string
	// OwnershipAttributes must match an existing organization when strict
	// ownership is enabled.
	OwnershipAttributes map[string][]string
	// LegacyOwnedID is the immutable UUID recorded by older operator versions.
	LegacyOwnedID string
	// RequireOwnership forbids alias-only adoption and concurrent 409 adoption.
	RequireOwnership bool
	// PreserveAdopted retains current native fields and domain verification.
	PreserveAdopted bool
}

// GetOrganizationByAlias returns the organization with the exact alias, or nil
// when absent. It never searches by mutable name or domain.
func (c *Client) GetOrganizationByAlias(ctx context.Context, realm, alias string) (*Organization, error) {
	existing, err := c.findOrganizationByAlias(ctx, realm, alias)
	if err != nil || existing == nil {
		return existing, err
	}
	return c.GetOrganization(ctx, realm, existing.ID)
}

// GetOrganization returns one organization by its immutable Keycloak UUID.
func (c *Client) GetOrganization(ctx context.Context, realm, organizationID string) (*Organization, error) {
	var organization Organization
	path := adminRealmsPath + realm + organizationsSegment + url.PathEscape(organizationID)
	if err := c.get(ctx, path, &organization); err != nil {
		return nil, fmt.Errorf("get organization %q in realm %q: %w", organizationID, realm, err)
	}
	return &organization, nil
}

// OrganizationMatchesOwnership applies the same fail-closed marker semantics
// as GroupMatchesOwnership: partial/conflicting markers cannot fall back to a
// legacy status ID.
func OrganizationMatchesOwnership(organization *Organization, expected map[string][]string, legacyOwnedID string) bool {
	if organization == nil {
		return false
	}
	markerPresent := false
	for key := range expected {
		if _, ok := organization.Attributes[key]; ok {
			markerPresent = true
			break
		}
	}
	if markerPresent {
		for key, values := range expected {
			actual, ok := organization.Attributes[key]
			if !ok {
				return false
			}
			for _, value := range values {
				if !slices.Contains(actual, value) {
					return false
				}
			}
		}
		return len(expected) != 0
	}
	return legacyOwnedID != "" && organization.ID == legacyOwnedID
}

// EnsureOrganizationsEnabled turns on the realm's organizations feature when
// it is off. Keycloak rejects every organization call on a realm that has not
// opted in, so the operator enables it before reconciling a tenant root.
func (c *Client) EnsureOrganizationsEnabled(ctx context.Context, realm string) error {
	var rep map[string]any
	if err := c.get(ctx, adminRealmsPath+realm, &rep); err != nil {
		return fmt.Errorf("read realm %q: %w", realm, err)
	}
	if enabled, ok := rep["organizationsEnabled"].(bool); ok && enabled {
		return nil
	}
	rep["organizationsEnabled"] = true
	resp, err := c.doJSON(ctx, http.MethodPut, adminRealmsPath+realm, rep)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enable organizations on realm %q: keycloak %d: %s", realm, resp.StatusCode, body)
	}
	return nil
}

// EnsureOrganization creates or adopts the organization with the spec's alias
// and returns its Keycloak UUID. Adoption matches on the alias only: Keycloak's
// search parameter matches names and domains, not aliases, so the client walks
// the collection. Display name and domains drift back to the declared state; a
// concurrent create surfacing as 409 is resolved by re-reading.
func (c *Client) EnsureOrganization(ctx context.Context, realm string, spec OrganizationSpec) (string, error) { //nolint:cyclop,gocognit // Create-or-update reconcile with 409 recovery; complexity tracked by SonarQube S3776.
	existing, err := c.findOrganizationByAlias(ctx, realm, spec.Alias)
	if err != nil {
		return "", err
	}
	if existing != nil && spec.RequireOwnership {
		existing, err = c.GetOrganization(ctx, realm, existing.ID)
		if err != nil {
			return "", err
		}
	}
	if existing != nil && spec.RequireOwnership && !OrganizationMatchesOwnership(existing, spec.OwnershipAttributes, spec.LegacyOwnedID) {
		return "", fmt.Errorf("%w: existing organization %q in realm %q is not owned by this HankoOrganization", ErrOrganizationOwnershipConflict, spec.Alias, realm)
	}
	if existing != nil {
		if _, adopted := existing.Attributes["hanko.sh/adoption-receipt"]; adopted {
			if !spec.PreserveAdopted {
				return "", ErrAdoptionPrecondition
			}
			return existing.ID, c.reconcileAdoptedNativeOrganization(ctx, realm, existing.ID, spec)
		}
	}
	if existing == nil {
		id, created, err := c.createOrganization(ctx, realm, spec)
		if err != nil || created {
			return id, err
		}
		if spec.RequireOwnership {
			// A conflict (or a successful create without a usable Location) is
			// deliberately retried through the read/preflight path. Never adopt an
			// alias that appeared concurrently in the authority realm.
			return "", fmt.Errorf("%w: organization %q appeared concurrently in realm %q", ErrOrganizationOwnershipConflict, spec.Alias, realm)
		}
		// Legacy non-protected realms retain alias adoption.
		if existing, err = c.findOrganizationByAlias(ctx, realm, spec.Alias); err != nil {
			return "", err
		}
		if existing == nil {
			return "", fmt.Errorf("organization %q in realm %q conflicts but cannot be resolved", spec.Alias, realm)
		}
	}
	if organizationDrifted(*existing, spec) {
		desired := desiredOrganization(spec)
		desired.ID = existing.ID
		desired.Attributes = make(map[string][]string, len(existing.Attributes)+len(spec.Attributes))
		for key, values := range existing.Attributes {
			desired.Attributes[key] = append([]string(nil), values...)
		}
		for key, values := range spec.Attributes {
			desired.Attributes[key] = append([]string(nil), values...)
		}
		resp, err := c.doJSON(ctx, http.MethodPut, adminRealmsPath+realm+organizationsSegment+existing.ID, desired)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("update organization %q in realm %q: keycloak %d: %s", spec.Alias, realm, resp.StatusCode, body)
		}
	}
	return existing.ID, nil
}

// DeleteOrganization removes an organization by UUID. A missing organization is
// treated as success so deletion stays idempotent.
func (c *Client) DeleteOrganization(ctx context.Context, realm, orgID string) error {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+adminRealmsPath+realm+organizationsSegment+orgID, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete organization %q in realm %q: keycloak %d: %s", orgID, realm, resp.StatusCode, body)
}

// EnsureOrganizationIdentityProvider links the realm broker with the given
// alias to the organization and unlinks any other linked broker, keeping the
// declared one the organization's only IdP. An empty alias leaves existing
// links untouched: unmanaged, never silently removed, so enabling the operator
// on a realm whose broker is the live login path cannot break sign-in.
func (c *Client) EnsureOrganizationIdentityProvider(ctx context.Context, realm, orgID, alias string) error {
	return c.ensureOrganizationIdentityProvider(ctx, realm, orgID, alias, false)
}

// Receipt-backed node ownership does not own foreign broker relationships.
func (c *Client) EnsureOrganizationIdentityProviderAdditive(ctx context.Context, realm, orgID, alias string) error {
	return c.ensureOrganizationIdentityProvider(ctx, realm, orgID, alias, true)
}

func (c *Client) ensureOrganizationIdentityProvider(ctx context.Context, realm, orgID, alias string, preserve bool) error {
	if alias == "" {
		return nil
	}
	linksPath := adminRealmsPath + realm + organizationsSegment + orgID + identityProvidersSegment
	var linked []IdentityProvider
	if err := c.get(ctx, linksPath, &linked); err != nil {
		return fmt.Errorf("list identity providers of organization %q: %w", orgID, err)
	}
	found := false
	for _, idp := range linked {
		if idp.Alias == alias {
			found = true
			continue
		}
		if preserve {
			continue
		}
		if err := c.unlinkOrganizationIdentityProvider(ctx, linksPath, idp.Alias); err != nil {
			return err
		}
	}
	if found {
		return nil
	}
	// Keycloak's link endpoint consumes the raw alias as the request body, not
	// a JSON document, so this bypasses the JSON helpers deliberately.
	resp, err := c.doRaw(ctx, http.MethodPost, linksPath, alias)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("link identity provider %q to organization %q: keycloak %d: %s", alias, orgID, resp.StatusCode, body)
	}
	return nil
}

// unlinkOrganizationIdentityProvider removes one broker link; a link already
// gone (404) is success.
func (c *Client) unlinkOrganizationIdentityProvider(ctx context.Context, linksPath, alias string) error {
	resp, err := c.doRaw(ctx, http.MethodDelete, linksPath+"/"+url.PathEscape(alias), "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("unlink identity provider %q: keycloak %d: %s", alias, resp.StatusCode, body)
}

// doRaw issues an authenticated request with a plain-text body (empty for
// bodyless methods) and returns the raw response. The caller closes the body.
func (c *Client) doRaw(ctx context.Context, method, path, body string) (*http.Response, error) {
	tok, err := c.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	req.Header.Set(forwardedProtoHeader, httpsScheme)
	return c.do(req)
}

// createOrganization POSTs the desired organization. It returns the new UUID
// with created=true, or created=false when the alias already exists (409).
func (c *Client) createOrganization(ctx context.Context, realm string, spec OrganizationSpec) (string, bool, error) {
	location, status, err := c.postJSONLocation(ctx, adminRealmsPath+realm+organizationsPath, desiredOrganization(spec))
	if err != nil {
		return "", false, err
	}
	switch status {
	case http.StatusCreated:
		if id := idFromLocation(location); id != "" {
			return id, true, nil
		}
		return "", false, nil
	case http.StatusConflict:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("create organization %q in realm %q: keycloak %d", spec.Alias, realm, status)
	}
}

// findOrganizationByAlias walks the realm's organizations and returns the one
// matching the alias, or nil when absent.
func (c *Client) findOrganizationByAlias(ctx context.Context, realm, alias string) (*Organization, error) {
	for first := 0; ; first += organizationsPageSize {
		var page []Organization
		path := adminRealmsPath + realm + organizationsPath +
			"?first=" + strconv.Itoa(first) + "&max=" + strconv.Itoa(organizationsPageSize)
		if err := c.get(ctx, path, &page); err != nil {
			return nil, fmt.Errorf("list organizations in realm %q: %w", realm, err)
		}
		for i := range page {
			if page[i].Alias == alias {
				return &page[i], nil
			}
		}
		if len(page) < organizationsPageSize {
			return nil, nil
		}
	}
}

// desiredOrganization maps a spec onto the Keycloak representation.
func desiredOrganization(spec OrganizationSpec) Organization {
	org := Organization{Name: spec.Name, Alias: spec.Alias, Enabled: true, Attributes: make(map[string][]string, len(spec.Attributes))}
	for key, values := range spec.Attributes {
		org.Attributes[key] = append([]string(nil), values...)
	}
	for _, domain := range spec.Domains {
		org.Domains = append(org.Domains, OrganizationDomain{Name: domain})
	}
	return org
}

// organizationDrifted reports whether the observed organization diverges from
// the declared name, enablement or domain set. Domain verification state is
// owned by Keycloak and intentionally ignored.
func organizationDrifted(observed Organization, spec OrganizationSpec) bool {
	if observed.Name != spec.Name || !observed.Enabled {
		return true
	}
	if len(observed.Domains) != len(spec.Domains) {
		return true
	}
	names := make(map[string]struct{}, len(observed.Domains))
	for _, domain := range observed.Domains {
		names[domain.Name] = struct{}{}
	}
	for _, want := range spec.Domains {
		if _, ok := names[want]; !ok {
			return true
		}
	}
	for key, values := range spec.Attributes {
		actual, ok := observed.Attributes[key]
		if !ok {
			return true
		}
		for _, value := range values {
			if !slices.Contains(actual, value) {
				return true
			}
		}
	}
	return false
}
