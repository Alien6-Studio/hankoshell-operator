package authentik

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// Connection is administrator-owned typed configuration, not portable intent.
// The controller resolves TokenSecret and CASecret separately; values never enter
// plans, status, logs or the durable recovery journal.
type Connection struct {
	SchemaVersion     int      `json:"schemaVersion"`
	Provider          string   `json:"provider"`
	Version           string   `json:"version"`
	Endpoint          string   `json:"endpoint"`
	Realm             string   `json:"realm"`
	TokenSecret       string   `json:"tokenSecret"`
	CASecret          string   `json:"caSecret,omitempty"`
	AuthorizationFlow string   `json:"authorizationFlow"`
	InvalidationFlow  string   `json:"invalidationFlow"`
	SigningKey        string   `json:"signingKey"`
	ScopeMappings     []string `json:"scopeMappings"`
}

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var localName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

func (c Connection) Validate() error {
	if c.SchemaVersion != 1 || c.Provider != string(iamcontract.Authentik) || c.Version != Version || !localName.MatchString(c.Realm) || !localName.MatchString(c.TokenSecret) || c.CASecret != "" && !localName.MatchString(c.CASecret) || !uuid.MatchString(c.AuthorizationFlow) || !uuid.MatchString(c.InvalidationFlow) || !uuid.MatchString(c.SigningKey) || !validMappingCount(c.ScopeMappings) {
		return ErrUnsupported
	}
	seen := map[string]bool{}
	for _, id := range c.ScopeMappings {
		if seen[id] {
			return ErrUnsupported
		}
		seen[id] = true
		if !uuid.MatchString(id) {
			return ErrUnsupported
		}
	}
	_, err := NewClient(c.Endpoint, "configuration-validation", nil)
	return err
}
func Evidence() applications.CapabilityEvidence {
	return applications.CapabilityEvidence{Supported: applications.Capabilities{OIDC: true, PublicClient: true, ConfidentialClient: true}, Source: "experimental-adapter", Window: Version}
}

// Classify refuses the complete intent before any read or write. No native
// attribute, claim, scope, rotation or projection is silently discarded.
func Classify(i applications.Intent, r applications.ResolvedReferences) []iamcontract.Finding {
	i = applications.Normalize(i)
	code := ""
	switch {
	case !validClientID(i.ClientID):
		code = "client_identity_unsupported"
	case i.Protocol != "oidc":
		code = "protocol_unsupported"
	case i.Pattern != "spa" && i.Pattern != "web":
		code = "machine_identity_requires_user"
	case hasNativeExtension(i, r):
		code = "native_extension_unsupported"
	case hasBindings(i):
		code = "application_bindings_unsupported"
	case i.Rotation != nil || len(i.Projections) > 0:
		code = "credential_lifecycle_unsupported"
	case len(i.PostLogoutURIs) > 0:
		code = "post_logout_unsupported"
	case len(i.RedirectURIs) < 1 || len(i.RedirectURIs) > 32:
		code = "redirect_set_unsupported"
	}
	if !validRedirects(i.RedirectURIs) {
		code = "redirect_set_unsupported"
	}
	if code == "" {
		return nil
	}
	return []iamcontract.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "application", Code: code, Message: "intent requires semantics outside the experimental authentik window"}}
}

type Driver struct {
	client     *Client
	connection Connection
}

var _ applications.Driver = (*Driver)(nil)

func NewDriver(c *Client, connection Connection) (*Driver, error) {
	if c == nil || connection.Validate() != nil || c.endpoint != connection.Endpoint {
		return nil, ErrUnsupported
	}
	connection.ScopeMappings = append([]string(nil), connection.ScopeMappings...)
	slices.Sort(connection.ScopeMappings)
	return &Driver{client: c, connection: connection}, nil
}
func (*Driver) Capabilities(context.Context) (applications.CapabilityEvidence, error) {
	return Evidence(), nil
}
func (d *Driver) inputs(p applications.Plan) (applications.Intent, applications.ResolvedReferences, error) {
	i, r, err := p.Inputs(iamcontract.Authentik)
	if err != nil {
		return i, r, err
	}
	if iamcontract.Accept(Classify(i, r)) != nil || r.Realm != d.connection.Realm || i.RealmRef != d.connection.Realm || r.PublicBase != d.client.endpoint || r.ConnectionIdentity != d.connection.Identity() {
		return i, r, ErrUnsupported
	}
	return i, r, nil
}
func marker(endpoint, owner string) string {
	sum := sha256.Sum256([]byte(endpoint + "\x00" + owner))
	return "hanko:v1:" + hex.EncodeToString(sum[:])
}
func slug(i applications.Intent) string {
	sum := sha256.Sum256([]byte(i.RealmRef + "\x00" + i.ClientID))
	return "hk-" + hex.EncodeToString(sum[:20])
}

type redirectURI struct {
	MatchingMode string `json:"matching_mode"`
	URL          string `json:"url"`
	Type         string `json:"redirect_uri_type"`
}
type provider struct {
	PK                  int           `json:"pk,omitempty"`
	Name                string        `json:"name"`
	AuthorizationFlow   string        `json:"authorization_flow"`
	InvalidationFlow    string        `json:"invalidation_flow"`
	ClientID            string        `json:"client_id"`
	ClientType          string        `json:"client_type"`
	Grants              []string      `json:"grant_types"`
	Redirects           []redirectURI `json:"redirect_uris"`
	SigningKey          string        `json:"signing_key"`
	Mappings            []string      `json:"property_mappings"`
	IssuerMode          string        `json:"issuer_mode"`
	FederationSources   []string      `json:"jwt_federation_sources"`
	FederationProviders []int         `json:"jwt_federation_providers"`
}
type application struct {
	PK          string `json:"pk,omitempty"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Provider    int    `json:"provider"`
	Marker      string `json:"meta_description"`
	Backchannel []int  `json:"backchannel_providers"`
}
type pagination struct {
	Next  int `json:"next"`
	Count int `json:"count"`
}
type providerList struct {
	Pagination pagination `json:"pagination"`
	Results    []provider `json:"results"`
}

func (d *Driver) find(ctx context.Context, i applications.Intent) (*provider, *application, error) {
	var list providerList
	if err := d.client.request(ctx, http.MethodGet, "/api/v3/providers/oauth2/", url.Values{"client_id": {i.ClientID}, "page_size": {"2"}}, nil, &list); err != nil {
		return nil, nil, err
	}
	if list.Pagination.Next != 0 || list.Pagination.Count != len(list.Results) || len(list.Results) > 1 {
		return nil, nil, ErrResponse
	}
	var got *provider
	if len(list.Results) == 1 {
		if list.Results[0].PK <= 0 || list.Results[0].ClientID != i.ClientID {
			return nil, nil, ErrResponse
		}
		got = &list.Results[0]
	}
	var app application
	err := d.client.request(ctx, http.MethodGet, "/api/v3/core/applications/"+slug(i)+"/", nil, nil, &app)
	if errors.Is(err, ErrNotFound) {
		return got, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if app.Slug != slug(i) || app.PK == "" || app.Provider <= 0 {
		return nil, nil, ErrResponse
	}
	return got, &app, nil
}
func (d *Driver) desired(i applications.Intent, r applications.ResolvedReferences) (provider, application) {
	kind := "confidential"
	if i.Pattern == "spa" {
		kind = "public"
	}
	redirects := make([]redirectURI, 0, len(i.RedirectURIs))
	for _, uri := range i.RedirectURIs {
		redirects = append(redirects, redirectURI{"strict", uri, "authorization"})
	}
	p := provider{Name: marker(d.client.endpoint, r.Owner), AuthorizationFlow: d.connection.AuthorizationFlow, InvalidationFlow: d.connection.InvalidationFlow, ClientID: i.ClientID, ClientType: kind, Grants: []string{"authorization_code", "refresh_token"}, Redirects: redirects, SigningKey: d.connection.SigningKey, Mappings: d.connection.ScopeMappings, IssuerMode: "per_provider", FederationSources: []string{}, FederationProviders: []int{}}
	a := application{Name: i.ClientID, Slug: slug(i), Marker: p.Name, Backchannel: []int{}}
	return p, a
}
func owns(got *provider, app *application, want provider) bool {
	return (got == nil || got.Name == want.Name) && (app == nil || got != nil && app.Marker == want.Name && app.Provider == got.PK)
}
func providerEqual(a, b provider) bool {
	a.PK, b.PK = 0, 0
	slices.Sort(a.Grants)
	slices.Sort(b.Grants)
	slices.Sort(a.Mappings)
	slices.Sort(b.Mappings)
	slices.SortFunc(a.Redirects, func(a, b redirectURI) int {
		if a.URL < b.URL {
			return -1
		}
		if a.URL > b.URL {
			return 1
		}
		return 0
	})
	slices.SortFunc(b.Redirects, func(a, b redirectURI) int {
		if a.URL < b.URL {
			return -1
		}
		if a.URL > b.URL {
			return 1
		}
		return 0
	})
	if len(a.FederationSources) == 0 {
		a.FederationSources = []string{}
	}
	if len(a.FederationProviders) == 0 {
		a.FederationProviders = []int{}
	}
	return reflect.DeepEqual(a, b)
}
func (d *Driver) Observe(ctx context.Context, p applications.Plan) (applications.State, error) {
	i, r, err := d.inputs(p)
	if err != nil {
		return applications.State{}, err
	}
	got, app, err := d.find(ctx, i)
	if err != nil {
		return applications.State{}, iamcontract.SafeError(err)
	}
	want, wantApp := d.desired(i, r)
	owned := owns(got, app, want)
	equal := got != nil && app != nil && owned && providerEqual(*got, want) && app.Name == wantApp.Name && len(app.Backchannel) == 0
	// Observation contains local booleans only. Remote names, payloads, credentials
	// and native primary keys cannot contaminate rendered evidence.
	data, _ := json.Marshal(struct{ Provider, Application, Owned, Equal bool }{got != nil, app != nil, owned, equal})
	state := applications.State{Present: got != nil || app != nil, Owned: got != nil && owned, Protocol: "oidc", Observation: iamcontract.Observation{Complete: true, Drifted: !equal, StateHash: iamcontract.Hash(iamcontract.Version, "applications", "authentik-observation", data)}}
	if got != nil {
		state.ProviderID = strconv.Itoa(got.PK)
	}
	return state, nil
}
func (d *Driver) Ensure(ctx context.Context, p applications.Plan) (applications.State, error) {
	i, r, err := d.inputs(p)
	if err != nil {
		return applications.State{}, err
	}
	got, app, err := d.find(ctx, i)
	if err != nil {
		return applications.State{}, iamcontract.SafeError(err)
	}
	want, wantApp := d.desired(i, r)
	if !owns(got, app, want) {
		return applications.State{}, ErrConflict
	}
	var created bool
	got, created, err = d.ensureProvider(ctx, want, got)
	if err != nil {
		return applications.State{}, err
	}
	wantApp.Provider = got.PK
	if app == nil {
		if err := d.client.request(ctx, http.MethodPost, "/api/v3/core/applications/", nil, wantApp, nil); err != nil {
			return applications.State{}, iamcontract.SafeError(err)
		}
	} else if app.Name != wantApp.Name || len(app.Backchannel) > 0 {
		if err := d.client.request(ctx, http.MethodPatch, "/api/v3/core/applications/"+slug(i)+"/", nil, wantApp, nil); err != nil {
			return applications.State{}, iamcontract.SafeError(err)
		}
	}
	state, err := d.Observe(ctx, p)
	state.Created = created
	if err == nil && (!state.Observation.Complete || state.Observation.Drifted) {
		err = iamcontract.ErrDrift
	}
	return state, err
}
func (d *Driver) DeleteOwned(ctx context.Context, p applications.Plan) error {
	i, r, err := d.inputs(p)
	if err != nil {
		return err
	}
	got, app, err := d.find(ctx, i)
	if err != nil {
		return iamcontract.SafeError(err)
	}
	want, _ := d.desired(i, r)
	if !owns(got, app, want) {
		return ErrConflict
	}
	if app != nil {
		if err := d.client.request(ctx, http.MethodDelete, "/api/v3/core/applications/"+slug(i)+"/", nil, nil, nil); err != nil {
			return iamcontract.SafeError(err)
		}
	}
	if got != nil {
		if err := d.client.request(ctx, http.MethodDelete, "/api/v3/providers/oauth2/"+strconv.Itoa(got.PK)+"/", nil, nil, nil); err != nil {
			return iamcontract.SafeError(err)
		}
	}
	got, app, err = d.find(ctx, i)
	if err != nil {
		return iamcontract.SafeError(err)
	}
	if got != nil || app != nil {
		return iamcontract.ErrDrift
	}
	return nil
}
func (d *Driver) Metadata(ctx context.Context, p applications.Plan) (applications.Metadata, error) {
	i, _, err := d.inputs(p)
	if err != nil {
		return applications.Metadata{}, err
	}
	return applications.Metadata{Issuer: d.client.endpoint + "/application/o/" + slug(i) + "/", Authorization: d.client.endpoint + "/application/o/authorize/", Token: d.client.endpoint + "/application/o/token/", JWKS: d.client.endpoint + "/application/o/" + slug(i) + "/jwks/", UserInfo: d.client.endpoint + "/application/o/userinfo/"}, nil
}

func validClientID(value string) bool {
	return len(value) > 0 && len(value) <= 255 && strings.IndexFunc(value, func(r rune) bool { return r < 33 || r > 126 }) < 0
}
func hasNativeExtension(i applications.Intent, r applications.ResolvedReferences) bool {
	return i.Theme != "" || len(r.Attributes) > 0 || len(r.Mappers) > 0 || len(r.IdentityMappers) > 0 || r.MigrationUUID != "" || r.MigrationObservation != ""
}
func hasBindings(i applications.Intent) bool {
	return len(i.Roles) > 0 || len(i.Claims) > 0 || len(i.IdentityMappings) > 0 || i.ScopesManaged || len(i.RealmRoleScopes) > 0
}
func validRedirects(values []string) bool {
	for _, value := range values {
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(value) > 2048 {
			return false
		}
	}
	return true
}

func (d *Driver) ensureProvider(ctx context.Context, want provider, got *provider) (*provider, bool, error) {
	created := false
	if got == nil {
		var result provider
		if err := d.client.request(ctx, http.MethodPost, "/api/v3/providers/oauth2/", nil, want, &result); err != nil {
			return nil, false, iamcontract.SafeError(err)
		}
		if result.PK <= 0 || result.ClientID != want.ClientID || result.Name != want.Name {
			return nil, false, ErrResponse
		}
		got = &result
		created = true
	} else if !providerEqual(*got, want) {
		if err := d.client.request(ctx, http.MethodPatch, "/api/v3/providers/oauth2/"+strconv.Itoa(got.PK)+"/", nil, want, nil); err != nil {
			return nil, false, iamcontract.SafeError(err)
		}
	}

	return got, created, nil
}

// Identity binds non-secret endpoint, flow, signing and scope prerequisites to
// execution without changing portable intent or serializing credentials.
func (c Connection) Identity() iamcontract.Digest {
	c.ScopeMappings = append([]string(nil), c.ScopeMappings...)
	slices.Sort(c.ScopeMappings)
	data, _ := json.Marshal(c)
	return iamcontract.Hash(iamcontract.Version, "applications", "authentik-connection", data)
}

func validMappingCount(values []string) bool { return len(values) > 0 && len(values) <= 8 }
