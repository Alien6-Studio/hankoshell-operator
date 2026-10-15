package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

// FleetPermissions is a conservative native-role snapshot from a newly issued
// response of this client's verified HTTPS token endpoint, never from Hub input.
// Fine-grained/opaque/lightweight tokens without these roles fail closed. This
// does not replace provider authorization or promise immediate role revocation.
type FleetPermissions struct {
	Version                                                           string
	ExpiresAt                                                         time.Time
	ManageRealm, ManageEvents, ManageClients, ManageIdentityProviders bool
}

var errFleetPermissions = errors.New("fleet provider permission evidence is unavailable")

func (c *Client) FleetPermissions(ctx context.Context, realm string) (FleetPermissions, error) {
	if c == nil || c.inventoryOnly || c.dependentRealm != "" || !workloadNativeID.MatchString(realm) || realm == "master" || ValidateEndpoint(c.baseURL, false) != nil {
		return FleetPermissions{}, errFleetPermissions
	}
	// A fresh token observes current effective native grants at each rollout
	// decision. Roles are not accepted from a CR, ConfigMap, cached status or API.
	token, err := c.fetchToken(ctx)
	if err != nil {
		return FleetPermissions{}, errFleetPermissions
	}
	result, err := c.fleetTokenPermissions(token, realm, time.Now())
	if err != nil {
		return FleetPermissions{}, err
	}
	result.Version, err = c.ServerVersion(ctx)
	if err != nil {
		return FleetPermissions{}, errFleetPermissions
	}
	observed, err := c.GetRealm(ctx, realm)
	if err != nil || observed.ID == "" || observed.URLName() != realm {
		return FleetPermissions{}, errFleetPermissions
	}
	return result, nil
}

func (c *Client) fleetTokenPermissions(token, realm string, now time.Time) (FleetPermissions, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 64<<10 || parts[0] == "" || parts[2] == "" {
		return FleetPermissions{}, errFleetPermissions
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var claims struct {
		Issuer  string `json:"iss"`
		Client  string `json:"azp"`
		Expires int64  `json:"exp"`
		Issued  int64  `json:"iat"`
		Access  map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if err != nil || httpsecurity.ValidateJSON(raw) != nil || json.Unmarshal(raw, &claims) != nil || claims.Issuer != c.baseURL+"/realms/master" || claims.Client != c.clientID || claims.Expires <= now.Unix() || claims.Issued > now.Add(30*time.Second).Unix() || claims.Issued < now.Add(-time.Minute).Unix() {
		return FleetPermissions{}, errFleetPermissions
	}
	roles := claims.Access[realm+"-realm"].Roles
	if len(roles) > 64 {
		return FleetPermissions{}, errFleetPermissions
	}
	return FleetPermissions{ExpiresAt: time.Unix(claims.Expires, 0), ManageRealm: slices.Contains(roles, "manage-realm"), ManageEvents: slices.Contains(roles, "manage-events"), ManageClients: slices.Contains(roles, "manage-clients"), ManageIdentityProviders: slices.Contains(roles, "manage-identity-providers")}, nil
}
