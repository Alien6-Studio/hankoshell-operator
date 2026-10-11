package keycloak

import (
	"context"
	"reflect"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

// FederatedWorkloadOwned checks the narrow native envelope used by containment.
// It neither acquires ownership nor treats a status/UUID as execution authority.
func FederatedWorkloadOwned(a *Application, uid, alias, subject string) bool {
	if !ServiceAccountOwned(a, uid) || !federatedWorkloadEnvelope(a) || a.Attributes["jwt.credential.issuer"] != alias || a.Attributes["jwt.credential.sub"] != subject {
		return false
	}
	if _, present := a.Attributes[adoption.ReceiptKey]; present && !validClientAdoptionReceipt(a, "HankoServiceAccount", uid) {
		return false
	}
	for key := range a.Attributes {
		if strings.HasPrefix(key, "jwt.credential.") && key != "jwt.credential.issuer" && key != "jwt.credential.sub" || strings.HasPrefix(key, "hanko.sh/workload-") {
			return false
		}
	}
	return true
}

func federatedWorkloadEnvelope(a *Application) bool {
	return a.ID != "" && a.Protocol == "openid-connect" && a.ClientAuthenticatorType == "federated-jwt" && !a.PublicClient && a.ServiceAccountsEnabled && !a.StandardFlowEnabled && !a.DirectAccessGrantsEnabled && !a.ImplicitFlowEnabled && !a.FullScopeAllowed && len(a.RedirectURIs) == 0 && len(a.WebOrigins) == 0
}

// DisableFederatedWorkloadIfOwned only submits an enabled=false partial native
// update. No credential endpoint, adoption, deletion or automatic reactivation
// is available through this boundary. Callers recheck local authority around it.
func (c *Client) DisableFederatedWorkloadIfOwned(ctx context.Context, realm, clientID, uid, alias, subject string, expected *Application, verify func(context.Context) error) error {
	if expected == nil || verify == nil || verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	current, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if !FederatedWorkloadOwned(current, uid, alias, subject) || !reflect.DeepEqual(current, expected) {
		return ErrApplicationPrecondition
	}
	if current.Enabled {
		if verify(ctx) != nil {
			return ErrApplicationPrecondition
		}
		// The native server merges this representation. Real-version qualification
		// verifies preservation, including fields deliberately absent here.
		_ = c.putJSON(ctx, applicationPath(realm, current.ID), struct {
			ID       string `json:"id"`
			ClientID string `json:"clientId"`
			Enabled  bool   `json:"enabled"`
		}{current.ID, clientID, false})
	}
	if verify(ctx) != nil {
		return ErrApplicationPrecondition
	}
	after, err := c.GetApplication(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if !FederatedWorkloadOwned(after, uid, alias, subject) || after.Enabled {
		return ErrApplicationPrecondition
	}
	before := *current
	before.Enabled = false
	if !reflect.DeepEqual(&before, after) {
		return ErrApplicationPrecondition
	}
	return nil
}
