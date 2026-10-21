package keycloak

import (
	"context"
	"net/url"
)

// WorkloadClientFlow is a closed public projection of the actually bound graph.
// Only the measured native flat clients flow is qualified in P6.2. Custom,
// nested, unknown or disabled executions are refused, never repaired.
type WorkloadClientFlow struct {
	RealmID    string
	Alias      string
	ID         string
	Executions []WorkloadFlowExecution
}

type WorkloadFlowExecution struct {
	ID                 string `json:"id"`
	ProviderID         string `json:"providerId"`
	Requirement        string `json:"requirement"`
	AuthenticationFlow bool   `json:"authenticationFlow"`
	FlowID             string `json:"flowId"`
	Level              int    `json:"level"`
}

func (c *Client) ValidateEffectiveFederatedClientFlow(ctx context.Context, realm string) (WorkloadClientFlow, error) {
	base := adminRealmsPath + url.PathEscape(realm)
	var bound struct {
		ID    string `json:"id"`
		Realm string `json:"realm"`
		Flow  string `json:"clientAuthenticationFlow"`
	}
	if err := c.readWorkloadMetadata(ctx, base, &bound); err != nil {
		return WorkloadClientFlow{}, err
	}
	if bound.ID == "" || len(bound.ID) > 128 || bound.Realm != realm || bound.Flow == "" {
		return WorkloadClientFlow{}, ErrWorkloadTrustRead
	}
	result := WorkloadClientFlow{RealmID: bound.ID, Alias: bound.Flow}
	id, err := c.qualifiedClientFlow(ctx, base, bound.Flow)
	if err != nil {
		return result, err
	}
	result.ID = id

	if err := c.readWorkloadMetadata(ctx, base+"/authentication/flows/"+url.PathEscape(bound.Flow)+"/executions", &result.Executions); err != nil {
		return WorkloadClientFlow{}, err
	}
	if !qualifiedFederatedExecutions(result.Executions) {
		return WorkloadClientFlow{}, ErrWorkloadTrustNative
	}
	return result, nil
}

type workloadNativeFlow struct {
	ID         string `json:"id"`
	Alias      string `json:"alias"`
	ProviderID string `json:"providerId"`
	BuiltIn    bool   `json:"builtIn"`
	TopLevel   bool   `json:"topLevel"`
}

func (c *Client) qualifiedClientFlow(ctx context.Context, base, alias string) (string, error) {
	var flows []workloadNativeFlow
	if err := c.readWorkloadMetadata(ctx, base+"/authentication/flows", &flows); err != nil {
		return "", err
	}
	if flows == nil || len(flows) > 512 {
		return "", ErrWorkloadTrustRead
	}
	id := ""
	seenIDs, seenAliases := map[string]bool{}, map[string]bool{}
	for _, f := range flows {
		if f.ID == "" || f.Alias == "" || seenIDs[f.ID] || seenAliases[f.Alias] {
			return "", ErrWorkloadTrustRead
		}
		seenIDs[f.ID], seenAliases[f.Alias] = true, true
		if f.Alias != alias {
			continue
		}
		if !f.BuiltIn || !f.TopLevel || f.ProviderID != "client-flow" || f.Alias != "clients" {
			return "", ErrWorkloadTrustNative
		}
		id = f.ID
	}
	if id == "" {
		return "", ErrWorkloadTrustRead
	}
	return id, nil
}

func qualifiedFederatedExecutions(executions []WorkloadFlowExecution) bool {
	if len(executions) == 0 || len(executions) > 512 {
		return false
	}
	seen := map[string]bool{}
	fed := 0
	for _, e := range executions {
		if seen[e.ID] || !qualifiedWorkloadExecution(e) {
			return false
		}
		seen[e.ID] = true
		if e.ProviderID == "federated-jwt" {
			fed++
		}
	}
	return fed == 1
}

func qualifiedWorkloadExecution(e WorkloadFlowExecution) bool {
	if e.ID == "" || len(e.ID) > 128 || e.AuthenticationFlow || e.FlowID != "" || e.Level != 0 || e.Requirement != "ALTERNATIVE" {
		return false
	}
	switch e.ProviderID {
	case "client-secret", "client-jwt", "client-secret-jwt", "client-x509", "federated-jwt":
		return true
	default:
		return false
	}
}
