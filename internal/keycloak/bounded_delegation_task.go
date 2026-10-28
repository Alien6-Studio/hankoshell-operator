package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

type taskDelegationCapability struct {
	Contract          string `json:"contract"`
	ExtensionVersion  string `json:"extensionVersion"`
	KeycloakVersion   string `json:"keycloakVersion"`
	Enabled           bool   `json:"enabled"`
	Experimental      bool   `json:"experimental"`
	StateStore        string `json:"stateStore"`
	OnlineRequired    bool   `json:"onlineRequired"`
	SingleUseApproval bool   `json:"singleUseApproval"`
	MaxDepth          int32  `json:"maxDepth"`
	MaxTTLSeconds     int32  `json:"maxTTLSeconds"`
}

func (c *Client) taskDelegationCapability(ctx context.Context, realm string) (taskDelegationCapability, error) {
	var capability taskDelegationCapability
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/realms/"+url.PathEscape(realm)+"/bounded-delegation/task-context", nil)
	if err != nil {
		return capability, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.do(request)
	if err != nil {
		return capability, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return capability, err
	}
	if response.StatusCode != http.StatusOK || len(data) > 8192 || httpsecurity.ValidateJSON(data) != nil {
		return capability, ErrBoundedDelegationUnsupported
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&capability) != nil || !validTaskDelegationCapability(capability) {
		return capability, ErrBoundedDelegationUnsupported
	}
	return capability, nil
}

func validTaskDelegationCapability(capability taskDelegationCapability) bool {
	return capability.Contract == "bounded-delegation/task-reference-v1" && capability.ExtensionVersion == "0.1.0-SNAPSHOT" &&
		slices.Contains([]string{"26.7.5", "26.8.0", "26.8.1"}, capability.KeycloakVersion) &&
		capability.Enabled && capability.Experimental && capability.StateStore == "database" && capability.OnlineRequired &&
		capability.SingleUseApproval && capability.MaxDepth == 1 && capability.MaxTTLSeconds == 600 &&
		validBoundedCapability(BoundedDelegationCapability{Contract: "bounded-delegation/software-v1", ExtensionVersion: capability.ExtensionVersion,
			KeycloakVersion: capability.KeycloakVersion, Enabled: true, Experimental: true, MaxDepth: 4, MaxTTLSeconds: 600})
}

func (c *Client) requestedTaskCapability(ctx context.Context, realm string, permissions []BoundedDelegationPermission) (*taskDelegationCapability, error) {
	if len(permissions) == 0 {
		return nil, ErrBoundedDelegationUnsupported
	}
	mode := permissions[0].TaskAuthorization
	if mode != "" && mode != "required" {
		return nil, ErrBoundedDelegationUnsupported
	}
	for _, permission := range permissions {
		if permission.TaskAuthorization != mode {
			return nil, ErrBoundedDelegationUnsupported
		}
	}
	if mode == "" {
		return nil, nil
	}
	capability, err := c.taskDelegationCapability(ctx, realm)
	if err != nil {
		return nil, err
	}
	return &capability, nil
}

func boundedTaskRuntime(data []byte, capability *taskDelegationCapability) string {
	if capability != nil {
		data, _ = json.Marshal([]any{data, capability})
	}
	return boundedDigest(data)
}
