package fleetplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

type localHub struct {
	Target   Target `json:"target"`
	Endpoint string `json:"endpoint"`
}
type localCommand struct {
	Target   Target `json:"target"`
	Action   string `json:"action"`
	Identity string `json:"identity"`
}

func validLocalAuthorities(hubs []localHub, commands []localCommand) bool {
	if len(hubs) > 64 || len(commands) > 64 {
		return false
	}
	seen := map[Target]bool{}
	for _, h := range hubs {
		if !validHub(h) || seen[h.Target] {
			return false
		}
		seen[h.Target] = true
	}
	seen = map[Target]bool{}
	for _, c := range commands {
		if !validTarget(c.Target) || seen[c.Target] || c.Action != "decommission" || !iamcontract.ValidDigest(c.Identity) {
			return false
		}
		seen[c.Target] = true
	}
	return true
}

// EndpointIdentity pins the exact outgoing credential destination locally.
func EndpointIdentity(endpoint string) string {
	digest := sha256.Sum256([]byte("hanko.sh/fleet-hub/v1alpha1\x00" + endpoint))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ApproveHub requires an exact protected entry when configured or when a
// previously accepted endpoint changes. Initial enrollment retains the local
// tenant declaration when no independent hub list was provisioned.
func ApproveHub(data []byte, target Target, endpoint, accepted string) error {
	if !validHubEndpoint(endpoint) {
		return Refusal("FleetHubEndpointUnapproved")
	}
	c, err := localConfiguration(data)
	if err != nil {
		return err
	}
	if len(c.Hubs) == 0 && (accepted == "" || accepted == EndpointIdentity(endpoint)) {
		return nil
	}
	for _, h := range c.Hubs {
		if h.Target == target && h.Endpoint == endpoint {
			return nil
		}
	}
	return Refusal("FleetHubEndpointUnapproved")
}

// DecommissionIdentity binds one exact command window and tenant UID, excluding
// Hub credentials. Independent policy administrators approve this hash.
func DecommissionIdentity(target Target, requestedAt, deadline time.Time) string {
	raw, _ := json.Marshal(struct {
		Target      Target    `json:"target"`
		RequestedAt time.Time `json:"requestedAt"`
		Deadline    time.Time `json:"deadline"`
	}{target, requestedAt.UTC(), deadline.UTC()})
	digest := sha256.Sum256(append([]byte("hanko.sh/fleet-decommission/v1alpha1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ApproveDecommission(data []byte, target Target, identity string) error {
	c, err := localConfiguration(data)
	if err != nil {
		return err
	}
	for _, command := range c.Commands {
		if command.Target == target && command.Action == "decommission" && command.Identity == identity {
			return nil
		}
	}
	return Refusal("FleetCommandUnapproved")
}

func validHub(h localHub) bool {
	return validTarget(h.Target) && validHubEndpoint(h.Endpoint)
}

func validHubEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && len(endpoint) <= 256 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
