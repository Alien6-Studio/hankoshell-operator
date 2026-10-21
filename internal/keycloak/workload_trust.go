package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
)

const WorkloadTrustOwnerKey = "hanko.sh/workload-trust-owner"
const WorkloadTrustJournalKey = "hanko.sh/workload-trust-journal"
const WorkloadTrustReceiptKey = "hanko.sh/adoption-receipt"

var ErrWorkloadTrustRead = errors.New("complete workload trust inventory unavailable")
var ErrWorkloadTrustNative = errors.New("native workload trust state outside qualified closed schema")
var ErrWorkloadTrustConflict = errors.New("native workload trust ownership conflict")

func (c *Client) readWorkloadMetadata(ctx context.Context, path string, target any) error {
	var raw json.RawMessage
	if err := c.get(ctx, path, &raw); err != nil {
		return err
	}
	if httpsecurity.ValidateJSON(raw) != nil || json.Unmarshal(raw, target) != nil {
		return ErrWorkloadTrustRead
	}
	return nil
}

// KubernetesTrustConfig is closed and contains only public, non-secret trust
// metadata. It is never a general-purpose native Config escape hatch.
type KubernetesTrustConfig struct {
	Issuer, DiscoveryURL, JWKSURL string
	MaxAge                        int64
	ClockSkew                     string
	Owner, Journal, Receipt       string
}

type KubernetesTrust struct {
	InternalID, Alias, ProviderID string
	Enabled                       bool
	Config                        KubernetesTrustConfig
	Qualified                     bool
	// Only explicitly qualified fields can be preserved. The native document is
	// discarded; unknown config/fields never enter this representation or a PUT.
	displayName     *string
	firstBrokerFlow *string
	syncMode        *string
}

// PreservedWorkloadTrustFields exposes only the closed qualified public fields,
// never the provider's original config/document or credential-derived data.
func (t KubernetesTrust) PreservedWorkloadTrustFields() []string {
	values := []string{"", "", ""}
	if t.displayName != nil {
		values[0] = *t.displayName
	}
	if t.firstBrokerFlow != nil {
		values[1] = *t.firstBrokerFlow
	}
	if t.syncMode != nil {
		values[2] = *t.syncMode
	}
	return values
}

// WorkloadTrustStateHash includes only reviewed public native semantic fields.
// Ownership metadata is excluded so the journal can bind its own exact state.
func WorkloadTrustStateHash(p KubernetesTrust) string {
	return workloadtrust.Digest("native-state", struct {
		ID, Alias, ProviderID              string
		Enabled                            bool
		Issuer, Discovery, JWKS, ClockSkew string
		Age                                int64
		Preserved                          []string
	}{p.InternalID, p.Alias, p.ProviderID, p.Enabled, p.Config.Issuer, p.Config.DiscoveryURL, p.Config.JWKSURL, p.Config.ClockSkew, p.Config.MaxAge, p.PreservedWorkloadTrustFields()})
}

func validTrustEnvelope(p KubernetesTrust) bool {
	j, err := workloadtrust.ParseJournal(p.Config.Journal)
	return err == nil && p.Qualified && p.ProviderID == "kubernetes" && j.Owner == p.Config.Owner && j.ProviderID == p.InternalID && j.StateHash == WorkloadTrustStateHash(p)
}

func (t *KubernetesTrust) UnmarshalJSON(data []byte) error {
	if httpsecurity.ValidateJSON(data) != nil {
		return ErrWorkloadTrustRead
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || root == nil {
		return ErrWorkloadTrustRead
	}
	*t = KubernetesTrust{Qualified: true}
	for key, raw := range root {
		if t.readRootField(key, raw) != nil {
			return ErrWorkloadTrustRead
		}
	}
	if !workloadNativeID.MatchString(t.InternalID) || t.Alias == "" || len(t.Alias) > 255 || t.ProviderID == "" || len(t.ProviderID) > 255 {
		return ErrWorkloadTrustRead
	}
	if t.ProviderID == "kubernetes" && t.Config.Issuer == "" {
		t.Qualified = false
	}
	return nil
}

func (t *KubernetesTrust) readRootField(key string, raw json.RawMessage) error {
	fields := map[string]any{"internalId": &t.InternalID, "alias": &t.Alias, "providerId": &t.ProviderID, "enabled": &t.Enabled}
	if target, ok := fields[key]; ok {
		return json.Unmarshal(raw, target)
	}
	switch key {
	case "displayName", "firstBrokerLoginFlowAlias":
		return t.readPreservedRoot(key, raw)
	case "hideOnLogin", "trustEmail", "storeToken", "addReadTokenRoleOnCreate", "linkOnly", "authenticateByDefault", "organizationEnabled":
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if value != (key == "hideOnLogin") {
			t.Qualified = false
		}
	case "types":
		var values []string
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		if !slices.Equal(values, []string{"CLIENT_ASSERTION"}) {
			t.Qualified = false
		}
	case "postBrokerLoginFlowAlias", "organizationId":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if value != "" {
			t.Qualified = false
		}
	case "config":
		return t.readConfig(raw)
	default:
		t.Qualified = false
	}
	return nil
}

func (t *KubernetesTrust) readPreservedRoot(key string, raw json.RawMessage) error {
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if key == "displayName" {
		t.displayName = value
		if value != nil && len(*value) > 512 {
			t.Qualified = false
		}
	} else {
		t.firstBrokerFlow = value
		if value != nil && *value != "first broker login" && *value != "" {
			t.Qualified = false
		}
	}
	return nil
}

func (t *KubernetesTrust) readConfig(data []byte) error {
	var config map[string]json.RawMessage
	if json.Unmarshal(data, &config) != nil || config == nil || len(config) > 64 {
		return ErrWorkloadTrustRead
	}
	for key, raw := range config {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return ErrWorkloadTrustRead
		}
		t.readConfigField(key, value)
	}
	// Absence means the measured native default, never desired-state authority.
	if t.Config.MaxAge == 0 {
		t.Config.MaxAge = 3600
	}
	if t.Config.ClockSkew == "" {
		t.Config.ClockSkew = "0"
	}
	if !t.configWithinBudget() {
		t.Qualified = false
	}
	return nil
}

func (t *KubernetesTrust) readConfigField(key, value string) {
	fields := map[string]*string{"issuer": &t.Config.Issuer, "issuerDiscoveryUrl": &t.Config.DiscoveryURL, "jwksUrl": &t.Config.JWKSURL, "allowedClockSkew": &t.Config.ClockSkew, WorkloadTrustOwnerKey: &t.Config.Owner, WorkloadTrustJournalKey: &t.Config.Journal, WorkloadTrustReceiptKey: &t.Config.Receipt}
	if target, ok := fields[key]; ok {
		*target = value
		return
	}
	switch key {
	case "fedClientAssertionMaxExp":
		age, err := strconv.ParseInt(value, 10, 64)
		if err != nil || age < 600 || age > 3600 || strconv.FormatInt(age, 10) != value {
			t.Qualified = false
		}
		t.Config.MaxAge = age
	case "syncMode":
		if value != "LEGACY" {
			t.Qualified = false
		}
		t.syncMode = &value
	default:
		t.Qualified = false
	}
}

func (t KubernetesTrust) configWithinBudget() bool {
	for _, value := range []string{t.Config.Issuer, t.Config.DiscoveryURL, t.Config.JWKSURL} {
		if len(value) > 2048 {
			return false
		}
	}
	return len(t.Config.Journal) <= 8192 && len(t.Config.Receipt) <= 512 && len(t.Config.Owner) <= 128 && (t.Config.ClockSkew == "0" || t.Config.ClockSkew == "10")
}

func trustPayload(t KubernetesTrust) map[string]any {
	c := map[string]string{"issuer": t.Config.Issuer, "allowedClockSkew": t.Config.ClockSkew, "fedClientAssertionMaxExp": strconv.FormatInt(t.Config.MaxAge, 10)}
	for key, value := range map[string]string{"issuerDiscoveryUrl": t.Config.DiscoveryURL, WorkloadTrustOwnerKey: t.Config.Owner, WorkloadTrustJournalKey: t.Config.Journal, WorkloadTrustReceiptKey: t.Config.Receipt} {
		if value != "" {
			c[key] = value
		}
	}
	if t.syncMode != nil {
		c["syncMode"] = *t.syncMode
	}
	p := map[string]any{"alias": t.Alias, "providerId": "kubernetes", "enabled": t.Enabled, "hideOnLogin": true, "config": c}
	if t.InternalID != "" {
		p["internalId"] = t.InternalID
	}
	if t.displayName != nil {
		p["displayName"] = *t.displayName
	}
	if t.firstBrokerFlow != nil {
		p["firstBrokerLoginFlowAlias"] = *t.firstBrokerFlow
	}
	return p
}

// ObserveKubernetesWorkloadTrust inventories all native providers and then reads
// the exact object/mappers. Every page is read; Keycloak defaults to 100 IdPs.
// Response bytes and object count are independently bounded.
func (c *Client) ObserveKubernetesWorkloadTrust(ctx context.Context, realm, alias string) ([]KubernetesTrust, *KubernetesTrust, error) {
	var all []KubernetesTrust
	if err := readAuthorizationCollection(ctx, c, identityProvidersPath(realm), &all); err != nil {
		return nil, nil, err
	}
	if all == nil || len(all) > 1024 {
		return nil, nil, ErrWorkloadTrustRead
	}
	seenIDs, seenAliases := map[string]bool{}, map[string]bool{}
	var target *KubernetesTrust
	for _, p := range all {
		if seenIDs[p.InternalID] || seenAliases[p.Alias] {
			return nil, nil, ErrWorkloadTrustRead
		}
		seenIDs[p.InternalID] = true
		seenAliases[p.Alias] = true
		if p.Alias == alias {
			exact, err := c.readExactKubernetesTrust(ctx, realm, alias, p)
			if err != nil {
				return nil, nil, err
			}
			target = &exact
		}
	}
	return all, target, nil
}

func (c *Client) readExactKubernetesTrust(ctx context.Context, realm, alias string, listed KubernetesTrust) (KubernetesTrust, error) {
	var exact KubernetesTrust
	path := identityProvidersPath(realm) + "/" + url.PathEscape(alias)
	if err := c.get(ctx, path, &exact); err != nil {
		return exact, err
	}
	if exact.InternalID != listed.InternalID || exact.Alias != alias || exact.ProviderID != listed.ProviderID {
		return exact, ErrWorkloadTrustRead
	}
	var mappers []json.RawMessage
	if err := c.get(ctx, path+"/mappers", &mappers); err != nil {
		return exact, err
	}
	if mappers == nil || len(mappers) > 512 {
		return exact, ErrWorkloadTrustRead
	}
	if len(mappers) != 0 {
		exact.Qualified = false
	}
	return exact, nil
}

func (c *Client) CreateOwnedKubernetesWorkloadTrust(ctx context.Context, realm string, desired KubernetesTrust) error {
	if !validTrustEnvelope(desired) {
		return ErrWorkloadTrustConflict
	}
	return c.writeKubernetesTrust(ctx, http.MethodPost, identityProvidersPath(realm), trustPayload(desired))
}

func (c *Client) UpdateOwnedKubernetesWorkloadTrust(ctx context.Context, realm string, before, desired KubernetesTrust) error {
	if !validTrustEnvelope(before) || !validTrustEnvelope(desired) || before.InternalID != desired.InternalID || before.Alias != desired.Alias || before.Config.Owner != desired.Config.Owner {
		return ErrWorkloadTrustConflict
	}
	return c.writeKubernetesTrust(ctx, http.MethodPut, identityProvidersPath(realm)+"/"+url.PathEscape(before.Alias), trustPayload(desired))
}

// Acquire changes only ownership metadata; it never normalizes native defaults
// or rewrites issuer/discovery/age. The closed original semantic document is
// fetched again, compared and retained only within this transaction.
func (c *Client) AcquireKubernetesWorkloadTrustOwnership(ctx context.Context, realm string, before KubernetesTrust, owner, journal, receipt string) error {
	if !before.Qualified || before.ProviderID != "kubernetes" || before.Config.Owner != "" || before.Config.Journal != "" || before.Config.Receipt != "" {
		return ErrWorkloadTrustConflict
	}
	envelope := before
	envelope.Config.Owner, envelope.Config.Journal = owner, journal
	proof, err := adoption.ParseReceipt(receipt)
	if !validTrustEnvelope(envelope) || err != nil || proof.TargetKind != "HankoWorkloadTrust" || proof.TargetUID != owner {
		return ErrWorkloadTrustConflict
	}
	path := identityProvidersPath(realm) + "/" + url.PathEscape(before.Alias)
	var document json.RawMessage
	if err := c.get(ctx, path, &document); err != nil {
		return err
	}
	var fresh KubernetesTrust
	if json.Unmarshal(document, &fresh) != nil || !fresh.Qualified || !reflect.DeepEqual(fresh, before) {
		return ErrWorkloadTrustConflict
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(document, &root)
	var config map[string]string
	if json.Unmarshal(root["config"], &config) != nil {
		return ErrWorkloadTrustRead
	}
	config[WorkloadTrustOwnerKey] = owner
	config[WorkloadTrustJournalKey] = journal
	config[WorkloadTrustReceiptKey] = receipt
	root["config"], _ = json.Marshal(config)
	return c.writeKubernetesTrust(ctx, http.MethodPut, path, root)
}

func (c *Client) DeleteOwnedKubernetesWorkloadTrust(ctx context.Context, realm string, before KubernetesTrust) error {
	if !validTrustEnvelope(before) {
		return ErrWorkloadTrustConflict
	}
	return c.writeKubernetesTrust(ctx, http.MethodDelete, identityProvidersPath(realm)+"/"+url.PathEscape(before.Alias), nil)
}

func (c *Client) writeKubernetesTrust(ctx context.Context, method, path string, payload any) error {
	response, _, err := c.mapperRequest(ctx, method, path, payload)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return ErrWorkloadTrustConflict
	}
	return nil
}

// DependentClient excludes secrets, certificates and arbitrary attributes.
type DependentClient struct {
	ID                                   string `json:"id"`
	ClientID                             string `json:"clientId"`
	Authenticator                        string `json:"clientAuthenticatorType"`
	Enabled                              bool   `json:"enabled"`
	Issuer, Subject, OwnerKind, OwnerUID string
	OwnershipAmbiguous                   bool
}

func (d *DependentClient) UnmarshalJSON(data []byte) error {
	if httpsecurity.ValidateJSON(data) != nil {
		return ErrWorkloadTrustRead
	}
	var p struct {
		ID            string                     `json:"id"`
		ClientID      string                     `json:"clientId"`
		Authenticator string                     `json:"clientAuthenticatorType"`
		Enabled       bool                       `json:"enabled"`
		Attributes    map[string]json.RawMessage `json:"attributes"`
	}
	if json.Unmarshal(data, &p) != nil {
		return ErrWorkloadTrustRead
	}
	*d = DependentClient{ID: p.ID, ClientID: p.ClientID, Authenticator: p.Authenticator, Enabled: p.Enabled}
	for key, target := range map[string]*string{"jwt.credential.issuer": &d.Issuer, "jwt.credential.sub": &d.Subject, "hanko.sh/client-owner-kind": &d.OwnerKind, "hanko.sh/client-owner-uid": &d.OwnerUID} {
		if raw, ok := p.Attributes[key]; ok && json.Unmarshal(raw, target) != nil {
			return ErrWorkloadTrustRead
		}
	}
	d.OwnershipAmbiguous = dependentOwnershipAmbiguous(p.Attributes, *d)
	if !d.validMetadata() {
		return ErrWorkloadTrustRead
	}
	if d.Authenticator == "federated-jwt" && (d.Issuer == "" || d.Subject == "") {
		return ErrWorkloadTrustRead
	}
	return nil
}

func dependentOwnershipAmbiguous(attributes map[string]json.RawMessage, d DependentClient) bool {
	for key := range attributes {
		if key == BoundedDelegationActorAttribute && d.OwnerKind == "HankoServiceAccount" {
			var marker string
			if json.Unmarshal(attributes[key], &marker) == nil && boundedClientEnvelope(&Application{ID: d.ID,
				Attributes: map[string]string{BoundedDelegationActorAttribute: marker}}, d.OwnerUID, adoption.ClientOwnerUIDKey) {
				continue
			}
		}
		if key != adoption.ClientOwnerKindKey && key != adoption.ClientOwnerUIDKey && key != adoption.ReceiptKey && adoption.ReservedAttribute(key) {
			return true
		}
	}
	if _, present := attributes[adoption.ClientOwnerKindKey]; present && d.OwnerKind == "" {
		return true
	}
	_, present := attributes[adoption.ClientOwnerUIDKey]
	return present && d.OwnerUID == ""
}

func (d DependentClient) validMetadata() bool {
	return workloadNativeID.MatchString(d.ID) && d.ClientID != "" && len(d.ClientID) <= 255 && len(d.Issuer) <= 253 && len(d.Subject) <= 512 && len(d.OwnerUID) <= 128 && len(d.OwnerKind) <= 64 && len(d.Authenticator) <= 128
}

var workloadNativeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (c *Client) ListKubernetesWorkloadTrustDependents(ctx context.Context, realm string) ([]DependentClient, error) {
	if c.dependentRealm != realm {
		return nil, ErrWorkloadTrustRead
	}
	var all []DependentClient
	path := adminRealmsPath + url.PathEscape(realm) + "/clients"
	if err := readAuthorizationCollection(ctx, c, path, &all); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	names := map[string]bool{}
	for i, p := range all {
		if seen[p.ID] || names[p.ClientID] {
			return nil, ErrWorkloadTrustRead
		}
		seen[p.ID] = true
		names[p.ClientID] = true
		var full DependentClient
		if err := c.get(ctx, path+"/"+url.PathEscape(p.ID), &full); err != nil {
			return nil, err
		}
		if full.ID != p.ID || full.ClientID != p.ClientID || full.Authenticator != p.Authenticator || full.Issuer != p.Issuer || full.Subject != p.Subject {
			return nil, ErrWorkloadTrustRead
		}
		all[i] = full
	}
	slices.SortFunc(all, func(a, b DependentClient) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return all, nil
}
