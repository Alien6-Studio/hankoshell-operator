package keycloak

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
)

// No opaque value enters the adoption projection. Native attribute families
// are admitted only by an explicit schema; unknown values remain blocked.
func OrganizationAttributesQualified(attrs map[string][]string) bool {
	for key, values := range attrs {
		if adoption.ReservedAttribute(key) {
			continue
		}
		if QualifiedOrganizationPublicAttribute(key, values) {
			continue
		}
		if key != "trunx_slug" || len(values) != 1 || len(values[0]) > 253 {
			return false
		}
	}
	return true
}

// These exact public locale values are independently qualified native metadata.
// This is a closed schema, not permission to hash arbitrary attribute values.
func QualifiedOrganizationPublicAttribute(key string, values []string) bool {
	return QualifiedNativeLocale(key, values)
}

func organizationPreservationProof(document map[string]any, owner map[string][]string) (map[string]any, error) {
	var rep struct {
		Attributes map[string][]string `json:"attributes"`
	}
	data, err := json.Marshal(document)
	if err != nil || json.Unmarshal(data, &rep) != nil {
		return nil, ErrAdoptionPrecondition
	}
	values := rep.Attributes[adoption.ReceiptKey]
	if len(values) != 1 {
		return nil, ErrAdoptionPrecondition
	}
	proof, err := adoption.ParseReceipt(values[0])
	name, namespace, uid := owner[organization.OwnerName], owner[organization.OwnerNamespace], owner[organization.OwnerUID]
	if err != nil || len(name) != 1 || len(namespace) != 1 || len(uid) != 1 || proof.TargetKind != "HankoOrganization" || proof.TargetUID != uid[0] || !OrganizationExactReceipt(rep.Attributes, name[0], namespace[0], uid[0], values[0]) || !OrganizationAttributesQualified(rep.Attributes) {
		return nil, ErrAdoptionPrecondition
	}
	attrs, _ := document["attributes"].(map[string]any)
	return attrs, nil
}

func (c *Client) reconcileAdoptedGroup(ctx context.Context, realm, id string, spec GroupSpec) error {
	var document map[string]any
	if err := c.get(ctx, groupEndpoint(realm, id), &document); err != nil {
		return err
	}
	delete(document, "access")
	if !(&OrganizationOwnershipSnapshot{group: document}).QualifiedRoots() {
		return ErrAdoptionPrecondition
	}
	if document["id"] != id || document["name"] != spec.Name || document["path"] != spec.groupPath() {
		return ErrAdoptionPrecondition
	}
	attrs, err := organizationPreservationProof(document, spec.OwnershipAttributes)
	if err != nil {
		return err
	}
	changed := false
	for key, values := range spec.Attributes {
		current, _ := attrs[key].([]any)
		want := make([]any, len(values))
		for i, value := range values {
			want[i] = value
		}
		if !reflect.DeepEqual(current, want) {
			changed = true
			attrs[key] = want
		}
	}
	if !changed {
		return nil
	}
	return c.putJSON(ctx, groupEndpoint(realm, id), map[string]any{"name": spec.Name, "attributes": attrs})
}

func (c *Client) reconcileAdoptedNativeOrganization(ctx context.Context, realm, id string, spec OrganizationSpec) error {
	var document map[string]any
	if err := c.get(ctx, organizationEndpoint(realm, id), &document); err != nil {
		return err
	}
	delete(document, "access")
	if !(&OrganizationOwnershipSnapshot{native: document}).QualifiedRoots() {
		return ErrAdoptionPrecondition
	}
	if document["id"] != id || document["alias"] != spec.Alias {
		return ErrAdoptionPrecondition
	}
	attrs, err := organizationPreservationProof(document, spec.OwnershipAttributes)
	if err != nil {
		return err
	}
	var current Organization
	data, _ := json.Marshal(document)
	if json.Unmarshal(data, &current) != nil {
		return ErrAdoptionPrecondition
	}
	if !organizationDrifted(current, spec) {
		return nil
	}
	// Preserve each existing domain's provider metadata, including Verified.
	domains, _ := document["domains"].([]any)
	nextDomains, err := preservedOrganizationDomains(domains, spec.Domains)
	if err != nil {
		return err
	}
	for key, values := range spec.Attributes {
		attrs[key] = slices.Clone(values)
	}
	document["name"], document["enabled"], document["domains"], document["attributes"] = spec.Name, true, nextDomains, attrs
	delete(document, "access")
	return c.putJSON(ctx, organizationEndpoint(realm, id), document)
}

func preservedOrganizationDomains(domains []any, want []string) ([]any, error) {
	nextDomains := []any{}
	seen := map[string]bool{}
	for _, entry := range domains {
		domain, ok := entry.(map[string]any)
		if !ok {
			return nil, ErrAdoptionPrecondition
		}
		name, ok := domain["name"].(string)
		if !ok || name == "" || seen[name] {
			return nil, ErrAdoptionPrecondition
		}
		seen[name] = true
		if slices.Contains(want, name) {
			nextDomains = append(nextDomains, entry)
		}
	}
	for _, name := range want {
		if !seen[name] {
			nextDomains = append(nextDomains, map[string]any{"name": name})
		}
	}
	return nextDomains, nil
}

// Each adopted node must still have a closed native representation and its own
// exact checkpoint before cleanup; a sibling's receipt is not authority.
func (c *Client) CheckAdoptedOrganizationRepresentation(ctx context.Context, realm, id string, native bool, owner map[string][]string) error {
	path := groupEndpoint(realm, id)
	if native {
		path = organizationEndpoint(realm, id)
	}
	var document map[string]any
	if err := c.get(ctx, path, &document); err != nil {
		return err
	}
	delete(document, "access")
	snapshot := &OrganizationOwnershipSnapshot{group: document}
	if native {
		snapshot.group, snapshot.native = nil, document
	}
	if document["id"] != id || !snapshot.QualifiedRoots() {
		return ErrAdoptionPrecondition
	}
	_, err := organizationPreservationProof(document, owner)
	return err
}
