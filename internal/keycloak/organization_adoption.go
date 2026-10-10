package keycloak

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/organization"
)

// OrganizationOwnershipSnapshot is ephemeral aggregate evidence. Members are
// never loaded. Raw documents are private and used only for owner-only writes.
type OrganizationOwnershipSnapshot struct {
	Group         Group
	Organization  *Organization
	ParentID      string
	Children      []Group
	Roles         []RealmRole
	Links         []string
	group, native map[string]any
}

func groupEndpoint(realm, id string) string {
	return adminRealmsPath + url.PathEscape(realm) + groupsSegment + url.PathEscape(id)
}
func organizationEndpoint(realm, id string) string {
	return adminRealmsPath + url.PathEscape(realm) + organizationsSegment + url.PathEscape(id)
}

func (c *Client) ReadOrganizationOwnership(ctx context.Context, realm, path, alias string) (*OrganizationOwnershipSnapshot, error) {
	group, err := c.GetGroupByPath(ctx, realm, path)
	if err != nil {
		return nil, err
	}
	s := &OrganizationOwnershipSnapshot{}
	if err := c.get(ctx, groupEndpoint(realm, group.ID), &s.group); err != nil {
		return nil, err
	}
	if err := decodeSnapshot(s.group, &s.Group); err != nil {
		return nil, err
	}
	if s.Group.ID == "" || s.Group.ID != group.ID || s.Group.Path != path {
		return nil, ErrAdoptionPrecondition
	}
	if err := c.readOrganizationParent(ctx, realm, path, s); err != nil {
		return nil, err
	}
	s.Children, err = c.InventoryGroups(ctx, realm, group.ID)
	if err != nil {
		return nil, err
	}
	s.Roles, err = c.InventoryGroupRoles(ctx, realm, group.ID)
	if err != nil {
		return nil, err
	}
	if len(s.Roles) > adoption.MaxEdges {
		return nil, ErrAuthorizationReadLimit
	}
	if alias == "" {
		return s, nil
	}
	return s, c.readOrganizationNative(ctx, realm, alias, s)
}

func (c *Client) readOrganizationParent(ctx context.Context, realm, path string, s *OrganizationOwnershipSnapshot) error {
	s.ParentID, _ = s.group["parentId"].(string)
	end := strings.LastIndex(path, "/")
	if end <= 0 {
		if s.ParentID != "" {
			return ErrAdoptionPrecondition
		}
		return nil
	}
	parent, err := c.GetGroupByPath(ctx, realm, path[:end])
	if err != nil {
		return err
	}
	children, err := c.InventoryGroups(ctx, realm, parent.ID)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.ID == s.Group.ID && child.Path == path && (s.ParentID == "" || s.ParentID == parent.ID) {
			s.ParentID = parent.ID
			return nil
		}
	}
	return ErrAdoptionPrecondition
}

func (c *Client) readOrganizationNative(ctx context.Context, realm, alias string, s *OrganizationOwnershipSnapshot) error {
	listed, err := c.InventoryOrganizations(ctx, realm)
	if err != nil {
		return err
	}
	for _, o := range listed {
		if o.Alias != alias {
			continue
		}
		if s.Organization != nil || o.ID == "" {
			return ErrAdoptionPrecondition
		}
		if err := c.get(ctx, organizationEndpoint(realm, o.ID), &s.native); err != nil {
			return err
		}
		s.Organization = &Organization{}
		if err := decodeSnapshot(s.native, s.Organization); err != nil {
			return err
		}
		if s.Organization.ID != o.ID || s.Organization.Alias != alias {
			return ErrAdoptionPrecondition
		}
		s.Links, err = c.OrganizationIdentityProviderAliases(ctx, realm, o.ID)
		if err != nil {
			return err
		}
	}
	if s.Organization == nil {
		return ErrAdoptionPrecondition
	}
	return nil
}

func (s *OrganizationOwnershipSnapshot) SameSemantics(other *OrganizationOwnershipSnapshot) bool {
	return s != nil && other != nil && s.ParentID == other.ParentID &&
		reflect.DeepEqual(withoutAcquisition(s.group), withoutAcquisition(other.group)) &&
		reflect.DeepEqual(withoutAcquisition(s.native), withoutAcquisition(other.native)) &&
		sameUnorderedDocuments(s.Children, other.Children) && sameUnorderedDocuments(s.Roles, other.Roles) &&
		slices.Equal(semanticSet(s.Links), semanticSet(other.Links))
}

func sameUnorderedDocuments[T any](a, b []T) bool {
	canonical := func(items []T) []string {
		result := make([]string, 0, len(items))
		for _, item := range items {
			data, _ := json.Marshal(item)
			result = append(result, string(data))
		}
		slices.Sort(result)
		return result
	}
	return slices.Equal(canonical(a), canonical(b))
}

func OrganizationUnmarked(attributes map[string][]string) bool {
	for key := range attributes {
		if adoption.ReservedAttribute(key) {
			return false
		}
	}
	return true
}
func OrganizationExactReceipt(attributes map[string][]string, name, namespace, uid, receipt string) bool {
	if !organization.StrictOwnership(attributes, name, namespace, uid) || !slices.Equal(attributes[adoption.ReceiptKey], []string{receipt}) {
		return false
	}
	for key := range attributes {
		if adoption.ReservedAttribute(key) && key != organization.OwnerName && key != organization.OwnerNamespace && key != organization.OwnerUID && key != adoption.ReceiptKey {
			return false
		}
	}
	return true
}

func OrganizationOwned(attributes map[string][]string, name, namespace, uid string) bool {
	if !organization.StrictOwnership(attributes, name, namespace, uid) {
		return false
	}
	for key := range attributes {
		if adoption.ReservedAttribute(key) && key != organization.OwnerName && key != organization.OwnerNamespace && key != organization.OwnerUID && key != adoption.ReceiptKey {
			return false
		}
	}
	return true
}

// Each member has its own checkpoint. A fresh representation must still match;
// existing exact receipts are idempotent. The controller handles lost ACK by
// read-back, never rollback or an unconditional second PUT.
func (c *Client) MarkOrganizationMemberAdoption(ctx context.Context, realm string, expected *OrganizationOwnershipSnapshot, native bool, name, namespace, uid, receipt string) error {
	proof, err := adoption.ParseReceipt(receipt)
	if err != nil || proof.TargetKind != "HankoOrganization" || proof.TargetUID != uid || expected == nil {
		return ErrAdoptionPrecondition
	}
	path, document := groupEndpoint(realm, expected.Group.ID), expected.group
	if native {
		if expected.Organization == nil {
			return ErrAdoptionPrecondition
		}
		path, document = organizationEndpoint(realm, expected.Organization.ID), expected.native
	}
	var current map[string]any
	if err := c.get(ctx, path, &current); err != nil {
		return err
	}
	delete(current, "access")
	if !reflect.DeepEqual(withoutAcquisition(document), withoutAcquisition(current)) {
		return ErrAdoptionPrecondition
	}
	acquired, err := organizationMarkableAttributes(current, name, namespace, uid, receipt)
	if err != nil {
		return err
	}
	if acquired {
		return nil
	}
	attrs, _ := current["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[organization.OwnerName], attrs[organization.OwnerNamespace], attrs[organization.OwnerUID] = []string{name}, []string{namespace}, []string{uid}
	attrs[adoption.ReceiptKey] = []string{receipt}
	current["attributes"] = attrs
	if !native {
		// Hierarchy, children and role mappings have separate Admin APIs. Omit
		// their read-only representation fields from the attribute checkpoint.
		for _, key := range []string{"path", "parentId", "subGroups", "subGroupCount", "realmRoles", "clientRoles"} {
			delete(current, key)
		}
	}
	return c.putJSON(ctx, path, current)
}

func organizationMarkableAttributes(current map[string]any, name, namespace, uid, receipt string) (bool, error) {
	var rep struct {
		Attributes map[string][]string `json:"attributes"`
	}
	data, err := json.Marshal(current)
	if err != nil || json.Unmarshal(data, &rep) != nil {
		return false, ErrAdoptionPrecondition
	}
	if OrganizationExactReceipt(rep.Attributes, name, namespace, uid, receipt) {
		return true, nil
	}
	_, present := rep.Attributes[adoption.ReceiptKey]
	if !OrganizationUnmarked(rep.Attributes) && (!OrganizationOwned(rep.Attributes, name, namespace, uid) || present) {
		return false, ErrAdoptionPrecondition
	}
	return false, nil
}

// Membership reads are cleanup-only and return existence, never identities.
func (c *Client) HasGroupMembers(ctx context.Context, realm, id string) (bool, error) {
	return c.hasMembers(ctx, groupEndpoint(realm, id)+"/members?first=0&max=1&briefRepresentation=true")
}
func (c *Client) HasOrganizationMembers(ctx context.Context, realm, id string) (bool, error) {
	return c.hasMembers(ctx, organizationEndpoint(realm, id)+"/members?first=0&max=1")
}
func (c *Client) hasMembers(ctx context.Context, path string) (bool, error) {
	var members []json.RawMessage
	if err := c.get(ctx, path, &members); err != nil {
		return false, err
	}
	if len(members) > 1 {
		return false, ErrAuthorizationReadLimit
	}
	return len(members) != 0, nil
}

func (c *Client) OrganizationIdentityProviderAliases(ctx context.Context, realm, id string) ([]string, error) {
	var links []struct {
		Alias string `json:"alias"`
	}
	if err := c.get(ctx, organizationEndpoint(realm, id)+identityProvidersSegment, &links); err != nil {
		return nil, err
	}
	if len(links) > 64 {
		return nil, ErrAuthorizationReadLimit
	}
	result := []string{}
	for _, link := range links {
		if link.Alias == "" || len(link.Alias) > adoption.MaxReferenceBytes || slices.Contains(result, link.Alias) {
			return nil, ErrAdoptionPrecondition
		}
		result = append(result, link.Alias)
	}
	return result, nil
}

func (s *OrganizationOwnershipSnapshot) QualifiedRoots() bool {
	if s == nil {
		return false
	}
	groupFields := map[string]bool{"id": true, "name": true, "path": true, "parentId": true, "attributes": true, "subGroups": true, "subGroupCount": true, "realmRoles": true, "clientRoles": true}
	nativeFields := map[string]bool{"id": true, "name": true, "alias": true, "enabled": true, "domains": true, "attributes": true, "description": true}
	for key := range s.group {
		if !groupFields[key] {
			return false
		}
	}
	for key, value := range s.native {
		if !nativeFields[key] || key == "description" && value != "" && value != nil {
			return false
		}
	}
	return true
}
