package keycloak

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

type boundedDelegationOperationKey struct{}
type boundedDelegationOperation struct{ ownerUID string }

type boundedDelegationActorMarker struct {
	Version          int                      `json:"version"`
	Actor            BoundedDelegationBinding `json:"actor"`
	PreviousExchange string                   `json:"previousExchange"`
	ExchangePresent  bool                     `json:"exchangePresent"`
	Owners           map[string]string        `json:"owners"`
}

// Known sibling envelopes do not invalidate the client's own UID marker. Their
// version, shape and self binding must still be proven; an arbitrary reserved
// attribute never becomes an ownership grant or an adoption exception.
func boundedClientEnvelope(app *Application, uid, attribute string) bool {
	if app == nil || app.ID == "" || uid == "" {
		return false
	}
	if raw, present := app.Attributes[BoundedDelegationAttribute]; present {
		if attribute != adoption.ApplicationOwnerKey || len(raw) > 128*1024 || httpsecurity.ValidateJSON([]byte(raw)) != nil {
			return false
		}
		var document BoundedDelegationDocument
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&document) != nil || document.Audience != (BoundedDelegationBinding{ID: app.ID, Attribute: attribute, Value: uid}) {
			return false
		}
		if _, err := boundedDelegationJSON(document); err != nil {
			return false
		}
	}
	if raw, present := app.Attributes[BoundedDelegationActorAttribute]; present {
		return boundedActorEnvelope(raw, BoundedDelegationBinding{ID: app.ID, Attribute: attribute, Value: uid})
	}
	return true
}

func boundedActorEnvelope(raw string, actor BoundedDelegationBinding) bool {
	if len(raw) > 32*1024 || httpsecurity.ValidateJSON([]byte(raw)) != nil {
		return false
	}
	var marker boundedDelegationActorMarker
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&marker) == nil && validBoundedActorMarker(marker) && marker.Actor == actor
}

// beginBoundedDelegation serializes sibling delegation transactions using the
// same credential connection, including guarded views. Waiting is cancelable.
func (c *Client) beginBoundedDelegation(ctx context.Context) (func(), error) {
	c.mu.Lock()
	if c.delegationTransaction == nil {
		c.delegationTransaction = make(chan struct{}, 1)
	}
	queue := c.delegationTransaction
	c.mu.Unlock()
	select {
	case queue <- struct{}{}:
		return func() { <-queue }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func boundedDelegationInProgress(ctx context.Context, uid string) bool {
	witness, ok := ctx.Value(boundedDelegationOperationKey{}).(boundedDelegationOperation)
	return ok && uid != "" && witness.ownerUID == uid
}

// ApplyBoundedDelegation keeps the grant inactive through prepare, ordinary
// resource reconciliation and read-back. Only Committed is executable by the SPI.
func (c *Client) ApplyBoundedDelegation(ctx context.Context, model AuthorizationModel, prepared BoundedDelegationPreparation,
	owned AuthorizationManagedObjects, revision string,
) (AuthorizationState, error) {
	if !validBoundedRevision(revision) || prepared.Document.OwnerUID != model.OwnerUID || prepared.Document.Audience.ID == "" {
		return AuthorizationState{}, ErrBoundedDelegationUnsupported
	}
	release, err := c.beginBoundedDelegation(ctx)
	if err != nil {
		return AuthorizationState{}, err
	}
	defer release()
	document := prepared.Document
	document.Revision = revision
	if _, err := boundedDelegationJSON(document); err != nil {
		return AuthorizationState{}, err
	}
	document, err = c.prepareBoundedTransaction(ctx, model.Realm, document)
	if err != nil {
		return AuthorizationState{}, err
	}
	for _, actor := range boundedActors(document) {
		if err := c.ensureBoundedActor(ctx, model.Realm, actor, document.Audience.ID, document.OwnerUID); err != nil {
			return AuthorizationState{}, err
		}
	}
	operation := context.WithValue(ctx, boundedDelegationOperationKey{}, boundedDelegationOperation{ownerUID: model.OwnerUID})
	state, err := c.ReconcileAuthorization(operation, model, owned)
	if err != nil {
		return state, err
	}
	return state, c.commitBoundedTransaction(operation, model, document, state.ManagedObjects)
}

func (c *Client) prepareBoundedTransaction(ctx context.Context, realm string, document BoundedDelegationDocument) (BoundedDelegationDocument, error) {
	// Validate all shared actor markers before the first native write.
	for _, actor := range boundedActors(document) {
		current, err := c.readBoundedClient(ctx, realm, actor)
		if err != nil {
			return document, err
		}
		if _, err := parseBoundedActorMarker(current, actor, document.Audience.ID, document.OwnerUID); err != nil {
			return document, err
		}
	}
	current, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return document, err
	}
	existing, err := ownedBoundedDocument(current, document.OwnerUID)
	if err != nil {
		return document, err
	}
	if existing != nil {
		document.RetiredActors = slices.Clone(existing.RetiredActors)
		for _, actor := range boundedActors(*existing) {
			if !slices.Contains(boundedActors(document), actor) && !slices.Contains(document.RetiredActors, actor) {
				document.RetiredActors = append(document.RetiredActors, actor)
			}
		}
	}
	if existing == nil || existing.Revision != document.Revision {
		document.Phase = "Prepared"
		if err := c.saveBoundedDocument(ctx, realm, document); err != nil {
			return document, err
		}
	}
	return document, nil
}

func (c *Client) commitBoundedTransaction(ctx context.Context, model AuthorizationModel, document BoundedDelegationDocument, owned AuthorizationManagedObjects) error {
	for _, actor := range document.RetiredActors {
		if err := c.releaseBoundedActor(ctx, model.Realm, actor, document.Audience.ID, document.OwnerUID); err != nil {
			return err
		}
	}
	document.RetiredActors = nil
	document, err := materializeBoundedDocument(document, owned)
	if err != nil {
		return err
	}
	if err := c.advanceBoundedDocument(ctx, model.Realm, document, "Applied"); err != nil {
		return err
	}
	observed, err := c.ObserveAuthorization(ctx, model)
	if err != nil {
		return err
	}
	if !observed.Observation.Complete || observed.Drifted {
		return ErrAuthorizationReadBack
	}
	for _, actor := range boundedActors(document) {
		current, err := c.readBoundedClient(ctx, model.Realm, actor)
		if err != nil {
			return err
		}
		marker, err := parseBoundedActorMarker(current, actor, document.Audience.ID, document.OwnerUID)
		attrs, _ := current["attributes"].(map[string]any)
		if err != nil || marker.Owners[document.Audience.ID] != document.OwnerUID || attrs["standard.token.exchange.enabled"] != "true" {
			return ErrAuthorizationReadBack
		}
	}
	if err := c.advanceBoundedDocument(ctx, model.Realm, document, "Verified"); err != nil {
		return err
	}
	return c.advanceBoundedDocument(ctx, model.Realm, document, "Committed")
}

func materializeBoundedDocument(document BoundedDelegationDocument, owned AuthorizationManagedObjects) (BoundedDelegationDocument, error) {
	if document.Audience.ID != owned.ResourceServerID {
		return document, ErrAuthorizationOwnershipConflict
	}
	resources := map[string]string{}
	for _, resource := range owned.Resources {
		resources[resource.Name] = resource.ID
	}
	document.Grants = slices.Clone(document.Grants)
	for i := range document.Grants {
		mapped := map[string][]string{}
		for name, scopes := range document.Grants[i].Authority.Permissions {
			id := resources[name]
			if id == "" {
				return document, ErrAuthorizationReadBack
			}
			mapped[id] = slices.Clone(scopes)
		}
		document.Grants[i].Authority.Permissions = mapped
	}
	return document, nil
}

func (c *Client) ObserveBoundedDelegation(ctx context.Context, model AuthorizationModel, prepared BoundedDelegationPreparation,
	owned AuthorizationManagedObjects, revision string,
) (bool, string, error) {
	current, err := c.readBoundedClient(ctx, model.Realm, prepared.Document.Audience)
	if err != nil {
		return false, "", err
	}
	document, err := ownedBoundedDocument(current, model.OwnerUID)
	if err != nil || document == nil {
		return false, "", err
	}
	want, err := materializeBoundedDocument(prepared.Document, owned)
	if err != nil {
		return false, "", err
	}
	want.Phase, want.Revision = "Committed", revision
	left, _ := boundedDelegationJSON(want)
	right, err := boundedDelegationJSON(*document)
	if err != nil {
		return false, "", err
	}
	for _, actor := range boundedActors(want) {
		current, err := c.readBoundedClient(ctx, model.Realm, actor)
		if err != nil {
			return false, "", err
		}
		marker, err := parseBoundedActorMarker(current, actor, want.Audience.ID, want.OwnerUID)
		attrs, _ := current["attributes"].(map[string]any)
		if err != nil || marker.Owners[want.Audience.ID] != want.OwnerUID || attrs["standard.token.exchange.enabled"] != "true" {
			return false, boundedDigest(right), err
		}
	}
	return bytes.Equal(left, right), boundedDigest(right), nil
}

func (c *Client) ObserveBoundedAuthorization(ctx context.Context, model AuthorizationModel) (AuthorizationState, error) {
	operation := context.WithValue(ctx, boundedDelegationOperationKey{}, boundedDelegationOperation{ownerUID: model.OwnerUID})
	state, err := c.ObserveAuthorization(operation, model)
	if err != nil {
		return state, err
	}
	owned, _, err := c.readAuthorizationOwnership(ctx, model, state.ResourceServerID)
	state.ManagedObjects = owned
	return state, err
}

func (c *Client) advanceBoundedDocument(ctx context.Context, realm string, document BoundedDelegationDocument, phase string) error {
	current, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return err
	}
	existing, err := ownedBoundedDocument(current, document.OwnerUID)
	if err != nil {
		return err
	}
	if existing != nil && existing.Revision == document.Revision {
		candidate := *existing
		candidate.Phase = phase
		document.Phase = phase
		a, _ := boundedDelegationJSON(candidate)
		b, _ := boundedDelegationJSON(document)
		if bytes.Equal(a, b) && boundedPhase(existing.Phase) >= boundedPhase(phase) {
			return nil
		}
	}
	document.Phase = phase
	return c.saveBoundedDocument(ctx, realm, document)
}

func (c *Client) saveBoundedDocument(ctx context.Context, realm string, document BoundedDelegationDocument) error {
	encoded, err := boundedDelegationJSON(document)
	if err != nil {
		return err
	}
	current, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return err
	}
	if _, err := ownedBoundedDocument(current, document.OwnerUID); err != nil {
		return err
	}
	attrs, _ := current["attributes"].(map[string]any)
	if attrs == nil {
		return ErrAuthorizationOwnershipConflict
	}
	if attrs[BoundedDelegationAttribute] == string(encoded) {
		return nil
	}
	attrs[BoundedDelegationAttribute] = string(encoded)
	if err := c.putJSON(ctx, applicationPath(realm, document.Audience.ID), current); err != nil {
		return err
	}
	next, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return err
	}
	nextAttrs, _ := next["attributes"].(map[string]any)
	if nextAttrs[BoundedDelegationAttribute] != string(encoded) {
		return fmt.Errorf("bounded delegation phase read-back: %w", ErrAuthorizationReadBack)
	}
	return nil
}

func (c *Client) readBoundedClient(ctx context.Context, realm string, binding BoundedDelegationBinding) (map[string]any, error) {
	var current map[string]any
	if binding.ID == "" || binding.Value == "" || (binding.Attribute != adoption.ApplicationOwnerKey && binding.Attribute != adoption.ClientOwnerUIDKey) {
		return nil, ErrAuthorizationOwnershipConflict
	}
	if err := c.get(ctx, applicationPath(realm, binding.ID), &current); err != nil {
		return nil, err
	}
	attrs, _ := current["attributes"].(map[string]any)
	if current["id"] != binding.ID || current["protocol"] != "openid-connect" || attrs[binding.Attribute] != binding.Value || attrs[adoption.ReceiptKey] != nil {
		return nil, ErrAuthorizationOwnershipConflict
	}
	if binding.Attribute == adoption.ClientOwnerUIDKey && attrs[adoption.ClientOwnerKindKey] != "HankoServiceAccount" {
		return nil, ErrAuthorizationOwnershipConflict
	}
	return current, nil
}

func ownedBoundedDocument(current map[string]any, owner string) (*BoundedDelegationDocument, error) {
	attrs, _ := current["attributes"].(map[string]any)
	value, present := attrs[BoundedDelegationAttribute]
	if !present {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok || len(text) > 128*1024 || httpsecurity.ValidateJSON([]byte(text)) != nil {
		return nil, ErrAuthorizationOwnershipConflict
	}
	var document BoundedDelegationDocument
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.OwnerUID != owner || document.Audience.ID != current["id"] {
		return nil, ErrAuthorizationOwnershipConflict
	}
	if _, err := boundedDelegationJSON(document); err != nil {
		return nil, ErrAuthorizationOwnershipConflict
	}
	return &document, nil
}

func boundedDelegationJSON(document BoundedDelegationDocument) ([]byte, error) {
	if !validBoundedDocumentHeader(document) {
		return nil, ErrBoundedDelegationUnsupported
	}
	names, pairs := map[string]bool{}, map[string]bool{}
	for _, grant := range document.Grants {
		pair := grant.Actor.ID + "\x00" + grant.Subject.ID
		if names[grant.Name] || pairs[pair] || !validBoundedGrant(grant, document.Audience.ID) {
			return nil, ErrBoundedDelegationUnsupported
		}
		names[grant.Name], pairs[pair] = true, true
	}
	for _, actor := range document.RetiredActors {
		if !validBoundedBinding(actor) {
			return nil, ErrBoundedDelegationUnsupported
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 128*1024 {
		return nil, ErrBoundedDelegationUnsupported
	}
	return encoded, nil
}

func validBoundedDocumentHeader(document BoundedDelegationDocument) bool {
	return document.Version == 1 && boundedPhase(document.Phase) != 0 && validBoundedName(document.OwnerUID, 128) &&
		validBoundedName(document.RealmID, 128) && validBoundedRevision(document.Revision) && len(document.Grants) > 0 && len(document.Grants) <= 128 &&
		len(document.RetiredActors) <= 128 && validBoundedBinding(document.Audience) && document.Audience.Attribute == adoption.ApplicationOwnerKey
}

func validBoundedGrant(grant BoundedDelegationGrant, audience string) bool {
	if !validBoundedName(grant.Name, 255) || !validBoundedBinding(grant.Actor) || !validBoundedBinding(grant.Subject) ||
		grant.Actor.ID == grant.Subject.ID || grant.Actor.ID == audience || grant.Subject.ID == audience ||
		grant.MaxDepth < 1 || grant.MaxDepth > 4 || grant.MaxTTLSeconds < 1 || grant.MaxTTLSeconds > 600 {
		return false
	}
	return validBoundedAuthority(grant.Authority) && validBoundedConditions(grant.Conditions)
}

func validBoundedAuthority(authority BoundedDelegationAuthority) bool {
	if authority.Scopes == nil || authority.RealmRoles == nil || authority.ClientRoles == nil || len(authority.Permissions) == 0 || len(authority.Permissions) > 64 {
		return false
	}
	if len(authority.Scopes) != 0 || len(authority.RealmRoles) != 0 || len(authority.ClientRoles) != 0 {
		return false
	}
	for resource, scopes := range authority.Permissions {
		if !validBoundedName(resource, 255) || len(scopes) == 0 || len(scopes) > 64 {
			return false
		}
		for _, scope := range scopes {
			if !validBoundedName(scope, 255) {
				return false
			}
		}
	}
	return true
}

func validBoundedConditions(conditions []BoundedDelegationCondition) bool {
	if len(conditions) == 0 || len(conditions) > 128 {
		return false
	}
	for _, condition := range conditions {
		if !validBoundedCondition(condition) {
			return false
		}
	}
	return true
}

func validBoundedCondition(condition BoundedDelegationCondition) bool {
	if !validBoundedName(condition.ID, 128) {
		return false
	}
	switch condition.Kind {
	case "client":
		return validBoundedBinding(BoundedDelegationBinding{ID: condition.ID, Attribute: condition.Attribute, Value: condition.Value})
	case "role":
		return condition.Attribute == "" && condition.Value == ""
	case "group":
		return condition.Attribute == "hanko.sh/organization-uid" && validBoundedName(condition.Value, 128)
	default:
		return false
	}
}

func validBoundedName(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func validBoundedBinding(binding BoundedDelegationBinding) bool {
	return validBoundedName(binding.ID, 128) && validBoundedName(binding.Value, 128) &&
		(binding.Attribute == adoption.ApplicationOwnerKey || binding.Attribute == adoption.ClientOwnerUIDKey)
}

func validBoundedActorMarker(marker boundedDelegationActorMarker) bool {
	if marker.Version != 1 || !validBoundedBinding(marker.Actor) || len(marker.PreviousExchange) > 32 ||
		strings.ContainsFunc(marker.PreviousExchange, unicode.IsControl) || len(marker.Owners) == 0 || len(marker.Owners) > 128 {
		return false
	}
	for id, owner := range marker.Owners {
		if !validBoundedName(id, 128) || !validBoundedName(owner, 128) {
			return false
		}
	}
	return true
}

func boundedPhase(value string) int {
	return map[string]int{"Prepared": 1, "Applied": 2, "Verified": 3, "Committed": 4}[value]
}

func validBoundedRevision(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && value == strings.ToLower(value)
}

func boundedActors(document BoundedDelegationDocument) []BoundedDelegationBinding {
	actors := []BoundedDelegationBinding{}
	for _, grant := range document.Grants {
		if !slices.Contains(actors, grant.Actor) {
			actors = append(actors, grant.Actor)
		}
	}
	slices.SortFunc(actors, func(a, b BoundedDelegationBinding) int { return strings.Compare(a.ID, b.ID) })
	return actors
}

func parseBoundedActorMarker(current map[string]any, actor BoundedDelegationBinding, audienceID, owner string) (boundedDelegationActorMarker, error) {
	attrs, _ := current["attributes"].(map[string]any)
	marker := boundedDelegationActorMarker{Version: 1, Actor: actor, Owners: map[string]string{}}
	if raw, exists := attrs["standard.token.exchange.enabled"]; exists {
		var ok bool
		marker.PreviousExchange, ok = raw.(string)
		if !ok || len(marker.PreviousExchange) > 32 {
			return marker, ErrAuthorizationOwnershipConflict
		}
		marker.ExchangePresent = true
	}
	if value, present := attrs[BoundedDelegationActorAttribute]; present {
		text, ok := value.(string)
		if !ok || len(text) > 32*1024 || httpsecurity.ValidateJSON([]byte(text)) != nil {
			return marker, ErrAuthorizationOwnershipConflict
		}
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.DisallowUnknownFields()
		// Existing state must supply its own identity. Decoding over the fresh
		// initialization marker would fill absent/null fields from the caller.
		var stored boundedDelegationActorMarker
		if decoder.Decode(&stored) != nil || !validBoundedActorMarker(stored) || stored.Actor != actor {
			return marker, ErrAuthorizationOwnershipConflict
		}
		marker = stored
	}
	if previous, exists := marker.Owners[audienceID]; exists && previous != owner {
		return marker, ErrAuthorizationOwnershipConflict
	}
	return marker, nil
}

func (c *Client) ensureBoundedActor(ctx context.Context, realm string, actor BoundedDelegationBinding, audienceID, owner string) error {
	current, err := c.readBoundedClient(ctx, realm, actor)
	if err != nil {
		return err
	}
	marker, err := parseBoundedActorMarker(current, actor, audienceID, owner)
	if err != nil {
		return err
	}
	if _, exists := marker.Owners[audienceID]; !exists && len(marker.Owners) >= 128 {
		return ErrAuthorizationReadLimit
	}
	marker.Owners[audienceID] = owner
	encoded, _ := json.Marshal(marker)
	attrs, _ := current["attributes"].(map[string]any)
	if attrs[BoundedDelegationActorAttribute] == string(encoded) && attrs["standard.token.exchange.enabled"] == "true" {
		return nil
	}
	attrs[BoundedDelegationActorAttribute], attrs["standard.token.exchange.enabled"] = string(encoded), "true"
	return c.putJSON(ctx, applicationPath(realm, actor.ID), current)
}

// CleanupBoundedDelegation first disables new issuance, then releases only this
// owner's shared actor entries. It neither deletes clients nor revokes sessions.
func (c *Client) CleanupBoundedDelegation(ctx context.Context, realm, owner string, representation map[string]any) error {
	document, err := ownedBoundedDocument(representation, owner)
	if err != nil || document == nil {
		return err
	}
	release, err := c.beginBoundedDelegation(ctx)
	if err != nil {
		return err
	}
	defer release()
	document.Phase = "Prepared"
	if err := c.saveBoundedDocument(ctx, realm, *document); err != nil {
		return err
	}
	for _, actor := range append(boundedActors(*document), document.RetiredActors...) {
		if err := c.releaseBoundedActor(ctx, realm, actor, document.Audience.ID, owner); err != nil {
			return err
		}
	}
	return c.removeBoundedDocument(ctx, realm, owner, *document, representation)
}

func (c *Client) removeBoundedDocument(ctx context.Context, realm, owner string, document BoundedDelegationDocument, representation map[string]any) error {
	current, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return err
	}
	existing, err := ownedBoundedDocument(current, owner)
	if err != nil || existing == nil {
		return err
	}
	if existing.Revision != document.Revision || existing.Phase != "Prepared" {
		return ErrAuthorizationOwnershipConflict
	}
	attrs, _ := current["attributes"].(map[string]any)
	// Keycloak client PUT merges attributes: omission retains the old value.
	// An explicit null removes this exact owned key.
	attrs[BoundedDelegationAttribute] = nil
	if err := c.putJSON(ctx, applicationPath(realm, document.Audience.ID), current); err != nil {
		return err
	}
	fresh, err := c.readBoundedClient(ctx, realm, document.Audience)
	if err != nil {
		return err
	}
	freshAttrs, _ := fresh["attributes"].(map[string]any)
	if _, present := freshAttrs[BoundedDelegationAttribute]; present {
		return fmt.Errorf("bounded delegation removal read-back: %w", ErrAuthorizationReadBack)
	}
	// The caller may subsequently disable the ordinary authorization service.
	// Refresh its snapshot so that operation cannot resurrect the deleted grant.
	for key := range representation {
		delete(representation, key)
	}
	for key, value := range fresh {
		representation[key] = value
	}
	return nil
}

func (c *Client) releaseBoundedActor(ctx context.Context, realm string, actor BoundedDelegationBinding, audienceID, owner string) error {
	current, err := c.readBoundedClient(ctx, realm, actor)
	if IsNotFound(err) || errors.Is(err, ErrAuthorizationOwnershipConflict) {
		// An identity replaced since apply is foreign; disabling this owned
		// resource grant is still safe, mutating the replacement is not.
		return nil
	}
	if err != nil {
		return err
	}
	marker, err := parseBoundedActorMarker(current, actor, audienceID, owner)
	if err != nil {
		return err
	}
	if marker.Owners[audienceID] == "" {
		return nil
	}
	delete(marker.Owners, audienceID)
	attrs, _ := current["attributes"].(map[string]any)
	if len(marker.Owners) == 0 {
		attrs[BoundedDelegationActorAttribute] = nil
		if attrs["standard.token.exchange.enabled"] != "true" {
			return fmt.Errorf("%w: exchange setting changed during cleanup", ErrAuthorizationOwnershipConflict)
		}
		if marker.ExchangePresent {
			attrs["standard.token.exchange.enabled"] = marker.PreviousExchange
		} else {
			attrs["standard.token.exchange.enabled"] = nil
		}
	} else {
		encoded, _ := json.Marshal(marker)
		attrs[BoundedDelegationActorAttribute] = string(encoded)
	}
	return c.putJSON(ctx, applicationPath(realm, actor.ID), current)
}
