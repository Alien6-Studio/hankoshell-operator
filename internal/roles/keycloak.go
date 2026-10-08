package roles

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

type KeycloakDriver struct{ client *keycloak.Client }

func NewKeycloakDriver(c *keycloak.Client) *KeycloakDriver { return &KeycloakDriver{client: c} }
func (*KeycloakDriver) Capabilities(context.Context) (CapabilityEvidence, error) {
	return KeycloakEvidence(), nil
}
func (d *KeycloakDriver) AuthorityClosure(ctx context.Context, realm, name string) ([]string, error) {
	closure, err := d.client.GetRealmRoleClosure(ctx, realm, name)
	if keycloak.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, iamcontract.SafeError(err)
	}
	names := make([]string, 0, len(closure))
	for _, r := range closure {
		names = append(names, r.Name)
	}
	return names, nil
}
func owned(role *keycloak.RealmRole, p Plan) bool {
	return slices.Equal(role.Attributes[OwnerAttribute], []string{p.resolved.Owner})
}
func desired(p Plan) keycloak.RealmRole {
	attrs := cloneAttributes(p.resolved.Attributes)
	attrs[OwnerAttribute] = []string{p.resolved.Owner}
	return keycloak.RealmRole{Name: p.intent.Name, Description: p.intent.Description, Composite: p.intent.Composite, Attributes: attrs}
}
func (d *KeycloakDriver) Observe(ctx context.Context, p Plan) (State, error) {
	if err := p.Validate(p); err != nil {
		return State{}, err
	}
	got, err := d.client.GetRealmRole(ctx, p.resolved.Realm, p.intent.Name)
	if keycloak.IsNotFound(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, iamcontract.SafeError(err)
	}
	want := desired(p)
	state := State{Present: true, Owned: owned(got, p), Drifted: got.Description != want.Description || got.Composite != want.Composite || !maps.EqualFunc(cloneAttributes(got.Attributes), want.Attributes, slices.Equal[[]string])}
	if len(p.intent.Composites) > 0 {
		closure, err := d.AuthorityClosure(ctx, p.resolved.Realm, p.intent.Name)
		if err != nil {
			return State{}, err
		}
		for _, c := range p.intent.Composites {
			state.Drifted = state.Drifted || !slices.Contains(closure, c)
		}
	}
	return state, nil
}
func (d *KeycloakDriver) Reconcile(ctx context.Context, p Plan) (State, error) {
	if err := p.Validate(p); err != nil {
		return State{}, err
	}
	state, err := d.Observe(ctx, p)
	if err != nil {
		return State{}, err
	}
	if state.Present && !state.Owned {
		return State{}, ErrOwnershipConflict
	}
	if !state.Present || state.Drifted {
		if err := d.apply(ctx, p); err != nil {
			return State{}, err
		}
	}
	return d.Observe(ctx, p)
}
func (d *KeycloakDriver) apply(ctx context.Context, p Plan) error {
	// Resolve all child roles before any mutation. Provider IDs stay in this adapter.
	for _, c := range p.intent.Composites {
		if _, err := d.client.GetRealmRole(ctx, p.resolved.Realm, c); err != nil {
			return iamcontract.SafeError(err)
		}
	}
	if err := d.client.SyncRealmRoleIfOwned(ctx, p.resolved.Realm, desired(p), OwnerAttribute, p.resolved.Owner); err != nil {
		if errors.Is(err, keycloak.ErrRoleOwnershipConflict) {
			return ErrOwnershipConflict
		}
		return iamcontract.SafeError(err)
	}
	// A provider POST collision is an error, never implicit adoption. Read back
	// ownership before applying composites or authorizing future deletion.
	got, err := d.client.GetRealmRole(ctx, p.resolved.Realm, p.intent.Name)
	if err != nil {
		return iamcontract.SafeError(err)
	}
	if !owned(got, p) {
		return ErrOwnershipConflict
	}
	return iamcontract.SafeError(d.client.EnsureRealmRoleComposites(ctx, p.resolved.Realm, p.intent.Name, p.intent.Composites))
}

func (d *KeycloakDriver) DeleteOwned(ctx context.Context, p Plan) error {
	if err := p.Validate(p); err != nil {
		return err
	}
	got, err := d.client.GetRealmRole(ctx, p.resolved.Realm, p.intent.Name)
	if keycloak.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return iamcontract.SafeError(err)
	}
	if !owned(got, p) {
		return ErrOwnershipConflict
	}
	err = d.client.DeleteRealmRole(ctx, p.resolved.Realm, p.intent.Name)

	return iamcontract.SafeError(err)
}
