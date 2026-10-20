package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

const authorizationPageSize = 100
const MaxAuthorizationCollectionObjects = 1024

var ErrAuthorizationReadLimit = errors.New("authorization collection cannot be observed completely within its read budget")

type authorizationCollectionIdentity interface {
	authorizationIdentity() (string, string)
}

func (v authorizationScopeRepresentation) authorizationIdentity() (string, string) {
	return v.ID, v.Name
}
func (v authorizationResourceRepresentation) authorizationIdentity() (string, string) {
	return v.ID, v.Name
}
func (v authorizationPolicyRepresentation) authorizationIdentity() (string, string) {
	return v.ID, v.Name
}
func (v authorizationPermissionRepresentation) authorizationIdentity() (string, string) {
	return v.ID, v.Name
}

func validateAuthorizationIdentities[T any](items []T, ids, names map[string]bool) error {
	for _, item := range items {
		if identity, ok := any(item).(authorizationCollectionIdentity); ok {
			id, name := identity.authorizationIdentity()
			if id == "" || name == "" || ids[id] || names[name] {
				return ErrAuthorizationReadLimit
			}
			ids[id], names[name] = true, true
		}
	}
	return nil
}

// Keycloak defaults these collections to 100 entries. Read every page before
// exposing the result to comparison or deletion; a partial list proves neither
// absence nor absence of unowned objects. Existing per-response byte limits apply.
func readAuthorizationCollection[T any](ctx context.Context, c *Client, path string, target *[]T) error {
	endpoint, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("parse authorization collection route: %w", err)
	}
	query := endpoint.Query()
	result := []T{}
	ids, names := map[string]bool{}, map[string]bool{}
	for first := 0; ; first += authorizationPageSize {
		query.Set("first", strconv.Itoa(first))
		query.Set("max", strconv.Itoa(authorizationPageSize))
		endpoint.RawQuery = query.Encode()
		var page []T
		if err := c.get(ctx, endpoint.String(), &page); err != nil {
			return err
		}
		if page == nil || len(page) > authorizationPageSize || len(result)+len(page) > MaxAuthorizationCollectionObjects {
			return ErrAuthorizationReadLimit
		}
		if err := validateAuthorizationIdentities(page, ids, names); err != nil {
			return err
		}
		result = append(result, page...)
		if len(page) < authorizationPageSize {
			*target = result
			return nil
		}
	}
}
