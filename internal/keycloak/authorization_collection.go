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
	for first := 0; ; first += authorizationPageSize {
		query.Set("first", strconv.Itoa(first))
		query.Set("max", strconv.Itoa(authorizationPageSize))
		endpoint.RawQuery = query.Encode()
		var page []T
		if err := c.get(ctx, endpoint.String(), &page); err != nil {
			return err
		}
		if len(page) > authorizationPageSize || len(result)+len(page) > MaxAuthorizationCollectionObjects {
			return ErrAuthorizationReadLimit
		}
		result = append(result, page...)
		if len(page) < authorizationPageSize {
			*target = result
			return nil
		}
	}
}
