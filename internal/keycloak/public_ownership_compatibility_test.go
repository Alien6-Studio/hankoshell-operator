package keycloak

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestPublicAuthorizationJournalBackwardReadability(t *testing.T) {
	data, err := os.ReadFile("../iamconformance/testdata/public-initial/ownership.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AuthorizationAttribute     string               `json:"authorizationAttribute"`
		OwnerUID                   string               `json:"ownerUID"`
		LegacyAuthorizationJournal authorizationJournal `json:"legacyAuthorizationJournal"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.AuthorizationAttribute != authorizationOwnerAttribute {
		t.Fatal("public ownership marker changed without migration and reader fixtures")
	}
	journal := fixture.LegacyAuthorizationJournal
	check := func(j authorizationJournal, owner string) (AuthorizationManagedObjects, bool, error) {
		encoded, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		return parseAuthorizationJournal(map[string]any{"attributes": map[string]any{fixture.AuthorizationAttribute: string(encoded)}}, owner, journal.Objects.ResourceServerID)
	}
	got, found, err := check(journal, fixture.OwnerUID)
	if err != nil || !found || !reflect.DeepEqual(got, journal.Objects) {
		t.Fatalf("frozen legacy ownership is unreadable: found=%v err=%v", found, err)
	}
	if _, _, err := check(journal, "different-owner"); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
		t.Fatal("legacy journal granted authority to a different UID")
	}
	journal.Version = 999
	if _, _, err := check(journal, fixture.OwnerUID); !errors.Is(err, ErrAuthorizationOwnershipConflict) {
		t.Fatal("unknown newer journal was accepted during rollback")
	}
	_, found, err = parseAuthorizationJournal(map[string]any{"attributes": map[string]any{}}, fixture.OwnerUID, "fixture-client-uuid")
	if err != nil || found {
		t.Fatal("legacy unmarked object was treated as owned")
	}
}
