package organization

import "testing"

func TestStrictOwnershipRequiresEveryExactSingletonMarker(t *testing.T) {
	owned := func() map[string][]string {
		return map[string][]string{OwnerName: {"team"}, OwnerNamespace: {"auth"}, OwnerUID: {"current-uid"}, "native": {"preserved"}}
	}
	if !StrictOwnership(owned(), "team", "auth", "current-uid") {
		t.Fatal("exact owner with unrelated native attributes was rejected")
	}
	if StrictOwnership(nil, "team", "auth", "current-uid") || StrictOwnership(map[string][]string{"legacy-id": {"current-uid"}}, "team", "auth", "current-uid") {
		t.Fatal("absent or legacy markers acquired ownership")
	}
	for _, key := range []string{OwnerName, OwnerNamespace, OwnerUID} {
		for _, mutation := range []string{"missing", "empty", "foreign", "duplicate", "mixed"} {
			t.Run(key+"/"+mutation, func(t *testing.T) {
				attributes := owned()
				expected := attributes[key][0]
				switch mutation {
				case "missing":
					delete(attributes, key)
				case "empty":
					attributes[key] = nil
				case "foreign":
					attributes[key] = []string{"other"}
				case "duplicate":
					attributes[key] = []string{expected, expected}
				case "mixed":
					attributes[key] = []string{expected, "other"}
				}
				if StrictOwnership(attributes, "team", "auth", "current-uid") {
					t.Fatal("incomplete or ambiguous markers authorized ownership")
				}
			})
		}
	}
	for _, identity := range [][3]string{{"", "auth", "current-uid"}, {"team", "", "current-uid"}, {"team", "auth", ""}} {
		if StrictOwnership(owned(), identity[0], identity[1], identity[2]) {
			t.Fatal("incomplete expected identity authorized ownership")
		}
	}
}
