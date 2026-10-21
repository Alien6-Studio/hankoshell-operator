package httpsecurity

import (
	"fmt"
	"strings"
	"testing"
)

func TestJSONRejectsAmbiguityIncompleteInputAndTrailingValues(t *testing.T) {
	for _, valid := range []string{`{}`, `[]`, `null`, `true`, `123456789012345678901234567890`, `"scalar"`, `{"a":[1,{"b":false}],"other":{"b":null}}`} {
		if err := ValidateJSON([]byte(valid)); err != nil {
			t.Fatalf("valid JSON rejected: %v", err)
		}
	}
	for _, invalid := range []string{"", " ", `{`, `[`, `{"a":`, `[1,`, `{"a":1,}`, `{"a":1,"a":2}`, `{"role":1,"r\u006fle":2}`, `[{"a":1,"a":2}]`, `{"child":{"a":1,"a":2}}`, `{}[]`, `{} invalid`, `{"sensitive-fixture": NaN}`, `{"a":1, "unterminated}`} {
		if err := ValidateJSON([]byte(invalid)); err == nil || err.Error() != "remote JSON document is ambiguous or incomplete" {
			t.Fatalf("unsafe JSON was accepted or exposed input: %q", invalid)
		}
	}
}

func TestJSONEnforcesDepthAndObjectMemberBudgets(t *testing.T) {
	for _, depth := range []int{32, 33} {
		data := strings.Repeat("[", depth) + "null" + strings.Repeat("]", depth)
		if (ValidateJSON([]byte(data)) == nil) != (depth == 32) {
			t.Fatalf("wrong depth boundary: %d", depth)
		}
	}
	for _, count := range []int{1024, 1025} {
		members := make([]string, count)
		for i := range members {
			members[i] = fmt.Sprintf(`"field%d":null`, i)
		}
		data := "{" + strings.Join(members, ",") + "}"
		if (ValidateJSON([]byte(data)) == nil) != (count == 1024) {
			t.Fatalf("wrong member boundary: %d", count)
		}
	}
}
