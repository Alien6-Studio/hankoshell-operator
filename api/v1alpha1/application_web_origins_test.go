package v1alpha1_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestApplicationWebOriginsWireAndDeepCopyPreserveExplicitEmptySet(t *testing.T) {
	empty, restricted := []string{}, []string{"https://portal.test"}
	for _, origins := range []*[]string{nil, &empty, &restricted} {
		original := &api.HankoApplication{Spec: api.HankoApplicationSpec{RealmRef: "realm", ClientID: "portal", WebOrigins: origins}}
		encoded, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip api.HankoApplication
		if err := json.Unmarshal(encoded, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if origins == nil {
			if roundtrip.Spec.WebOrigins != nil || strings.Contains(string(encoded), `"webOrigins"`) {
				t.Fatal("omitted CORS policy became explicit on the API wire")
			}
			continue
		}
		if roundtrip.Spec.WebOrigins == nil || !slices.Equal(*origins, *roundtrip.Spec.WebOrigins) {
			t.Fatal("explicit CORS policy was lost on the API wire")
		}
		if len(*origins) == 0 && !strings.Contains(string(encoded), `"webOrigins":[]`) {
			t.Fatal("explicit empty policy became null or omission")
		}
		cloned := original.DeepCopy()
		if cloned.Spec.WebOrigins == origins {
			t.Fatal("deep copy shares CORS policy authority with its caller")
		}
		if len(*origins) > 0 {
			(*cloned.Spec.WebOrigins)[0] = "https://changed.test"
			if (*origins)[0] != "https://portal.test" {
				t.Fatal("deep copy shares the origin set backing array")
			}
		}
	}
}
