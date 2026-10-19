package credentialname

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestCanonicalCredentialNamesPreserveLegacyAndNeverCollideWithItsNamespace(t *testing.T) {
	data, err := os.ReadFile("testdata/names.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ClientID, Application, ServiceAccount   string
		LegacyApplication, LegacyServiceAccount bool
	}
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) < 10 {
		t.Fatal("incomplete independent canonical name vectors", err)
	}
	for _, c := range cases {
		for _, result := range []struct {
			value, want, prefix string
			legacy              bool
		}{
			{Application(c.ClientID), c.Application, "hanko-app-", c.LegacyApplication},
			{ServiceAccount(c.ClientID), c.ServiceAccount, "hanko-sa-", c.LegacyServiceAccount},
		} {
			if result.value != result.want || len(validation.IsDNS1123Subdomain(result.value)) != 0 {
				t.Fatal("canonical name differs from the reviewed vector or Kubernetes validation", c.ClientID)
			}
			if result.legacy && result.value != result.prefix+c.ClientID {
				t.Fatal("previously valid credential Secret was renamed")
			}
			if !result.legacy && strings.HasPrefix(result.value, result.prefix) {
				t.Fatal("hashed name overlaps the namespace of an existing legacy name")
			}
		}
	}
}
