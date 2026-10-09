package applications

import (
	"reflect"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

func TestApplicationObservationNormalizesGeneratedStateAndDetectsSemanticDrift(t *testing.T) {
	p := testApplicationPlan(t, Intent{Protocol: "saml", ClientID: "https://sp.test/entity", SAML: &SAML{ACS: []string{"https://sp.test/a", "https://sp.test/b"}, SignedAssertions: true}, Roles: []Role{{Name: "use", Description: "Use application"}}}, ResolvedReferences{}, iamcontract.Preconditions{})
	base := desired(p)
	canonical, complete := observedClient(base, p)
	if !complete {
		t.Fatal("managed client observation incomplete")
	}
	generated := desired(p)
	generated.ID = "provider-generated-uuid"
	generated.RedirectURIs = []string{"https://sp.test/b", "https://sp.test/a"}
	generated.Attributes["client.secret.creation.time"] = "generated-timestamp"
	generated.Attributes["saml.artifact.binding.identifier"] = "generated-artifact-identity"
	generated.Attributes["realm_client"] = "false"
	generated.Attributes["hanko.sh/resource-server-ownership"] = "sibling-journal"
	normalized, complete := observedClient(generated, p)
	if !complete || !reflect.DeepEqual(canonical, normalized) {
		t.Fatal("irrelevant provider IDs/defaults/order change observation")
	}
	o := observedApplication{Present: true, Complete: true, Client: canonical, Roles: p.intent.Roles}
	if applicationDrift(p, o) {
		t.Fatal("matching application classified as drift")
	}
	for _, change := range []func(*observedApplication){
		func(o *observedApplication) { o.Client.Protocol = "openid-connect" },
		func(o *observedApplication) { o.Client.Attributes["saml.assertion.signature"] = "false" },
		func(o *observedApplication) { o.Client.RedirectURIs = []string{"https://foreign.test/acs"} },
		func(o *observedApplication) { o.Roles = []Role{{Name: "use", Description: "drift"}} },
		func(o *observedApplication) { o.Complete = false },
	} {
		copy := o
		copy.Client.Attributes = cloneAttributes(o.Client.Attributes)
		change(&copy)
		if !applicationDrift(p, copy) {
			t.Fatal("protocol/signing/ACS/role drift hidden")
		}
	}
	generated.Attributes["private.signing.key"] = "must-not-be-observed"
	filtered, complete := observedClient(generated, p)
	if complete || filtered.Attributes["private.signing.key"] != "" {
		t.Fatal("credential-shaped metadata entered complete observation")
	}
}
