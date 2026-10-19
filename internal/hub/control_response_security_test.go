package hub

import (
	"strings"
	"testing"
)

func TestControlResponsesRefuseAmbiguousJSONBeforeCommands(t *testing.T) {
	for _, value := range []string{
		`{"ok":true,"ok":false}`,
		`{"ok":true,"agentUpdate":{"version":"unapproved","version":"1.0.0"}}`,
		`{"token":"foreign","token":"synthetic","tenantID":"t","clusterID":"c"}`,
		`{"ok":true} {"agentUpdate":{}}`,
		strings.Repeat("[", 33) + "null" + strings.Repeat("]", 33),
		strings.Repeat(" ", maxHubControlResponseBytes+1),
	} {
		if decodeControlResponse([]byte(value), new(StatusAck)) || decodeControlResponse([]byte(value), new(EnrollResult)) {
			t.Fatal("ambiguous or oversized Hub control response accepted")
		}
	}
	// Unknown additive fields retain the legacy wire compatibility contract.
	if !decodeControlResponse([]byte(`{"ok":true,"futureField":1}`), new(StatusAck)) {
		t.Fatal("additive Hub fields rejected")
	}
}
