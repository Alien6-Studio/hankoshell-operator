package imagevalidator

import (
	"strings"
	"testing"
)

func TestImagePolicyRefusesAmbiguousPublisherApproval(t *testing.T) {
	for _, value := range []string{`{"version":2,"version":1,"approvals":[]}`, `{"version":1,"approvals":[{"purpose":"keycloak","purpose":"theme-builder"}]}`, `{"version":1,"approvals":[]} {}`, strings.Repeat(" ", maxPolicyBytes+1)} {
		if _, err := decodePolicy([]byte(value)); err == nil {
			t.Fatal("ambiguous publisher approval accepted")
		}
	}
}
