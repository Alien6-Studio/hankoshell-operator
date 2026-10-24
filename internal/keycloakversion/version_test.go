package keycloakversion

import (
	"strings"
	"testing"
)

func TestFeatureEligibilityAcrossUpgradeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version                   string
		core, workload, discovery bool
	}{
		{"26.0.0", true, false, false},
		{"26.6.9", true, false, false},
		{"26.7.4", true, false, false},
		{"26.7.5", true, true, false},
		{"26.7.6", true, true, false},
		{"26.7.10", true, true, false},
		{"26.8.0", true, true, true},
		{"26.8.1", true, true, true},
		// Synthetic future versions exercise eligibility, not native qualification.
		{"26.8.2", true, true, true},
		{"26.9.0", true, true, true},
		{"26.10.0", true, true, true},
		{"25.0.0", false, false, false},
		{"27.0.0", false, false, false},
		{"", false, false, false},
		{"26.8", false, false, false},
		{"v26.8.1", false, false, false},
		{"26.08.1", false, false, false},
		{"26.8.01", false, false, false},
		{"26.8.1-rc.1", false, false, false},
		{"26.8.1-SNAPSHOT", false, false, false},
		{"26.8.1+vendor", false, false, false},
		{"26.8.1\n", false, false, false},
		{"26.8." + strings.Repeat("9", 30), false, false, false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if Core(tc.version) != tc.core || WorkloadIdentity(tc.version) != tc.workload || DiscoveryOverride(tc.version) != tc.discovery || BoundedDelegation(tc.version) != tc.workload {
				t.Fatal("feature eligibility crossed an unsupported boundary")
			}
		})
	}
}
