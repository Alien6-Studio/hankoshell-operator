// Package keycloakversion defines feature eligibility independently of the exact
// versions used in qualification. Eligibility never substitutes for native
// capability, permission, ownership or read-back checks.
package keycloakversion

import (
	"regexp"
	"strconv"
	"strings"
)

// Bound numeric components and reject prereleases, vendor suffixes and ambiguous
// spellings. A new major requires an adapter review, not an automatic promise.
var stable26 = regexp.MustCompile(`^26\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// Core covers the existing realm/client/role APIs throughout the 26.x family.
// Exact tested versions remain recorded separately in versions.json.
func Core(version string) bool { return stable26.MatchString(version) }

// WorkloadIdentity retains the oldest characterized baseline while allowing
// subsequent patches and minors of the same major.
func WorkloadIdentity(version string) bool { return atLeast(version, 7, 5) }

// DiscoveryOverride additionally requires the source override introduced in 26.8.
func DiscoveryOverride(version string) bool { return atLeast(version, 8, 0) }

// BoundedDelegation only permits probing the extension's versioned contract.
// The native extension still has to advertise and enforce every required bound.
func BoundedDelegation(version string) bool { return atLeast(version, 7, 5) }

func atLeast(version string, minor, patch int) bool {
	if !Core(version) {
		return false
	}
	parts := strings.Split(version, ".")
	m, _ := strconv.Atoi(parts[1]) // The bounded canonical pattern makes conversion total.
	p, _ := strconv.Atoi(parts[2])
	return m > minor || m == minor && p >= patch
}
