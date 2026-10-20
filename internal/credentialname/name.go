// Package credentialname maps public client identities to exact Secret names.
package credentialname

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Application preserves every previously valid application output name.
func Application(clientID string) string { return name("hanko-app-", clientID) }

// ServiceAccount preserves every previously valid M2M output name.
func ServiceAccount(clientID string) string { return name("hanko-sa-", clientID) }

func name(prefix, clientID string) string {
	legacy := prefix + clientID
	if len(validation.IsDNS1123Subdomain(legacy)) == 0 {
		return legacy
	}
	// The dot separates the hashed namespace from every legacy prefix+ID name.
	// No legacy Kubernetes-valid Secret is renamed, truncated or adopted.
	return strings.TrimSuffix(prefix, "-") + "." + fmt.Sprintf("%x", sha256.Sum256([]byte(clientID)))
}
