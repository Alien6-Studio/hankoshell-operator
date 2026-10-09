// Package organization shares the structural organization ownership boundary.
package organization

const (
	OwnerName      = "hanko.sh/organization-name"
	OwnerNamespace = "hanko.sh/organization-namespace"
	OwnerUID       = "hanko.sh/organization-uid"
)

// StrictOwnership never accepts markerless/legacy IDs or multi-valued markers.
func StrictOwnership(attributes map[string][]string, name, namespace, uid string) bool {
	if name == "" || namespace == "" || uid == "" {
		return false
	}
	for key, expected := range map[string]string{OwnerName: name, OwnerNamespace: namespace, OwnerUID: uid} {
		values := attributes[key]
		if len(values) != 1 || values[0] != expected {
			return false
		}
	}
	return true
}
