package adoption

// KeycloakDefault is deliberately limited to these exact values qualified on
// 26.7.5 and 26.8.0. Other values remain native and unqualified. Unlike opaque
// native presence, these values may enter canonical non-secret observation.
func KeycloakDefault(key, value string) bool {
	switch key {
	case "realm_client", "backchannel.logout.revoke.offline.tokens":
		return value == "false"
	case "backchannel.logout.session.required":
		return value == "true"
	}
	return false
}
