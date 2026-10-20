package applications

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

func normalizeWebOrigins(origins *[]string) *[]string {
	if origins == nil {
		return nil
	}
	normalized := stringSet(*origins)
	if normalized == nil {
		normalized = []string{}
	}
	return &normalized
}

func validOptionalWebOrigins(origins *[]string) bool {
	return origins == nil || ValidWebOrigins(*origins)
}

// ValidWebOrigins bounds explicit OIDC CORS policy without allowing URL
// credentials, queries, fragments or authority-wide wildcard origins.
func ValidWebOrigins(origins []string) bool {
	if len(origins) > 64 {
		return false
	}
	for _, origin := range origins {
		if !validWebOrigin(origin) {
			return false
		}
	}
	return true
}

func validWebOrigin(origin string) bool {
	if origin == "+" {
		return true
	}
	if utf8.RuneCountInString(origin) > 255 || !utf8.ValidString(origin) || strings.ContainsAny(origin, " \t\r\n\\") || strings.IndexFunc(origin, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || !webOriginURL(u, origin) {
		return false
	}
	authority := *u
	authority.Scheme = "https" // share the bounded authority/port check for HTTP origins
	return validACSAuthority(&authority)
}

func webOriginURL(u *url.URL, original string) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && !strings.Contains(u.Host, "*") && u.User == nil && u.Opaque == "" && validWebOriginPath(u.Path) && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(original, "#") && !strings.HasSuffix(u.Host, ":")
}

// Preserve qualified legacy callback-style entries verbatim; only a terminal
// path wildcard is admitted, never a wildcard authority or arbitrary glob.
func validWebOriginPath(path string) bool {
	if strings.ContainsAny(path, "@?#\\") || strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return false
	}
	return !strings.Contains(path, "*") || strings.Count(path, "*") == 1 && strings.HasSuffix(path, "/*")
}
