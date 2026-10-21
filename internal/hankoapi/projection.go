package hankoapi

import (
	"errors"
	"strings"
)

// ProjectionMode is installation authority, independent of client availability.
type ProjectionMode uint8

const (
	ProjectionDisabled ProjectionMode = iota
	ProjectionEnabled
)

var ErrProjectorUnavailable = errors.New("organization projector is unavailable")

// NormalizeProjectionMode preserves URL-based manual installations only when
// the explicit switch is absent. Explicit false rejects leftover credentials.
// Errors deliberately contain no supplied URL, token or boolean value.
func NormalizeProjectionMode(value string, present bool, apiURL, token string) (ProjectionMode, bool, error) {
	enabled := strings.TrimSpace(apiURL) != ""
	legacy := !present && enabled
	if present {
		switch strings.TrimSpace(value) {
		case "true":
			enabled = true
		case "false":
			enabled = false
		default:
			return ProjectionDisabled, false, errors.New("HANKO_ORGANIZATION_PROJECTION_ENABLED must be true or false")
		}
	}
	if !enabled {
		if strings.TrimSpace(apiURL) != "" || strings.TrimSpace(token) != "" {
			return ProjectionDisabled, false, errors.New("disabled organization projection requires removal of HANKO_API_URL and HANKO_API_TOKEN")
		}
		return ProjectionDisabled, false, nil
	}
	if strings.TrimSpace(apiURL) == "" || strings.TrimSpace(token) == "" {
		return ProjectionEnabled, legacy, errors.New("enabled organization projection requires HANKO_API_URL and HANKO_API_TOKEN")
	}
	return ProjectionEnabled, legacy, nil
}
