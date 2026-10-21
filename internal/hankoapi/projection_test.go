package hankoapi

import (
	"strings"
	"testing"
)

func TestProjectionConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, value, endpoint, token string
		present, legacy, invalid     bool
		mode                         ProjectionMode
	}{
		{name: "explicit disabled", value: "false", present: true},
		{name: "explicit enabled", value: "true", present: true, endpoint: "https://api.example", token: "sentinel-token", mode: ProjectionEnabled},
		{name: "missing URL", value: "true", present: true, token: "sentinel-token", invalid: true},
		{name: "missing token", value: "true", present: true, endpoint: "https://api.example", invalid: true},
		{name: "legacy enabled", endpoint: "https://api.example", token: "sentinel-token", mode: ProjectionEnabled, legacy: true},
		{name: "default disabled"},
		{name: "invalid boolean", value: "1", present: true, invalid: true},
		{name: "empty explicit boolean", present: true, invalid: true},
		{name: "disabled leftover URL", value: "false", present: true, endpoint: "https://api.example", invalid: true},
		{name: "disabled leftover token", value: "false", present: true, token: "sentinel-token", invalid: true},
		{name: "orphan token", token: "sentinel-token", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, legacy, err := NormalizeProjectionMode(tc.value, tc.present, tc.endpoint, tc.token)
			if (err != nil) != tc.invalid {
				t.Fatalf("configuration outcome: %v", err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "sentinel-token") || strings.Contains(err.Error(), "api.example") {
					t.Fatal("configuration leaked supplied data")
				}
				return
			}
			if mode != tc.mode || legacy != tc.legacy {
				t.Fatal("incorrect explicit mode or legacy classification")
			}
		})
	}
}
