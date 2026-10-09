package main

import (
	"os"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
)

func TestRuntimeProjectionConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, mode, url, token   string
		absent, invalid, enabled bool
	}{
		{name: "disabled", mode: "false"},
		{name: "enabled", mode: "true", url: "https://api.example", token: "sentinel-token", enabled: true},
		{name: "legacy", absent: true, url: "https://api.example", token: "sentinel-token", enabled: true},
		{name: "default", absent: true},
		{name: "missing URL", mode: "true", token: "sentinel-token", invalid: true},
		{name: "missing token", mode: "true", url: "https://api.example", invalid: true},
		{name: "invalid boolean", mode: "yes", invalid: true},
		{name: "contradictory", mode: "false", url: "https://api.example", token: "sentinel-token", invalid: true},
		{name: "credentials in URL", mode: "true", url: "https://user:secret@api.example", token: "sentinel-token", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HANKO_ORGANIZATION_PROJECTION_ENABLED", tc.mode)
			if tc.absent {
				if err := os.Unsetenv("HANKO_ORGANIZATION_PROJECTION_ENABLED"); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HANKO_API_URL", tc.url)
			t.Setenv("HANKO_API_TOKEN", tc.token)
			p, err := newPositionProjector()
			if (err != nil) != tc.invalid {
				t.Fatalf("runtime outcome: %v", err)
			}
			if err == nil && ((p.Mode == hankoapi.ProjectionEnabled) != tc.enabled || (p.Client != nil) != tc.enabled) {
				t.Fatal("mode/client mismatch")
			}
		})
	}
}
