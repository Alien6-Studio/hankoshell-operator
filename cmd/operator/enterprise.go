package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

func enterprisePolicyFromEnv() (*hub.ContinuumPolicy, error) {
	profile := os.Getenv("HANKO_SECURITY_PROFILE")
	switch profile {
	case "", "standard":
		return nil, nil
	case "enterprise":
	default:
		return nil, fmt.Errorf("HANKO_SECURITY_PROFILE must be standard or enterprise")
	}
	for _, name := range []string{"HANKO_API_URL", "HANKO_SUPERVISION_API_URL", "HANKO_KEYCLOAK_URL"} {
		value := os.Getenv(name)
		if value == "" || (name == "HANKO_KEYCLOAK_URL" && spokeMode()) {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%s must be an HTTPS endpoint in the enterprise profile", name)
		}
	}
	return hub.NewContinuumPolicy(
		strings.TrimSpace(os.Getenv("HANKO_ENTERPRISE_HUB_ENDPOINT")),
		strings.TrimSpace(os.Getenv("HANKO_CONTINUUM_HUB_ADDRESS")),
		strings.TrimSpace(os.Getenv("HANKO_ENTERPRISE_ENROLLMENT_ENDPOINT")),
	)
}
