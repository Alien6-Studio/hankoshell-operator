package imagevalidator

import (
	"strings"
	"testing"
)

func TestStructuralImageTrust(t *testing.T) {
	v := NewWithPrefixes("alien6registry.azurecr.io", "quay.io/keycloak", "registry.example:5000/team/")
	for _, image := range []string{
		"alien6registry.azurecr.io/hanko/api:latest",
		"alien6registry.azurecr.io/hanko/api@sha256:" + strings.Repeat("a", 64),
		"quay.io/keycloak:26.0", "quay.io/keycloak/keycloak:26.0",
		"registry.example:5000/team/app:v1",
	} {
		t.Run(image, func(t *testing.T) {
			if err := v.ValidateImageRef(image); err != nil {
				t.Fatalf("trusted image rejected: %v", err)
			}
		})
	}
	for _, image := range []string{
		"alien6registry.azurecr.io.attacker.example/hanko/api:latest",
		"alien6registry.azurecr.io:5000/hanko/api:latest",
		"quay.io/keycloak-attacker/app:latest", "quay.io/keycloakattacker:latest",
		"registry.example:50001/team/app:v1", "registry.example:5000/team-other/app:v1",
		"https://quay.io/keycloak/keycloak:26.0", "user@quay.io/keycloak/keycloak:26.0",
		"quay.io/keycloak//keycloak:26.0", "quay.io/keycloak/../app:v1",
		"quay.io/keycloak/keycloak@sha256:abc", "quay.io/keycloak/keycloak:bad tag",
		" quay.io/keycloak/keycloak:26.0", "quay.io/keycloak/keycloak:26.0\n",
		"keycloak:26.0", "keycloak/keycloak:26.0", "", "quay.io/keycloak/keycloak:",
	} {
		t.Run(image, func(t *testing.T) {
			if err := v.ValidateImageRef(image); err == nil {
				t.Fatal("untrusted or malformed image accepted")
			}
		})
	}
}

func TestInvalidAllowlistDeniesAll(t *testing.T) {
	for _, entry := range []string{
		"", "https://quay.io/keycloak", "quay.io/keycloak:latest",
		"quay.io/keycloak@sha256:" + strings.Repeat("a", 64),
		"quay.io/*", "quay.io/keycloak//", "user@quay.io", "keycloak",
	} {
		t.Run(entry, func(t *testing.T) {
			v := NewWithPrefixes("quay.io/keycloak", entry)
			if err := v.ValidateImageRef("quay.io/keycloak/keycloak:26.0"); err == nil {
				t.Fatal("malformed allowlist did not deny all")
			}
		})
	}
	if err := NewWithPrefixes().ValidateImageRef("quay.io/keycloak/keycloak:26.0"); err == nil {
		t.Fatal("empty allowlist did not deny all")
	}
}

func TestEnvironmentAllowlist(t *testing.T) {
	t.Setenv("HANKO_TRUSTED_REGISTRIES", "  registry.example/ , quay.io/keycloak/ ")
	if err := New().ValidateImageRef("registry.example/team/app:v1"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HANKO_TRUSTED_REGISTRIES", "")
	if err := New().ValidateImageRef("registry.example/team/app:v1"); err == nil {
		t.Fatal("unset policy must deny all")
	}
}

func TestDockerHubRegistryIdentity(t *testing.T) {
	v := NewWithPrefixes("docker.io")
	for _, image := range []string{"docker.io/library/keycloak:26.0", "docker.io/team/app:v1"} {
		if err := v.ValidateImageRef(image); err != nil {
			t.Fatalf("explicit canonical Docker Hub image rejected: %v", err)
		}
	}
	for _, image := range []string{"docker.io.attacker.test/library/keycloak:26.0", "index.docker.io/library/keycloak:26.0", "keycloak:26.0"} {
		if err := v.ValidateImageRef(image); err == nil {
			t.Fatalf("lookalike or normalized registry alias accepted: %q", image)
		}
	}
}
