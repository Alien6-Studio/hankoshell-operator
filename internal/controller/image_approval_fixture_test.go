package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
)

const approvedThemeImage = "registry.example/hanko/theme-builder@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const previousThemeImage = "registry.example/hanko/theme-builder@sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const approvedKeycloakImage = "registry.example/hanko/keycloak@sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const approvedOperatorImage = "registry.example/hanko/operator@sha256:" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const approvedBackupImage = "registry.example/hanko/pgdump@sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

type fixtureSignatureVerifier struct{ err error }

func (v fixtureSignatureVerifier) Verify(context.Context, string, string, string) error { return v.err }

// approvedFixtureValidator isolates registry cryptography from controller state
// tests while exercising the same policy admission and submission boundaries.
func approvedFixtureValidator(t *testing.T) *imagevalidator.Validator {
	t.Helper()
	return fixtureValidator(t, fixtureSignatureVerifier{})
}

func fixtureValidator(t *testing.T, verifier imagevalidator.SignatureVerifier) *imagevalidator.Validator {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	approvals := []imagevalidator.Approval{
		{Purpose: imagevalidator.ThemeBuilder, Image: approvedThemeImage, Revision: strings.Repeat("1", 40), KeyFile: "publisher.pub"},
		{Purpose: imagevalidator.ThemeBuilder, Image: previousThemeImage, Revision: strings.Repeat("2", 40), KeyFile: "publisher.pub"},
		{Purpose: imagevalidator.Keycloak, Image: approvedKeycloakImage, Revision: strings.Repeat("3", 40), KeyFile: "publisher.pub"},
		{Purpose: imagevalidator.OperatorUpdate, Image: approvedOperatorImage, Revision: strings.Repeat("4", 40), KeyFile: "publisher.pub", ReleaseVersion: "0.1.0"},
		{Purpose: imagevalidator.DatabaseBackup, Image: approvedBackupImage, Revision: strings.Repeat("5", 40), KeyFile: "publisher.pub"},
	}
	data, err := json.Marshal(map[string]any{"version": 1, "approvals": approvals})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return imagevalidator.NewWithPolicy(path, verifier)
}
