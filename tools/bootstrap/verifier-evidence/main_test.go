package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"testing/iotest"
)

func TestInventoryRefusesDeprecatedCodeAndMissingEvidence(t *testing.T) {
	base := []string{"github.com/sigstore/cosign/v3/cmd/cosign"}
	for index := range 100 {
		base = append(base, fmt.Sprintf("fixture/package%d", index))
	}
	if _, err := packages(strings.Join(base, "\n")); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"golang.org/x/crypto/openpgp", "golang.org/x/crypto/openpgp/armor", base[0]} {
		if _, err := packages(strings.Join(base, "\n") + "\n" + extra); err == nil {
			t.Fatal("unsafe inventory accepted")
		}
	}
	for _, invalid := range []string{"", strings.Join(base[1:], "\n"), strings.Repeat("a", 1024*1024+1)} {
		if _, err := packages(invalid); err == nil {
			t.Fatal("incomplete inventory accepted")
		}
	}
	if _, err := inspect("/missing-verifier", "v3.1.4", strings.NewReader(strings.Join(base, "\n"))); err == nil {
		t.Fatal("absent compiled verifier accepted")
	}
}

func TestCompiledEvidenceBindsBytesToolchainPlatformAndModules(t *testing.T) {
	info := &debug.BuildInfo{Path: "github.com/sigstore/cosign/v3/cmd/cosign", GoVersion: "go1.27.3",
		Main:     debug.Module{Path: "github.com/sigstore/cosign/v3", Version: "v3.1.4", Sum: "h1:reviewed-main"},
		Deps:     []*debug.Module{{Path: "golang.org/x/crypto", Version: "v0.58.0", Sum: "h1:reviewed-dependency"}},
		Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}}}
	if !verifierIdentity(info, "v3.1.4") || verifierIdentity(nil, "v3.1.4") || verifierIdentity(info, "v0.0.0") {
		t.Fatal("compiled command/version identity is ambiguous")
	}
	content := "synthetic binary bytes for the projection unit"
	got, err := compiledEvidence(info, strings.NewReader(content), []string{"reviewed/package"})
	expected := sha256.Sum256([]byte(content))
	if err != nil || got.SHA256 != hex.EncodeToString(expected[:]) || got.Go != "go1.27.3" || got.OS != "linux" || got.Arch != "amd64" || got.Main.Version != "v3.1.4" || len(got.Modules) != 1 || got.Modules[0].Sum != "h1:reviewed-dependency" {
		t.Fatal("evidence lost a compiled binding", err)
	}
	if _, err := compiledEvidence(info, iotest.ErrReader(errors.New("read refused")), nil); err == nil {
		t.Fatal("unreadable bytes accepted")
	}
	info.Deps[0].Replace = &debug.Module{Path: "unreviewed"}
	if _, err := compiledEvidence(info, strings.NewReader(content), nil); err == nil {
		t.Fatal("replaced module accepted")
	}
	info.Deps[0].Replace = nil
	info.Settings = nil
	if _, err := compiledEvidence(info, strings.NewReader(content), nil); err == nil {
		t.Fatal("missing platform accepted")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inventory := []string{"github.com/sigstore/cosign/v3/cmd/cosign"}
	for index := range 100 {
		inventory = append(inventory, fmt.Sprintf("fixture/package%d", index))
	}
	if _, err := inspect(self, "v3.1.4", strings.NewReader(strings.Join(inventory, "\n"))); err == nil {
		t.Fatal("foreign compiled command accepted")
	}
}
