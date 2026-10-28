// Command verifier-evidence binds the compiled verifier to its actual package
// graph. Module-level vulnerability reports remain available without filtering.
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"
)

type module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

type evidence struct {
	Schema   int      `json:"schema"`
	SHA256   string   `json:"binary_sha256"`
	Go       string   `json:"go_version"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Main     module   `json:"main"`
	Modules  []module `json:"modules"`
	Packages []string `json:"packages"`
}

func packages(data string) ([]string, error) {
	values := strings.Fields(data)
	if len(data) > 1024*1024 || len(values) < 100 || len(values) > 10000 {
		return nil, errors.New("verifier package inventory outside its bounds")
	}
	slices.Sort(values)
	for index, value := range values {
		if strings.ContainsAny(value, "\"\\\x00") || index > 0 && value == values[index-1] ||
			value == "golang.org/x/crypto/openpgp" || strings.HasPrefix(value, "golang.org/x/crypto/openpgp/") {
			return nil, errors.New("unsafe or ambiguous verifier package inventory")
		}
	}
	if !slices.Contains(values, "github.com/sigstore/cosign/v3/cmd/cosign") {
		return nil, errors.New("verifier command absent from package inventory")
	}
	return values, nil
}

func inspect(binary, version string, input io.Reader) (evidence, error) {
	var result evidence
	data, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
	if err != nil {
		return result, err
	}
	result.Packages, err = packages(string(data))
	if err != nil {
		return result, err
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil || !verifierIdentity(info, version) {
		return result, errors.New("compiled verifier identity differs from reviewed source")
	}
	file, err := os.Open(binary)
	if err != nil {
		return result, fmt.Errorf("open compiled verifier: %w", err)
	}
	defer file.Close()
	return compiledEvidence(info, file, result.Packages)
}

func compiledEvidence(info *debug.BuildInfo, file io.Reader, inventory []string) (evidence, error) {
	result := evidence{Packages: inventory}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}
	result.Schema, result.SHA256, result.Go = 1, hex.EncodeToString(hash.Sum(nil)), info.GoVersion
	result.Main = module{info.Main.Path, info.Main.Version, info.Main.Sum}
	for _, dependency := range info.Deps {
		if dependency.Replace != nil {
			return result, errors.New("replaced verifier module is not qualified")
		}
		result.Modules = append(result.Modules, module{dependency.Path, dependency.Version, dependency.Sum})
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			result.OS = setting.Value
		case "GOARCH":
			result.Arch = setting.Value
		}
	}
	if result.OS == "" || result.Arch == "" {
		return result, errors.New("compiled verifier platform unavailable")
	}
	return result, nil
}

func main() {
	binary := flag.String("binary", "", "Exact compiled verifier")
	version := flag.String("version", "", "Reviewed Cosign module version")
	flag.Parse()
	result, err := inspect(*binary, *version, os.Stdin)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verifierIdentity(info *debug.BuildInfo, version string) bool {
	return info != nil && info.Path == "github.com/sigstore/cosign/v3/cmd/cosign" && info.Main.Path == "github.com/sigstore/cosign/v3" &&
		info.Main.Version == version && info.Main.Replace == nil
}
