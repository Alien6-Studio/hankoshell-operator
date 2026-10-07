//go:build keycloak_integration

package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// Pin the official multi-architecture image indexes, including on Apple Silicon.
// Deliberately reject unknown versions rather than silently testing another image.
var qualifiedKeycloakImages = map[string]string{
	"26.8.0": "quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc",
	"26.7.5": "quay.io/keycloak/keycloak:26.7.5@sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85",
}

type keycloakFixture struct {
	t          *testing.T
	version    string
	baseURL    string
	ca         []byte
	http       *http.Client
	adminToken string
	secrets    []string
	kc         *keycloak.Client
	credential string
	logs       bytes.Buffer
}

func fixtureSecret(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func fixtureTLS(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable-keycloak-fixture"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
		IsCA:     true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}

func (f *keycloakFixture) docker(timeout time.Duration, environment []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), environment...)
	return cmd.CombinedOutput()
}

var fixtureJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

func (f *keycloakFixture) redact(data []byte) string {
	value := string(data)
	for _, secret := range f.secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return fixtureJWT.ReplaceAllString(value, "[REDACTED JWT]")
}

func newKeycloakFixture(t *testing.T) *keycloakFixture {
	t.Helper()
	version := os.Getenv("KEYCLOAK_VERSION")
	if version == "" {
		version = "26.8.0"
	}
	image, ok := qualifiedKeycloakImages[version]
	if !ok {
		t.Fatalf("no pinned fixture for Keycloak %q", version)
	}
	f := &keycloakFixture{t: t, version: version}
	password := fixtureSecret(t)
	f.secrets = append(f.secrets, password)
	cert, key := fixtureTLS(t)
	f.ca = cert
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	// testing.T keeps this directory's parent private (0700). These fixture PEMs are
	// read-only bind mounts readable by the image's unprivileged UID, not assets
	// or production credentials, and are removed by testing.T cleanup.
	for name, data := range map[string][]byte{"tls.crt": cert, "tls.key": key} {
		// #nosec G306 -- Disposable test key, private parent, read-only mount; Keycloak runs as UID 1000.
		if err := os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	name := "hankoshell-keycloak-test-" + fixtureSecret(t)[:12]
	// Register cleanup before startup: even a timed-out docker run may have
	// created the container. Never prune or touch developer-owned containers.
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := f.docker(10*time.Second, nil, "logs", "--tail", "100", name)
			t.Logf("Keycloak %s diagnostics (redacted):\n%s", version, f.redact(output))
		}
		output, err := f.docker(15*time.Second, nil, "rm", "--force", name)
		if err != nil && !strings.Contains(string(output), "No such container") {
			t.Errorf("fixture cleanup failed: %s", f.redact(output))
		}
	})
	output, err := f.docker(3*time.Minute, []string{"KC_BOOTSTRAP_ADMIN_PASSWORD=" + password},
		"run", "--detach", "--name", name, "--memory", "2g", "--pids-limit", "512",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--publish", "127.0.0.1::8443", "--env", "KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin",
		"--env", "KC_BOOTSTRAP_ADMIN_PASSWORD",
		"--volume", directory+":/fixture-tls:ro", image,
		"start", "--db=dev-file", "--http-enabled=false", "--hostname-strict=false",
		"--https-certificate-file=/fixture-tls/tls.crt", "--https-certificate-key-file=/fixture-tls/tls.key",
		"--https-protocols=TLSv1.3")
	if err != nil {
		t.Fatalf("Keycloak fixture startup failed (Docker is required): %s", f.redact(output))
	}
	output, err = f.docker(10*time.Second, nil, "port", name, "8443/tcp")
	if err != nil {
		t.Fatalf("resolve fixture port: %s", f.redact(output))
	}
	address := strings.TrimSpace(string(output))
	if !strings.HasPrefix(address, "127.0.0.1:") || strings.ContainsAny(address, "\r\n") {
		t.Fatal("Docker did not bind the fixture exclusively to loopback")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal("invalid Docker fixture port")
	}
	f.baseURL = "https://localhost:" + port
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	f.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(f.http.CloseIdleConnections)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		response, requestErr := f.http.Get(f.baseURL + "/realms/master/.well-known/openid-configuration")
		if requestErr == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Keycloak HTTPS readiness deadline exceeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Password grant exists only in this disposable bootstrap fixture. Production
	// reconcilers below authenticate exclusively with client_credentials.
	f.adminToken = f.token(url.Values{"client_id": {"admin-cli"}, "grant_type": {"password"}, "username": {"fixture-admin"}, "password": {password}})
	f.kc, f.credential = f.serviceClient("fixture-operator", true)
	return f
}

func (f *keycloakFixture) token(form url.Values) string {
	f.t.Helper()
	response, err := f.http.PostForm(f.baseURL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		f.t.Fatalf("fixture token request: %s", f.redact([]byte(err.Error())))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		f.t.Fatalf("fixture token request HTTP %d", response.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || payload.AccessToken == "" {
		f.t.Fatal("invalid fixture token response")
	}
	f.secrets = append(f.secrets, payload.AccessToken)
	return payload.AccessToken
}

func (f *keycloakFixture) admin(method, path string, payload, target any) int {
	f.t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := http.NewRequest(method, f.baseURL+path, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.http.Do(request)
	if err != nil {
		f.t.Fatalf("fixture Admin API %s %s: %s", method, path, f.redact([]byte(err.Error())))
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 && response.StatusCode != http.StatusNotFound {
		// Do not print response bodies: providers can echo supplied credentials.
		f.t.Fatalf("fixture Admin API %s %s: HTTP %d", method, path, response.StatusCode)
	}
	if target != nil && response.StatusCode != http.StatusNotFound {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
			f.t.Fatal("invalid fixture Admin API response")
		}
	}
	return response.StatusCode
}

func (f *keycloakFixture) client(realm, name string) map[string]any {
	f.t.Helper()
	var clients []map[string]any
	f.admin(http.MethodGet, "/admin/realms/"+realm+"/clients?clientId="+url.QueryEscape(name), nil, &clients)
	if len(clients) != 1 || clients[0]["clientId"] != name {
		f.t.Fatalf("expected exactly one client %s/%s, got %d", realm, name, len(clients))
	}
	var full map[string]any
	f.admin(http.MethodGet, "/admin/realms/"+realm+"/clients/"+clients[0]["id"].(string), nil, &full)
	return full
}

func (f *keycloakFixture) serviceClient(name string, privileged bool) (*keycloak.Client, string) {
	f.t.Helper()
	secret := fixtureSecret(f.t)
	f.secrets = append(f.secrets, secret)
	f.admin(http.MethodPost, "/admin/realms/master/clients", map[string]any{
		"clientId": name, "secret": secret, "protocol": "openid-connect", "enabled": true,
		"publicClient": false, "serviceAccountsEnabled": true, "standardFlowEnabled": false,
		"directAccessGrantsEnabled": false, "fullScopeAllowed": false,
	}, nil)
	if privileged {
		client := f.client("master", name)
		var user map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/clients/"+client["id"].(string)+"/service-account-user", nil, &user)
		var role map[string]any
		f.admin(http.MethodGet, "/admin/realms/master/roles/admin", nil, &role)
		// The complete realm lifecycle currently requires master administrative
		// authority. Do not label this fixture as a least-privilege deployment.
		f.admin(http.MethodPost, "/admin/realms/master/users/"+user["id"].(string)+"/role-mappings/realm", []any{role}, nil)
		f.admin(http.MethodPost, "/admin/realms/master/clients/"+client["id"].(string)+"/scope-mappings/realm", []any{role}, nil)
	}
	kc, err := keycloak.NewWithTLS(f.baseURL, name, secret, f.ca)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := kc.RequireHTTPS(); err != nil {
		f.t.Fatal(err)
	}
	return kc, secret
}

func (f *keycloakFixture) requireNoCredentials(label string, data []byte) {
	f.t.Helper()
	if f.credentialsPresent(data) {
		f.t.Errorf("%s contains a credential/bearer token (value withheld)", label)
	}
}

func (f *keycloakFixture) credentialsPresent(data []byte) bool {
	for _, secret := range f.secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			return true
		}
	}
	return fixtureJWT.Match(data)
}

func TestKeycloakFixtureRedactsAndDetectsCredentials(t *testing.T) {
	secret := fixtureSecret(t)
	token := "eyJ" + strings.Repeat("a", 10) + "." + strings.Repeat("b", 10) + ".fixture"
	f := &keycloakFixture{t: t, secrets: []string{"", secret}}
	for _, value := range []string{secret, token} {
		input := []byte("diagnostic " + value)
		if !f.credentialsPresent(input) || f.credentialsPresent([]byte(f.redact(input))) {
			t.Fatal("credential detection/redaction failed (values withheld)")
		}
	}
	if f.credentialsPresent([]byte("credential reference: admin/client_secret")) {
		t.Fatal("credential reference was mistaken for a secret value")
	}
}

func (f *keycloakFixture) requireNoError(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(f.redact([]byte(fmt.Sprint(err))))
	}
}
