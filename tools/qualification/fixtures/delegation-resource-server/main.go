// Disposable qualification resource server; never included in the operator image.
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type configuration struct {
	Issuer    string            `json:"issuer"`
	Audience  string            `json:"audience"`
	Resources map[string]string `json:"resources"`
}

type verifier struct {
	config configuration
	keys   map[string]*rsa.PublicKey
}

type signingKey struct{ Kid, Kty, Alg, Use, N, E string }

func (key signingKey) publicKey() (*rsa.PublicKey, error) {
	n, nErr := base64.RawURLEncoding.DecodeString(key.N)
	e, eErr := base64.RawURLEncoding.DecodeString(key.E)
	exponent := new(big.Int).SetBytes(e)
	if nErr != nil || eErr != nil || len(n) < 256 || len(n) > 512 || !exponent.IsInt64() || exponent.Int64() != 65537 {
		return nil, errors.New("fixture JWKS key refused")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, nil
}

func loadKeys(client *http.Client, issuer string) (map[string]*rsa.PublicKey, error) {
	response, err := client.Get(issuer + "/protocol/openid-connect/certs")
	if err != nil {
		return nil, errors.New("fixture JWKS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || response.StatusCode != http.StatusOK || len(data) > 65536 {
		return nil, errors.New("fixture JWKS response refused")
	}
	return parseSigningKeys(data)
}

func parseSigningKeys(data []byte) (map[string]*rsa.PublicKey, error) {
	var document struct {
		Keys []signingKey
	}
	if json.Unmarshal(data, &document) != nil {
		return nil, errors.New("fixture JWKS is malformed")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, key := range document.Keys {
		if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
			continue
		}
		if key.Kid == "" || keys[key.Kid] != nil {
			return nil, errors.New("fixture JWKS key refused")
		}
		parsed, err := key.publicKey()
		if err != nil {
			return nil, err
		}
		keys[key.Kid] = parsed
	}
	if len(keys) == 0 {
		return nil, errors.New("fixture JWKS contains no signing key")
	}
	return keys, nil
}

func (v verifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusUnauthorized
	defer func() {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "{\"allowed\":%t}\n", status == http.StatusOK)
	}()
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" || len(raw) > 16384 || raw == r.Header.Get("Authorization") {
		return
	}
	claims, err := v.claims(raw)
	if err != nil {
		return
	}
	status = http.StatusForbidden
	resource := v.config.Resources[r.URL.Path]
	scope := r.URL.Query().Get("scope")
	if resource == "" || scope != "read" && scope != "write" || r.Method != http.MethodGet {
		return
	}
	if allowedPermission(claims, resource, scope) {
		status = http.StatusOK
	}
}

func (v verifier) claims(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key := v.keys[kid]
		if key == nil {
			return nil, errors.New("unknown fixture signing key")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.config.Issuer), jwt.WithAudience(v.config.Audience), jwt.WithExpirationRequired())
	audiences, audErr := claims.GetAudience()
	if err != nil || audErr != nil || len(audiences) != 1 || audiences[0] != v.config.Audience {
		return nil, errors.New("fixture access token refused")
	}
	return claims, nil
}

func allowedPermission(claims jwt.MapClaims, resource, scope string) bool {
	authorization, _ := claims["authorization"].(map[string]any)
	permissions, _ := authorization["permissions"].([]any)
	for _, permission := range permissions {
		value, _ := permission.(map[string]any)
		scopes, _ := value["scopes"].([]any)
		if value["rsid"] == resource && slices.Contains(scopes, any(scope)) {
			return true
		}
	}
	return false
}

func serve(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("fixture configuration unavailable")
	}
	var config configuration
	if json.Unmarshal(data, &config) != nil || !strings.HasPrefix(config.Issuer, "https://") || config.Audience == "" || len(config.Resources) != 2 {
		return errors.New("fixture configuration refused")
	}
	ca, err := os.ReadFile("/ca/ca.crt")
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return errors.New("fixture CA unavailable")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	keys, err := loadKeys(client, config.Issuer)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: ":8445", Handler: verifier{config, keys}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32768, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	return server.ListenAndServeTLS("/tls/tls.crt", "/tls/tls.key")
}

func main() {
	path := flag.String("config", "/fixture/settings.json", "Disposable public resource configuration")
	flag.Parse()
	if serve(*path) != nil {
		fmt.Fprintln(os.Stderr, "Disposable resource server failed; private diagnostics withheld")
		os.Exit(1)
	}
}
