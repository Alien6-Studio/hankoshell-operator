package observability

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

var ErrMetricsTLS = errors.New("metrics requires valid server TLS, a client CA and authorized SPIFFE URI identities")

const maxTLSFileBytes = 64 << 10

func readTLSFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrMetricsTLS
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTLSFileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxTLSFileBytes {
		return nil, ErrMetricsTLS
	}
	return data, nil
}

// MetricsTLS fails at startup when credentials are absent. Every handshake
// reloads the projected Secret files and verifies both client trust and exact
// URI authorization. Session resumption is disabled so trust revocation wins.
func MetricsTLS(certDir, caFile string, identities []string) (func(*tls.Config), error) {
	if certDir == "" || caFile == "" {
		return nil, ErrMetricsTLS
	}
	if len(identities) == 0 || len(identities) > 16 {
		return nil, ErrMetricsTLS
	}
	allowed := make(map[string]bool, len(identities))
	for _, identity := range identities {
		if !validMetricsIdentity(identity) || allowed[identity] {
			return nil, ErrMetricsTLS
		}
		allowed[identity] = true
	}
	load := func() (*tls.Config, error) { return loadMetricsTLS(certDir, caFile, allowed) }
	if _, err := load(); err != nil {
		return nil, err
	}
	return func(config *tls.Config) {
		config.MinVersion = tls.VersionTLS13
		config.NextProtos = []string{"http/1.1"}
		config.SessionTicketsDisabled = true
		// Setting GetCertificate prevents controller-runtime's self-signed fallback.
		config.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			current, err := load()
			if err != nil {
				return nil, err
			}
			return &current.Certificates[0], nil
		}
		config.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) { return load() }
	}, nil
}

func loadMetricsTLS(certDir, caFile string, allowed map[string]bool) (*tls.Config, error) {
	certPEM, err := readTLSFile(filepath.Join(certDir, "tls.crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(filepath.Join(certDir, "tls.key"))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, ErrMetricsTLS
	}
	caPEM, err := readTLSFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, ErrMetricsTLS
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return ErrMetricsTLS
		}
		for _, identity := range state.PeerCertificates[0].URIs {
			if allowed[identity.String()] {
				return nil
			}
		}
		return ErrMetricsTLS
	}}, nil
}

func validMetricsIdentity(identity string) bool {
	u, err := url.Parse(identity)
	return err == nil && len(identity) <= 256 && u.Scheme == "spiffe" && u.Host != "" && u.User == nil && u.Path != "" && u.RawQuery == "" && u.Fragment == ""
}
