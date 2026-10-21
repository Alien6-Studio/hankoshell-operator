package observability

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
}
func (ca testCA) issue(t *testing.T, identity string, server, expired bool) ([]byte, []byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		cert.DNSNames = []string{"localhost"}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		u, parseErr := url.Parse(identity)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		cert.URIs = []*url.URL{u}
	}
	if expired {
		cert.NotAfter = time.Now().Add(-time.Minute)
	}
	raw, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, pair
}
func tlsFiles(t *testing.T, ca testCA) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key, _ := ca.issue(t, "", true, false)
	for name, data := range map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": ca.pem} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "ca.crt")
}
func TestMetricsMutualTLSAuthenticatesAuthorizesAndReloadsTrust(t *testing.T) {
	ca, foreign := newCA(t), newCA(t)
	identity := "spiffe://monitoring.example/prometheus/platform"
	dir, caFile := tlsFiles(t, ca)
	configure, err := MetricsTLS(dir, caFile, []string{identity})
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{}
	configure(config)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("public metrics")) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	_, _, valid := ca.issue(t, identity, false, false)
	_, _, wrongURI := ca.issue(t, "spiffe://monitoring.example/unapproved", false, false)
	_, _, wrongCA := foreign.issue(t, identity, false, false)
	_, _, expired := ca.issue(t, identity, false, true)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	scrape := func(cert *tls.Certificate, maxVersion uint16) error {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}}
		if cert != nil {
			transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		response, requestErr := client.Get(server.URL + "/metrics")
		if response != nil {
			response.Body.Close()
		}
		return requestErr
	}
	for _, test := range []struct {
		name    string
		cert    *tls.Certificate
		version uint16
		allowed bool
	}{{"approved", &valid, tls.VersionTLS13, true}, {"anonymous", nil, tls.VersionTLS13, false}, {"wrong-uri", &wrongURI, tls.VersionTLS13, false}, {"foreign-ca", &wrongCA, tls.VersionTLS13, false}, {"expired", &expired, tls.VersionTLS13, false}, {"tls12", &valid, tls.VersionTLS12, false}} {
		t.Run(test.name, func(t *testing.T) {
			if err := scrape(test.cert, test.version); (err == nil) != test.allowed {
				t.Fatalf("allowed=%v, error=%v", test.allowed, err)
			}
		})
	}
	if err := os.WriteFile(caFile, foreign.pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := scrape(&valid, tls.VersionTLS13); err == nil {
		t.Fatal("revoked CA still authorized a new connection")
	}
	if err := os.WriteFile(caFile, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scrape(&wrongCA, tls.VersionTLS13); err == nil {
		t.Fatal("invalid rotated trust fell back to old or system roots")
	}
}
func TestMetricsTLSRejectsMissingAndUnboundedAuthority(t *testing.T) {
	ca := newCA(t)
	dir, file := tlsFiles(t, ca)
	for _, identities := range [][]string{nil, {"*"}, {"https://monitoring.example/client"}, {"spiffe://example/client?token=secret"}, {"spiffe://example/client", "spiffe://example/client"}} {
		if _, err := MetricsTLS(dir, file, identities); err == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	if _, err := MetricsTLS(t.TempDir(), file, []string{"spiffe://example/client"}); err == nil {
		t.Fatal("missing server key accepted")
	}
}
