package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	hanko "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

const managedTLSMount = "/opt/keycloak/conf/hanko-tls"

type managedTransport struct {
	port     int32
	name     string
	args     []string
	endpoint string
}

func managedListener(ki *hanko.HankoKeycloakInstance, requireHTTPS bool) (managedTransport, error) {
	managed := ki.Spec.Managed
	if managed == nil {
		return managedTransport{}, fmt.Errorf("mode=managed requires spec.managed")
	}
	if managed.AllowInsecureHTTP {
		if requireHTTPS || os.Getenv("HANKO_SECURITY_PROFILE") == "enterprise" ||
			os.Getenv("HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP") != "true" || managed.TLSSecretRef != "" || ki.Spec.TLSCARef != "" {
			return managedTransport{}, fmt.Errorf("managed HTTP requires both explicit HTTP acknowledgements in standard profile, without serving TLS or CA references")
		}
		return managedTransport{port: 8080, name: "http", args: []string{"--http-enabled=true", "--http-port=8080"}}, nil
	}
	if managed.TLSSecretRef == "" {
		return managedTransport{}, fmt.Errorf("managed HTTPS requires spec.managed.tlsSecretRef")
	}
	if managed.TLSSecretRef == ki.Spec.AdminRef.Name || managed.TLSSecretRef == managed.Database.Name {
		return managedTransport{}, fmt.Errorf("managed serving TLS Secret must be separate from AdminRef and database Secrets")
	}
	protocols := "TLSv1.3,TLSv1.2"
	if requireHTTPS || os.Getenv("HANKO_SECURITY_PROFILE") == "enterprise" {
		protocols = "TLSv1.3"
	}
	return managedTransport{port: 8443, name: "https", args: []string{
		"--http-enabled=false", "--https-port=8443", "--https-protocols=" + protocols,
		"--https-certificate-file=" + managedTLSMount + "/tls.crt",
		"--https-certificate-key-file=" + managedTLSMount + "/tls.key",
	}}, nil
}

// managedServerTransport validates endpoint/listener agreement and the serving
// certificate before any infrastructure mutation. It never derives server TLS
// from the presence or absence of the client's CA Secret.
func (r *HankoKeycloakInstanceReconciler) managedServerTransport(ctx context.Context, ki *hanko.HankoKeycloakInstance) (managedTransport, error) {
	transport, err := managedListener(ki, r.RequireHTTPS)
	if err != nil {
		return managedTransport{}, err
	}
	var admin corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: ki.Namespace, Name: ki.Spec.AdminRef.Name}, &admin); err != nil {
		return managedTransport{}, fmt.Errorf("read managed AdminRef: %w", err)
	}
	endpoint := string(admin.Data["HANKO_KEYCLOAK_URL"])
	if err := keycloak.ValidateEndpoint(endpoint, transport.name == "http"); err != nil {
		return managedTransport{}, err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != transport.name {
		return managedTransport{}, fmt.Errorf("managed AdminRef endpoint must use the configured listener scheme")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return managedTransport{}, fmt.Errorf("managed AdminRef endpoint must use the root context path of the optimized image")
	}
	if transport.name == "https" {
		if err := r.validateManagedCertificate(ctx, ki, parsed.Hostname()); err != nil {
			return managedTransport{}, err
		}
	}
	transport.args = append(transport.args, "--hostname="+parsed.Scheme+"://"+parsed.Host,
		"--http-management-scheme=http", "--http-management-port=9000")
	transport.endpoint = endpoint
	return transport, nil
}

func (r *HankoKeycloakInstanceReconciler) validateManagedCertificate(ctx context.Context, ki *hanko.HankoKeycloakInstance, hostname string) error {
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: ki.Namespace, Name: ki.Spec.Managed.TLSSecretRef}, &secret); err != nil {
		return fmt.Errorf("read managed serving TLS Secret: %w", err)
	}
	if secret.Type != corev1.SecretTypeTLS {
		return fmt.Errorf("managed serving Secret must have type kubernetes.io/tls")
	}
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("managed serving Secret requires a matching PEM certificate and private key")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || cert.VerifyHostname(hostname) != nil {
		return fmt.Errorf("managed serving certificate must cover the AdminRef endpoint hostname")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return fmt.Errorf("managed serving certificate is outside its validity window")
	}
	return nil
}
