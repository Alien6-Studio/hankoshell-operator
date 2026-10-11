package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workloadConnection struct {
	instance          api.HankoKeycloakInstance
	client            *keycloak.Client
	identity          adoption.ProviderIdentity
	credentialUID     types.UID
	credentialVersion string
	caUID             types.UID
	caVersion         string
}

// A connection is built from one uncached Secret read, shared by TLS setup and
// source identity. Subsequent snapshots read the API again.
type workloadCAReader struct {
	client.Reader
	key client.ObjectKey
	ca  *corev1.Secret
}

func (r workloadCAReader) Get(ctx context.Context, key client.ObjectKey, target client.Object, opts ...client.GetOption) error {
	if ca, ok := target.(*corev1.Secret); ok && r.ca != nil && key == r.key {
		r.ca.DeepCopyInto(ca)
		return nil
	}
	return r.Reader.Get(ctx, key, target, opts...)
}

func (r *HankoWorkloadTrustReconciler) workloadConnection(ctx context.Context, namespace, name string) (workloadConnection, error) {
	var instance api.HankoKeycloakInstance
	if r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &instance) != nil || instance.UID == "" || !instance.DeletionTimestamp.IsZero() {
		return workloadConnection{}, trustFailure("SourceUnavailable")
	}
	var credential corev1.Secret
	if r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: instance.Spec.AdminRef.Name}, &credential) != nil || credential.UID == "" || !credential.DeletionTimestamp.IsZero() {
		return workloadConnection{}, trustFailure("SourceUnavailable")
	}
	reader := workloadCAReader{Reader: r.APIReader}
	if instance.Spec.TLSCARef != "" {
		reader.key = client.ObjectKey{Namespace: namespace, Name: instance.Spec.TLSCARef}
		reader.ca = &corev1.Secret{}
		if r.APIReader.Get(ctx, reader.key, reader.ca) != nil || reader.ca.UID == "" || !reader.ca.DeletionTimestamp.IsZero() {
			return workloadConnection{}, trustFailure("SourceUnavailable")
		}
	}
	kc, err := buildKCClientFromAdminSecret(ctx, reader, &instance, &credential, "HANKO_KC_CLIENT_SECRET", true)
	if err != nil {
		return workloadConnection{}, trustFailure("SourceUnavailable")
	}
	identity, err := adoptionSourceIdentity(ctx, reader, &instance, kc, "")
	if err != nil || identity.Trust == "explicit-http" {
		return workloadConnection{}, trustFailure("SourceUnavailable")
	}
	connection := workloadConnection{instance: instance, client: kc, identity: identity, credentialUID: credential.UID, credentialVersion: credential.ResourceVersion}
	if instance.Spec.TLSCARef != "" {
		connection.caUID = reader.ca.UID
		connection.caVersion = reader.ca.ResourceVersion
	}
	return connection, nil
}

func workloadCAIdentity(p adoption.ProviderIdentity) string {
	if at := strings.LastIndex(p.CAIdentity, ":sha256:"); at >= 0 {
		return p.CAIdentity[at+1:]
	}
	return p.CAIdentity
}
func sameWorkloadConnection(a, b workloadConnection) bool {
	return a.identity.Origin == b.identity.Origin && a.identity.Trust == b.identity.Trust && workloadCAIdentity(a.identity) == workloadCAIdentity(b.identity)
}

// configuredAPICA uses the same explicit TLS input used by the controller's
// Kubernetes transport. No workload Secret/JWT/TokenRequest/TokenReview is read.
func (r *HankoWorkloadTrustReconciler) configuredAPICA() ([]byte, string, error) {
	if r.ClusterConfig == nil || r.ClusterConfig.Insecure || !workloadtrust.ValidHTTPS(r.ClusterConfig.Host) {
		return nil, "", trustFailure("AnchorMismatch")
	}
	config := rest.CopyConfig(r.ClusterConfig)
	if rest.LoadTLSFiles(config) != nil {
		return nil, "", trustFailure("AnchorMismatch")
	}
	hash, err := workloadtrust.APICAHash(config.CAData)
	if err != nil {
		return nil, "", trustFailure("AnchorMismatch")
	}
	return config.CAData, hash, nil
}

func (r *HankoWorkloadTrustReconciler) validateWorkloadCluster(ctx context.Context, anchor api.WorkloadClusterAnchor) error {
	var namespace corev1.Namespace
	if r.APIReader.Get(ctx, types.NamespacedName{Name: "kube-system"}, &namespace) != nil || namespace.UID == "" || !namespace.DeletionTimestamp.IsZero() || string(namespace.UID) != anchor.KubeSystemNamespaceUID {
		return trustFailure("AnchorMismatch")
	}
	_, hash, err := r.configuredAPICA()
	if err != nil || hash != anchor.APIServerCAHash {
		return trustFailure("AnchorMismatch")
	}
	return nil
}

// API discovery is read using the normal controller Kubernetes API transport,
// exclusively against its configured API origin. Its ordinary authentication
// remains transport-private; no runtime assertion is issued, decoded or stored.
func (r *HankoWorkloadTrustReconciler) currentWorkloadDiscovery(ctx context.Context, i workloadtrust.Intent) (workloadtrust.DiscoveryEvidence, error) {
	ca, _, err := r.configuredAPICA()
	if err != nil {
		return workloadtrust.DiscoveryEvidence{}, err
	}
	apiHTTP, err := rest.HTTPClientFor(rest.CopyConfig(r.ClusterConfig))
	if err != nil {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("SourceUnavailable")
	}
	apiHTTP.Timeout = 10 * time.Second
	apiHTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer apiHTTP.CloseIdleConnections()
	read := func(path string, target any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(r.ClusterConfig.Host, "/")+path, nil)
		if err != nil {
			return workloadtrust.ErrDiscovery
		}
		response, err := apiHTTP.Do(req)
		if err != nil {
			return workloadtrust.ErrDiscovery
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return workloadtrust.ErrDiscovery
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, workloadtrust.PublicDocumentLimit+1))
		if err != nil || len(data) > workloadtrust.PublicDocumentLimit || httpsecurity.ValidateJSON(data) != nil || json.Unmarshal(data, target) != nil {
			return workloadtrust.ErrDiscovery
		}
		return nil
	}
	var document workloadtrust.DiscoveryDocument
	if read("/.well-known/openid-configuration", &document) != nil || document.Issuer != i.Issuer || !workloadtrust.ValidHTTPS(document.JWKSURL) {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("DiscoverySourceMismatch")
	}
	var publicKeys json.RawMessage
	if read("/openid/v1/jwks", &publicKeys) != nil {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("DiscoverySourceMismatch")
	}
	keysHash, err := workloadtrust.PublicKeysHash(publicKeys)
	if err != nil {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("DiscoverySourceMismatch")
	}
	current := workloadtrust.DiscoveryEvidence{Issuer: document.Issuer, JWKSURL: document.JWKSURL, KeysHash: keysHash, DocumentHash: workloadtrust.Digest("discovery", document)}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(ca) {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("AnchorMismatch")
	}
	publicHTTP := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}}
	defer publicHTTP.CloseIdleConnections()
	qualified, err := workloadtrust.ValidateDiscovery(ctx, publicHTTP, i, current)
	if err != nil {
		return workloadtrust.DiscoveryEvidence{}, trustFailure("DiscoverySourceMismatch")
	}
	return qualified, nil
}
