package workloadtrust

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

const PublicDocumentLimit = 1 << 20

type DiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

type DiscoveryEvidence struct{ Issuer, JWKSURL, KeysHash, DocumentHash string }

// ReadPublicDocument has no authentication path. Redirects, unexpected origins,
// oversized/trailing JSON and missing source fields are refused.
func ReadPublicDocument(ctx context.Context, c *http.Client, endpoint string, target any) error {
	if !ValidHTTPS(endpoint) {
		return ErrDiscovery
	}
	secured, err := httpsecurity.RequireHTTPS(c, endpoint)
	if err != nil {
		return ErrDiscovery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrDiscovery
	}
	response, err := secured.Do(req)
	if err != nil {
		return ErrDiscovery
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrDiscovery
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, PublicDocumentLimit+1))
	if err != nil || len(data) > PublicDocumentLimit {
		return ErrDiscovery
	}
	return decodePublicDocument(data, target)
}

func decodePublicDocument(data []byte, target any) error {
	if len(data) > PublicDocumentLimit || httpsecurity.ValidateJSON(data) != nil || json.Unmarshal(data, target) != nil {
		return ErrDiscovery
	}
	return nil
}

// PublicKeysHash is a closed public-key projection. Secret/symmetric keys,
// unknown fields, duplicates and incomplete keysets cannot become evidence.
func PublicKeysHash(data []byte) (string, error) {
	var document struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if len(data) > PublicDocumentLimit || httpsecurity.ValidateJSON(data) != nil || json.Unmarshal(data, &document) != nil || len(document.Keys) == 0 || len(document.Keys) > 64 {
		return "", ErrDiscovery
	}
	keys := []map[string]string{}
	seen := map[string]bool{}
	for _, raw := range document.Keys {
		key, err := qualifiedPublicKey(raw)
		if err != nil || seen[key["kid"]] {
			return "", ErrDiscovery
		}
		seen[key["kid"]] = true
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b map[string]string) int {
		if a["kid"] < b["kid"] {
			return -1
		}
		if a["kid"] > b["kid"] {
			return 1
		}
		return 0
	})
	return Digest("public-signing-keys", keys), nil
}

func qualifiedPublicKey(raw map[string]json.RawMessage) (map[string]string, error) {
	key := map[string]string{}
	for name, value := range raw {
		switch name {
		case "kty", "kid", "use", "alg", "n", "e", "x", "y", "crv":
		default:
			return nil, ErrDiscovery
		}
		var text string
		if json.Unmarshal(value, &text) != nil || text == "" || len(text) > 4096 {
			return nil, ErrDiscovery
		}
		key[name] = text
	}
	if !validPublicKey(key) {
		return nil, ErrDiscovery
	}
	return key, nil
}

func validPublicKey(key map[string]string) bool {
	if key["kid"] == "" || key["use"] != "" && key["use"] != "sig" {
		return false
	}
	switch key["kty"] {
	case "RSA":
		return key["n"] != "" && key["e"] != "" && key["x"] == "" && key["y"] == ""
	case "EC":
		return key["x"] != "" && key["y"] != "" && key["crv"] != "" && key["n"] == "" && key["e"] == ""
	default:
		return false
	}
}

func ValidateDiscovery(ctx context.Context, c *http.Client, i Intent, current DiscoveryEvidence) (DiscoveryEvidence, error) {
	base := i.Issuer
	if i.DiscoveryURL != "" {
		if !SupportsDiscoveryOverride(i.QualifiedVersion) {
			return DiscoveryEvidence{}, ErrDiscovery
		}
		base = i.DiscoveryURL
	}
	endpoint := base
	// Native issuerDiscoveryUrl is an issuer base, not a full document path.
	endpoint += "/.well-known/openid-configuration"
	var document DiscoveryDocument
	if err := ReadPublicDocument(ctx, c, endpoint, &document); err != nil {
		return DiscoveryEvidence{}, err
	}
	if document.Issuer != i.Issuer || document.Issuer != current.Issuer || !ValidHTTPS(document.JWKSURL) {
		return DiscoveryEvidence{}, ErrDiscovery
	}
	approved, _ := url.Parse(base)
	jwks, _ := url.Parse(document.JWKSURL)
	// The actual current API document independently approves its JWKS endpoint.
	// Otherwise only the explicitly approved discovery authority is admitted.
	if jwks.Host != approved.Host && document.JWKSURL != current.JWKSURL {
		return DiscoveryEvidence{}, ErrDiscovery
	}
	var keys json.RawMessage
	if err := ReadPublicDocument(ctx, c, document.JWKSURL, &keys); err != nil {
		return DiscoveryEvidence{}, err
	}
	hash, err := PublicKeysHash(keys)
	if err != nil || hash != current.KeysHash {
		return DiscoveryEvidence{}, ErrDiscovery
	}
	return DiscoveryEvidence{document.Issuer, document.JWKSURL, hash, Digest("discovery", document)}, nil
}
