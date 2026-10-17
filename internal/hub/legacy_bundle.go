package hub

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
)

// Match the signed Fleet aggregate budget. Enforce it before allocating a
// RawMessage per object, serializing the HMAC payload or issuing Kubernetes I/O.
const maxLegacyBundleObjects = 200

func refuseHubRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func legacyBundleObjectCount(b *Bundle) int {
	return len(b.IAMProfiles) + len(b.Realms) + len(b.Apps) + len(b.Themes) + len(b.ServiceAccounts)
}

func decodeLegacyBundle(body []byte) (*SignedBundle, error) {
	invalid := errors.New("invalid or oversized hub bundle")
	if httpsecurity.ValidateJSON(body) != nil {
		return nil, invalid
	}
	var envelope struct {
		Bundle    json.RawMessage `json:"bundle"`
		Signature string          `json:"signature"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, invalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Bundle, &fields) != nil || fields == nil {
		return nil, invalid
	}
	sb := &SignedBundle{Signature: envelope.Signature}
	if v := fields["version"]; len(v) != 0 && json.Unmarshal(v, &sb.Bundle.Version) != nil {
		return nil, invalid
	}
	if v := fields["tenantID"]; len(v) != 0 && json.Unmarshal(v, &sb.Bundle.TenantID) != nil {
		return nil, invalid
	}
	count := 0
	if err := decodeLegacyGroups(fields, &sb.Bundle, &count); err != nil {
		return nil, err
	}
	return sb, nil
}

func decodeLegacyGroups(fields map[string]json.RawMessage, bundle *Bundle, count *int) error {
	for _, group := range []struct {
		name string
		out  *[]json.RawMessage
	}{{"iamProfiles", &bundle.IAMProfiles}, {"realms", &bundle.Realms}, {"apps", &bundle.Apps}, {"themes", &bundle.Themes}, {"serviceAccounts", &bundle.ServiceAccounts}} {
		raw := fields[group.name]
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			continue
		}
		if err := decodeLegacyGroup(raw, group.out, count); err != nil {
			return err
		}
	}
	return nil
}

func decodeLegacyGroup(raw []byte, out *[]json.RawMessage, count *int) error {
	invalid := errors.New("invalid or oversized hub bundle")
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return invalid
	}
	for d.More() {
		if *count >= maxLegacyBundleObjects {
			return invalid
		}
		var object json.RawMessage
		if d.Decode(&object) != nil {
			return invalid
		}
		*out = append(*out, object)
		*count++
	}
	return nil
}
