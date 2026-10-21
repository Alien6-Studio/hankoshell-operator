package httpsecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ValidateJSON rejects duplicate members, excessive depth and trailing values.
// Its error is independent of remote content, which may be secret.
func ValidateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if jsonValue(d, 0) {
		if _, err := d.Token(); err == io.EOF {
			return nil
		}
	}
	return errors.New("remote JSON document is ambiguous or incomplete")
}

func jsonValue(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		return jsonObject(d, depth)
	case '[':
		return jsonArray(d, depth)
	default:
		return false
	}
}

func jsonObject(d *json.Decoder, depth int) bool {
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[name] || len(seen) >= 1024 {
			return false
		}
		seen[name] = true
		if !jsonValue(d, depth+1) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && end == json.Delim('}')
}

func jsonArray(d *json.Decoder, depth int) bool {
	for d.More() {
		if !jsonValue(d, depth+1) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && end == json.Delim(']')
}
