package httpsecurity

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzJSONDocument(f *testing.F) {
	for _, seed := range []string{`null`, `{}`, `{"role":1,"role":2}`, `{"role":1,"r\u006fle":2}`, `{}[]`, strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33), "\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := ValidateJSON(data)
		if err == nil && !json.Valid(data) {
			t.Fatal("accepted invalid JSON")
		}
		if err != nil && err.Error() != "remote JSON document is ambiguous or incomplete" {
			t.Fatal("remote input entered diagnostic")
		}
		if err == nil && ValidateJSON(append(append([]byte{}, data...), []byte(" null")...)) == nil {
			t.Fatal("accepted trailing value")
		}
	})
}
