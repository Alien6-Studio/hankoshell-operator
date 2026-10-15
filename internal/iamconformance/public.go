package iamconformance

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

// PublicFixture is non-secret desired state and independently frozen expected
// output. It is shared by compiler, real-API and installed conformance tests.
type PublicFixture struct {
	Name          string                   `json:"name"`
	Kind          string                   `json:"kind"`
	Spec          json.RawMessage          `json:"spec"`
	DefaultedSpec json.RawMessage          `json:"defaultedSpec"`
	Status        json.RawMessage          `json:"status"`
	Equivalent    []json.RawMessage        `json:"equivalent"`
	Identity      iamcontract.PlanIdentity `json:"identity"`
}

// PublicCorpus binds the candidate and its explicit predecessor limitation.
type PublicCorpus struct {
	SchemaVersion int             `json:"schemaVersion"`
	Release       string          `json:"release"`
	Predecessor   string          `json:"predecessor"`
	Limitation    string          `json:"limitation"`
	OwnerUID      string          `json:"ownerUID"`
	Fixtures      []PublicFixture `json:"fixtures"`
}

//go:embed testdata/public-*/corpus.json
var publicCorpora embed.FS

// ReadPublicCorpus rejects ambiguous fixture metadata rather than treating a
// missing predecessor or golden as a successful cross-release qualification.
func ReadPublicCorpus(name string) (PublicCorpus, error) {
	data, err := publicCorpora.ReadFile("testdata/" + name + "/corpus.json")
	if err != nil {
		return PublicCorpus{}, fmt.Errorf("read reviewed public corpus: %w", err)
	}
	var result PublicCorpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return PublicCorpus{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return PublicCorpus{}, errors.New("public corpus has trailing input")
	}
	if result.SchemaVersion != 1 || result.Release != "0.1.0-candidate" || result.OwnerUID == "" || len(result.Fixtures) == 0 ||
		(result.Predecessor == "" && result.Limitation != "NoPublishedPredecessor") {
		return PublicCorpus{}, errors.New("public corpus lacks a reviewed release/rollback boundary")
	}
	seen := map[string]bool{}
	for _, fixture := range result.Fixtures {
		if fixture.Name == "" || seen[fixture.Name] || !json.Valid(fixture.Spec) || !json.Valid(fixture.DefaultedSpec) {
			return PublicCorpus{}, errors.New("public corpus has duplicate, missing or invalid stored intent")
		}
		seen[fixture.Name] = true
	}
	return result, nil
}
