package workloadtrust

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
)

const CheckpointKey = "hanko.sh/workload-trust-checkpoint"
const CheckpointVersion = "hanko.sh/workload-trust-checkpoint/v1alpha1"

// Checkpoint remembers the physical source and UUID before an uncertain write.
// It contains public identifiers only and never substitutes for native ownership
// markers, the journal or a fresh complete observation.
type Checkpoint struct {
	Version    string `json:"version"`
	Owner      string `json:"owner"`
	ProviderID string `json:"providerID"`
	RealmID    string `json:"realmID"`
	SourceHash string `json:"sourceHash"`
	Step       string `json:"step"`
}

func (c Checkpoint) valid() bool {
	return c.Version == CheckpointVersion && ValidOwner(c.Owner) && ValidOwner(c.ProviderID) && ValidOwner(c.RealmID) && iamcontract.ValidDigest(c.SourceHash) && (c.Step == "CreateReserved" || c.Step == "CreateAttempted" || c.Step == "AdoptionPending" || c.Step == "Owned")
}

func ParseCheckpoint(value string) (Checkpoint, error) {
	var c Checkpoint
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if len(value) > 1024 || d.Decode(&c) != nil || !c.valid() {
		return Checkpoint{}, ErrOwnership
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Checkpoint{}, ErrOwnership
	}
	b, _ := json.Marshal(c)
	if string(b) != value {
		return Checkpoint{}, ErrOwnership
	}
	return c, nil
}

func (p Plan) Checkpoint(step string) (string, error) {
	c := Checkpoint{CheckpointVersion, p.refs.Owner, p.refs.ProviderID, p.refs.RealmID, p.refs.SourceHash, step}
	if !c.valid() {
		return "", ErrOwnership
	}
	b, _ := json.Marshal(c)
	return string(b), nil
}

func (c Checkpoint) Matches(p Plan) bool {
	return c.valid() && c.Owner == p.refs.Owner && c.ProviderID == p.refs.ProviderID && c.RealmID == p.refs.RealmID && c.SourceHash == p.refs.SourceHash
}
