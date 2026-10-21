package roles

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// roleObservation is an explicit private semantic projection. Owner IDs,
// credentials, provider IDs and timestamps never enter its canonical bytes.
type roleObservation struct {
	Present                bool
	Ownership              string
	Description            string
	Composite              bool
	Composites             []string
	EffectiveComposites    []string
	Attributes             map[string][]string
	Complete               bool
	NativeClientComposites bool
}

func observeRole(got *keycloak.RealmRole, p Plan, direct, closure []string, nativeClientComposites bool) State {
	o := roleObservation{Ownership: "absent", Composites: []string{}, Attributes: map[string][]string{}, Complete: true}
	state := State{Drifted: true}
	if got != nil {
		o.Present, state.Present, state.Owned = true, true, owned(got, p)
		o.Ownership = "unmarked"
		if len(got.Attributes[OwnerAttribute]) > 0 {
			o.Ownership = "foreign"
		}
		if state.Owned {
			o.Ownership = "owned"
		}
		o.Description, o.Composite = got.Description, got.Composite
		for _, name := range direct {
			if name != p.intent.Name {
				o.Composites = append(o.Composites, name)
			}
		}
		o.Composites = Normalize(Intent{Composites: o.Composites}).Composites
		o.EffectiveComposites = Normalize(Intent{Composites: closure}).Composites
		o.Attributes = cloneAttributes(got.Attributes)
		delete(o.Attributes, OwnerAttribute)
		delete(o.Attributes, "hanko.sh/adoption-receipt")
		metadataComplete := filterRoleObservationAttributes(o.Attributes)
		metadataComplete = projectRoleMetadata(o.Attributes, p) && metadataComplete
		o.NativeClientComposites = nativeClientComposites
		o.Complete = metadataComplete && (!nativeClientComposites || keycloak.ValidRoleAdoptionReceipt(got, p.resolved.Owner) && keycloak.QualifiedRoleAttributes(got.Attributes))
		// Composition is additive: false does not authorize removing extra
		// provider composites. An explicitly requested composite must exist.
		state.Drifted = roleContractDrift(got, p, o, metadataComplete, state.Owned)
		if !metadataComplete {
			state.Findings = []iamcontract.Finding{{Classification: iamcontract.Unsupported, ObjectKind: "role", Code: "native_metadata_not_observed", Message: "credential-shaped native metadata is excluded from observation", ReadOnly: true}}
		}
	}
	if nativeClientComposites && !o.Complete {
		state.Findings = append(state.Findings, iamcontract.Finding{Classification: iamcontract.Unsupported, ObjectKind: "role", Code: "native_client_composites", Message: "client-role composite identity is outside the supported realm-role observation contract", ReadOnly: true})
	}
	data, _ := json.Marshal(o)
	state.Observation = iamcontract.Observation{StateHash: iamcontract.Hash(iamcontract.Version, "roles", "observation", data), Complete: o.Complete, Drifted: state.Drifted}
	return state
}

func filterRoleObservationAttributes(attributes map[string][]string) bool {
	complete := true
	for key := range attributes {
		if validateNativeAttributes(map[string][]string{key: nil}) != nil {
			delete(attributes, key)
			complete = false
		}
	}
	return complete
}

func roleContractDrift(got *keycloak.RealmRole, p Plan, o roleObservation, metadataComplete, owned bool) bool {
	if !metadataComplete || !owned || got.Description != p.intent.Description || (p.intent.Composite && !got.Composite) || !roleAttributesMatch(o.Attributes, p.resolved.Attributes, got.Attributes["hanko.sh/adoption-receipt"] != nil) {
		return true
	}
	for _, child := range p.intent.Composites {
		if !slices.Contains(o.Composites, child) {
			return true
		}
	}
	return false
}

func roleAttributesMatch(actual, desired map[string][]string, adopted bool) bool {
	if !adopted {
		return maps.EqualFunc(actual, desired, slices.Equal[[]string])
	}
	for key, values := range desired {
		if !slices.Equal(actual[key], values) {
			return false
		}
	}
	return true
}

func projectRoleMetadata(attrs map[string][]string, p Plan) bool {
	complete := true
	for key, values := range attrs {
		if keycloak.QualifiedNativeLocale(key, values) {
			continue
		}
		if expected, declared := p.resolved.Attributes[key]; declared {
			if !slices.Equal(values, expected) {
				attrs[key] = []string{"<different-from-intent>"}
			}
		} else {
			delete(attrs, key)
			complete = false
		}
	}
	return complete
}
