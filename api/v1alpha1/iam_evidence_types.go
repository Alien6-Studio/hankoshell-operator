package v1alpha1

// IAMCapabilityEvidence describes the adapter mapping's qualification. It does
// not claim to discover or qualify the installed provider version at runtime.
type IAMCapabilityEvidence struct {
	// +kubebuilder:validation:MaxLength=64
	Source string `json:"source,omitempty"`
	// +kubebuilder:validation:MaxLength=64
	QualificationWindow string `json:"qualificationWindow,omitempty"`
}

// RoleCapabilitySnapshot is domain-specific; it is not a global provider API.
type RoleCapabilitySnapshot struct {
	RealmRoles       bool `json:"realmRoles"`
	Composites       bool `json:"composites"`
	NativeAttributes bool `json:"nativeAttributes"`
}
