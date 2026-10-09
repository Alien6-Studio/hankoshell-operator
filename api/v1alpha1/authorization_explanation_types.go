package v1alpha1

// AuthorizationExplanation describes bounded structural allow alternatives.
// Complete does not mean that any runtime subject has been evaluated. Hashes
// and paths are evidence only and never authorize adoption, execution or deletion.
type AuthorizationExplanation struct {
	// +kubebuilder:validation:Minimum=0
	SourceGeneration int64 `json:"sourceGeneration"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SourcePlanHash string `json:"sourcePlanHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SourceObservationHash string `json:"sourceObservationHash"`
	// Applied requires matching current Manage read-back. Observed proves no application.
	// +kubebuilder:validation:Enum=Applied;Observed
	Source    string `json:"source"`
	Complete  bool   `json:"complete"`
	Truncated bool   `json:"truncated"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ExplanationHash string `json:"explanationHash"`
	// +kubebuilder:validation:MaxItems=256
	Paths []AuthorizationExplanationPath `json:"paths"`
}

// AuthorizationExplanationPath is one observed resource/scope/policy allow
// alternative. Different proven origins remain separate even when access overlaps.
type AuthorizationExplanationPath struct {
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	Permission string `json:"permission"`
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	Action string `json:"action"`
	// +kubebuilder:validation:Enum=organization;realm_role;application;service_account
	SourceKind string `json:"sourceKind"`
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	SourceRef string `json:"sourceRef"`
	// +kubebuilder:validation:MaxLength=255
	OrganizationRef string `json:"organizationRef,omitempty"`
	// +kubebuilder:validation:Enum=direct;descendant;generic;mapped_role;mapped_composite_role;mapped_client_role
	Relationship string `json:"relationship"`
	// Ordered HankoOrganization refs, at most 32 edges. No provider paths or IDs.
	// +kubebuilder:validation:MaxItems=33
	// +kubebuilder:validation:items:MaxLength=255
	Ancestry []string `json:"ancestry,omitempty"`
	// Ordered proven role mappings/composite edges, at most 32 edges.
	// +kubebuilder:validation:MaxItems=33
	RoleChain []AuthorizationExplanationRoleStep `json:"roleChain,omitempty"`
}
type AuthorizationExplanationRoleStep struct {
	// +kubebuilder:validation:Enum=realm_role;client_role
	Kind string `json:"kind"`
	// Declared HankoRole ref or declared domain role name.
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	Ref string `json:"ref"`
	// Declared clientID, never a provider UUID.
	// +kubebuilder:validation:MaxLength=255
	Client string `json:"client,omitempty"`
}
