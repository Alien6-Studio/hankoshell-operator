package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hrole,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoRole represents one realm-scoped role in Keycloak.
type HankoRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoRoleSpec   `json:"spec,omitempty"`
	Status HankoRoleStatus `json:"status,omitempty"`
}

// HankoRoleSpec defines the desired state of a realm role.
// Reserved authority role definitions are owned only by the canonical
// HankoRealm in the configured fleet authority realm.
// +kubebuilder:validation:XValidation:rule="self.name != 'HANKO_PLATFORM' && !self.name.startsWith('HANKO_PLATFORM_') && !self.name.startsWith('HANKO_FLEET_') && !self.name.startsWith('HANKO_CLUSTER_')",message="reserved platform, fleet and cluster roles cannot be defined by HankoRole"
// +kubebuilder:validation:XValidation:rule="!has(self.composites) || self.composites.all(r, r != 'HANKO_PLATFORM' && !r.startsWith('HANKO_PLATFORM_') && !r.startsWith('HANKO_FLEET_') && !r.startsWith('HANKO_CLUSTER_'))",message="reserved platform, fleet and cluster roles cannot be inherited through HankoRole composites"
type HankoRoleSpec struct {
	// RealmRef references the HankoRealm this role belongs to.
	// +kubebuilder:validation:Required
	RealmRef string `json:"realmRef"`

	// Name is the Keycloak realm role name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// Description is a human-readable description of the role.
	Description string `json:"description,omitempty"`

	// Composite marks this role as a composite role, aggregating the
	// permissions of the roles listed in Composites.
	Composite bool `json:"composite,omitempty"`

	// Composites lists child realm role names aggregated by this role when
	// Composite is true.
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=255
	Composites []string `json:"composites,omitempty"`

	// Attributes holds arbitrary key/value metadata attached to the role in
	// Keycloak. Values are lists of strings per Keycloak's representation.
	Attributes map[string][]string `json:"attributes,omitempty"`
}

// HankoRoleStatus describes the observed state of the realm role.
type HankoRoleStatus struct {
	// AdoptionCandidate is bounded review evidence, never execution authority.
	AdoptionCandidate *AdoptionCandidateStatus `json:"adoptionCandidate,omitempty"`

	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	// ObservedGeneration is the latest generation processed into this status,
	// including failures; it does not mean successfully applied.
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// EvaluatedGeneration is the latest generation whose execution semantics
	// were fully evaluated or definitively refused. It does not prove application.
	// +kubebuilder:validation:Minimum=0
	EvaluatedGeneration int64 `json:"evaluatedGeneration,omitempty"`

	// AppliedGeneration is the latest Manage generation proven by matching
	// provider read-back. Observe clears applied evidence and cannot advance it.
	// +kubebuilder:validation:Minimum=0
	AppliedGeneration int64 `json:"appliedGeneration,omitempty"`

	// ContractVersion identifies canonical evidence semantics, not an executable API.
	// +kubebuilder:validation:MaxLength=64
	ContractVersion string `json:"contractVersion,omitempty"`

	// IntentHash identifies normalized portable semantics of EvaluatedGeneration.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	IntentHash string `json:"intentHash,omitempty"`

	// EvaluatedPlanHash identifies the locally compiled provider-bound plan.
	// It is absent for rejected evaluation and is never execution authority.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	EvaluatedPlanHash string `json:"evaluatedPlanHash,omitempty"`

	// ObservedStateHash identifies safe normalized provider semantics, including
	// observation coverage. It is neither an intent/plan identity nor a provider ID.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservedStateHash string `json:"observedStateHash,omitempty"`

	// ObservationGeneration and ObservationPlanHash bind the latest successful
	// bounded read to its evaluated input. They remain unchanged on read failure.
	// +kubebuilder:validation:Minimum=0
	ObservationGeneration int64 `json:"observationGeneration,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservationPlanHash string `json:"observationPlanHash,omitempty"`

	// ObservationComplete distinguishes full supported-contract read-back from
	// partial coverage. A partial observation can prove drift but never equality.
	ObservationComplete bool `json:"observationComplete,omitempty"`

	// DriftState is the comparison for ObservationPlanHash. Failure conditions
	// describe the current attempt; an older observation is historical evidence.
	// +kubebuilder:validation:Enum=Unknown;InSync;Drifted
	DriftState string `json:"driftState,omitempty"`

	// CapabilityEvidence names static adapter qualification, not runtime discovery.
	CapabilityEvidence IAMCapabilityEvidence `json:"capabilityEvidence,omitempty"`

	// AppliedPlanHash identifies the latest Manage plan proven by matching read-back.
	// Observe clears applied evidence and cannot claim provider application.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	AppliedPlanHash string `json:"appliedPlanHash,omitempty"`
	// +kubebuilder:validation:MaxLength=32
	BackendKind  string                 `json:"backendKind,omitempty"`
	Capabilities RoleCapabilitySnapshot `json:"capabilities,omitempty"`
	// +listType=map
	// +listMapKey=classification
	// +listMapKey=objectKind
	// +listMapKey=objectName
	// +listMapKey=code
	// +kubebuilder:validation:MaxItems=32
	Findings []AuthorizationFinding `json:"findings,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoRoleList contains a list of HankoRole.
type HankoRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoRole `json:"items"`
}
