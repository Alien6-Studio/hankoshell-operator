package v1alpha1

// AdoptionReceiptStatus reports a live provider checkpoint, never write or
// deletion authority. A failed status update can be recovered from the provider.
type AdoptionReceiptStatus struct {
	// +kubebuilder:validation:Enum="hanko.sh/adoption-contract/v1alpha1"
	ContractVersion string `json:"contractVersion"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	CandidateHash string `json:"candidateHash"`
	// +kubebuilder:validation:Enum=Pending;Verified;Partial;Conflict
	State string `json:"state"`
}

// AdoptionTargetIdentity identifies a current object, never write authority.
type AdoptionTargetIdentity struct {
	// TenantRef binds connection-selecting target metadata without acquiring it.
	// +kubebuilder:validation:MaxLength=255
	TenantRef string `json:"tenantRef,omitempty"`
	// ImportRef binds the discovery latch without consuming it.
	// +kubebuilder:validation:MaxLength=255
	ImportRef string `json:"importRef,omitempty"`
	// +kubebuilder:validation:Minimum=0
	Generation int64 `json:"generation,omitempty"`
	// +kubebuilder:validation:MaxLength=64
	Kind string `json:"kind"`
	// +kubebuilder:validation:MaxLength=255
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// AdoptionProviderIdentity excludes AdminRef, credentials and credential hashes.
type AdoptionProviderIdentity struct {
	Instance AdoptionTargetIdentity `json:"instance"`
	// +kubebuilder:validation:MaxLength=2048
	Origin string `json:"origin"`
	// Unknown is reserved for incomplete diagnostic evidence.
	// +kubebuilder:validation:Enum=public-ca;private-ca;explicit-http;unknown
	Trust string `json:"trust"`
	// +kubebuilder:validation:MaxLength=255
	CAReference string `json:"caReference,omitempty"`
	// CAIdentity binds the public trust bundle and Secret UID.
	// +kubebuilder:validation:MaxLength=255
	CAIdentity string `json:"caIdentity,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	RealmID string `json:"realmID"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=512
	// +kubebuilder:validation:items:MaxLength=128
	ObjectIDs []string `json:"objectIDs,omitempty"`
}

// AdoptionValue contains only reviewed non-secret semantic fields.
type AdoptionValue struct {
	// +kubebuilder:validation:MaxLength=512
	Text string `json:"text,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1024
	// +kubebuilder:validation:items:MaxLength=512
	Set  []string `json:"set,omitempty"`
	Flag *bool    `json:"flag,omitempty"`
}

type AdoptionDiffEntry struct {
	// +kubebuilder:validation:MaxLength=64
	Domain string `json:"domain"`
	// +kubebuilder:validation:MaxLength=128
	Identity string `json:"identity"`
	// +kubebuilder:validation:MaxLength=255
	Object string `json:"object"`
	// +kubebuilder:validation:MaxLength=64
	Field string `json:"field"`
	// +kubebuilder:validation:Enum=equal;would-manage;would-change;would-preserve;provider-native-readonly;unsupported;credential-excluded;recreation-required;ownership-transition
	Code string `json:"code"`
	// +kubebuilder:validation:Enum=supported-typed-native;preserved-readonly-native;unsupported;conflicting;security-sensitive-excluded
	Classification string `json:"classification"`
	// +kubebuilder:validation:Enum=lossless-represented;preserved-native;lossy;unsupported
	RoundTrip string         `json:"roundTrip"`
	Current   *AdoptionValue `json:"current,omitempty"`
	Desired   *AdoptionValue `json:"desired,omitempty"`
}

type AdoptionFinding struct {
	// +kubebuilder:validation:MaxLength=512
	Code string `json:"code"`
	// +kubebuilder:validation:MaxLength=64
	Domain string `json:"domain"`
	// +kubebuilder:validation:MaxLength=512
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

// AdoptionCandidateStatus is review evidence for a possible future adoption.
// It is not approval, ownership, a receipt, or permission to enter Manage.
type AdoptionCandidateStatus struct {
	// +kubebuilder:validation:Enum="hanko.sh/adoption-contract/v1alpha1"
	ContractVersion  string                   `json:"contractVersion"`
	Target           AdoptionTargetIdentity   `json:"target"`
	ProviderIdentity AdoptionProviderIdentity `json:"providerIdentity"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservationHash string `json:"observationHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	DiffHash string `json:"diffHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	CandidateHash string `json:"candidateHash"`
	Complete      bool   `json:"complete"`
	Truncated     bool   `json:"truncated"`
	Approvable    bool   `json:"approvable"`
	// +kubebuilder:validation:MaxItems=256
	Diff []AdoptionDiffEntry `json:"diff,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	Findings []AdoptionFinding `json:"findings,omitempty"`
}

// ImportCoverage distinguishes inventory coverage from one-shot completion.
type ImportCoverage struct {
	Complete  bool `json:"complete"`
	Truncated bool `json:"truncated"`
	// +kubebuilder:validation:Minimum=0
	InventoryCount int `json:"inventoryCount"`
	// +kubebuilder:validation:Minimum=0
	CandidateCount int `json:"candidateCount"`
	// +kubebuilder:validation:Minimum=0
	UnsupportedCount int `json:"unsupportedCount"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservationHash string `json:"observationHash,omitempty"`
}

// ImportInventoryReference is a compact identity/coverage summary, not a diff.
type ImportInventoryReference struct {
	// +kubebuilder:validation:MaxLength=64
	Kind string `json:"kind"`
	// +kubebuilder:validation:MaxLength=255
	Realm string `json:"realm"`
	// +kubebuilder:validation:MaxLength=128
	ProviderID string                  `json:"providerID"`
	Target     *AdoptionTargetIdentity `json:"target,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	CandidateHash string `json:"candidateHash,omitempty"`
	Complete      bool   `json:"complete"`
	Approvable    bool   `json:"approvable"`
	// +kubebuilder:validation:MaxItems=32
	Findings []AdoptionFinding `json:"findings,omitempty"`
}
