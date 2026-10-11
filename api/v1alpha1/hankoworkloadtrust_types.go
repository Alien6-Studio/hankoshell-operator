package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hwt,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Alias",type=string,JSONPath=".spec.keycloakAlias"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoWorkloadTrust owns one shared Kubernetes client-assertion trust. Ready
// qualifies configuration only; it never enables a workload client or handles JWTs.
type HankoWorkloadTrust struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HankoWorkloadTrustSpec   `json:"spec"`
	Status            HankoWorkloadTrustStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.realmRef == oldSelf.realmRef",message="realmRef is immutable; create a separately reviewed trust"
// +kubebuilder:validation:XValidation:rule="self.sourceRef == oldSelf.sourceRef",message="sourceRef is immutable; create a separately reviewed trust"
// +kubebuilder:validation:XValidation:rule="self.keycloakAlias == oldSelf.keycloakAlias",message="keycloakAlias is immutable; create a separately reviewed trust"
// +kubebuilder:validation:XValidation:rule="!has(self.kubernetes.discoveryURL) || (has(self.qualifiedKeycloakVersion) && self.qualifiedKeycloakVersion == '26.8.0')",message="discovery override requires explicit 26.8.0 source qualification"
type HankoWorkloadTrustSpec struct {
	// Imported-by always forces Observe. Explicit adoption is an ownership-only transaction.
	// +kubebuilder:validation:Enum=Manage;Observe
	// +kubebuilder:default=Manage
	Mode string `json:"mode,omitempty"`
	// RealmRef selects an existing HankoRealm in this namespace, including Observe realms.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	RealmRef string `json:"realmRef"`
	// SourceRef selects the canonical HankoKeycloakInstance connection. Observe uses its reader identity.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	SourceRef string `json:"sourceRef"`
	// WriterRef optionally selects a distinct instance credential for Manage or explicitly approved acquisition.
	// Its endpoint/CA must equal SourceRef. Observe without approval never loads this credential.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	WriterRef string `json:"writerRef,omitempty"`
	// DependentReaderRef selects a dedicated, distinct view-clients connection in this namespace.
	// The controller permits only target-realm client metadata GETs on that connection.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	DependentReaderRef string `json:"dependentReaderRef"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	KeycloakAlias string `json:"keycloakAlias"`
	// +kubebuilder:validation:Enum=Kubernetes
	Provider string `json:"provider"`
	// QualifiedKeycloakVersion is explicit administrator source qualification,
	// never copied from diagnostic status. Common behavior needs no version disclosure.
	// Discovery override additionally requires native resolved-source read-back.
	// +kubebuilder:validation:Enum="26.7.5";"26.8.0"
	QualifiedKeycloakVersion string                      `json:"qualifiedKeycloakVersion,omitempty"`
	Kubernetes               KubernetesWorkloadTrustSpec `json:"kubernetes"`
}

type KubernetesWorkloadTrustSpec struct {
	// Issuer is the exact approved HTTPS issuer of the controller's current cluster.
	// +kubebuilder:validation:MinLength=9
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://[a-z0-9\[\]:.-]+(/[A-Za-z0-9._~!$&'()*+,;=:@/-]*)?$`
	Issuer string `json:"issuer"`
	// DiscoveryURL is a source override qualified only on explicit 26.8.0 sources.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://[a-z0-9\[\]:.-]+(/[A-Za-z0-9._~!$&'()*+,;=:@/-]*)?$`
	DiscoveryURL  string                `json:"discoveryURL,omitempty"`
	ClusterAnchor WorkloadClusterAnchor `json:"clusterAnchor"`
	// +kubebuilder:validation:Minimum=600
	// +kubebuilder:validation:Maximum=3600
	// +kubebuilder:default=600
	AssertionMaxAgeSeconds int64 `json:"assertionMaxAgeSeconds,omitempty"`
}

type WorkloadClusterAnchor struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]*$`
	KubeSystemNamespaceUID string `json:"kubeSystemNamespaceUID"`
	// APIServerCAHash identifies the single configured public API CA certificate DER.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	APIServerCAHash string `json:"apiServerCAHash"`
}

type WorkloadTrustCapabilities struct {
	KubernetesWorkloadIdentity bool `json:"kubernetesWorkloadIdentity"`
	// FederatedClientAuthentication reports only the observed flow prerequisite.
	FederatedClientAuthentication bool `json:"federatedClientAuthentication"`
	ShortLivedClientAssertion     bool `json:"shortLivedClientAssertion"`
	// SecretFallback remains false: no workload credential transition is implemented here.
	SecretFallback          bool `json:"secretFallback"`
	IssuerDiscoveryOverride bool `json:"issuerDiscoveryOverride"`
}

type HankoWorkloadTrustStatus struct {
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	ProviderID string `json:"providerID,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	RealmID string `json:"realmID,omitempty"`
	// +kubebuilder:validation:MaxLength=64
	ContractVersion string `json:"contractVersion,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	IntentHash string `json:"intentHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	EvaluatedPlanHash string `json:"evaluatedPlanHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	AppliedPlanHash string `json:"appliedPlanHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservedStateHash   string `json:"observedStateHash,omitempty"`
	ObservationComplete bool   `json:"observationComplete,omitempty"`
	// SharedAgeReviewHash is bounded review evidence; approval is explicit metadata, never status.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SharedAgeReviewHash string `json:"sharedAgeReviewHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	DependentInventoryHash string                    `json:"dependentInventoryHash,omitempty"`
	CapabilityEvidence     IAMCapabilityEvidence     `json:"capabilityEvidence,omitempty"`
	Capabilities           WorkloadTrustCapabilities `json:"capabilities,omitempty"`
	AdoptionCandidate      *AdoptionCandidateStatus  `json:"adoptionCandidate,omitempty"`
	AdoptionReceipt        *AdoptionReceiptStatus    `json:"adoptionReceipt,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

type HankoWorkloadTrustList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoWorkloadTrust `json:"items"`
}
