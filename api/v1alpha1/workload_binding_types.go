package v1alpha1

// ServiceAccountAuthentication selects one client authentication contract.
// Omission preserves Secret. Kubernetes binding is validated independently of
// native activation and does not authorize a method transition.
// +kubebuilder:validation:XValidation:rule="self.mode == 'Kubernetes' ? has(self.kubernetes) : !has(self.kubernetes)",message="Kubernetes parameters are required only for Kubernetes mode"
type ServiceAccountAuthentication struct {
	// +kubebuilder:validation:Enum=Secret;Kubernetes
	// +kubebuilder:default=Secret
	Mode       string                                  `json:"mode,omitempty"`
	Kubernetes *KubernetesServiceAccountAuthentication `json:"kubernetes,omitempty"`
}

type KubernetesServiceAccountAuthentication struct {
	// TrustRef selects the shared trust in the HankoServiceAccount namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	TrustRef string `json:"trustRef"`
	// SourceRef selects the client connection, freshly bound to the trust's
	// endpoint, public CA and native realm. There is no pooled writer fallback.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	SourceRef string                    `json:"sourceRef"`
	Workload  KubernetesWorkloadBinding `json:"workload"`
	// ExpirationSeconds recommends kubelet projection duration, not native JWT
	// lifespan enforcement. It must also fit the current shared assertion age.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=600
	// +kubebuilder:validation:Maximum=3600
	ExpirationSeconds int64 `json:"expirationSeconds,omitempty"`
}

// KubernetesWorkloadBinding reuses the application workload's structural names
// without changing that existing authorization-anchor contract into federation.
// +kubebuilder:validation:XValidation:rule="self.serviceAccountRef != 'default'",message="a dedicated ServiceAccount is required"
type KubernetesWorkloadBinding struct {
	ApplicationRuntimeWorkload `json:",inline"`
	// ExpectedUID is explicit administrator authority; names/status never approve
	// the UID of a replacement ServiceAccount.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`
	ExpectedUID string `json:"expectedUID"`
}

// WorkloadRuntimeMetadataTarget names a pre-existing, workload-owned ConfigMap
// in the approved workload namespace. Its owner grants separate UID consent.
type WorkloadRuntimeMetadataTarget struct {
	ApplicationRuntimeMetadataTarget `json:",inline"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`
	ExpectedUID string `json:"expectedUID"`
}

// WorkloadBindingStatus is public configuration evidence, never activation or
// cleanup authority. Failure clears it rather than retaining a current claim.
type WorkloadBindingStatus struct {
	Workload KubernetesWorkloadBinding `json:"workload"`
	// +kubebuilder:validation:MaxLength=128
	ClusterNamespaceUID string `json:"clusterNamespaceUID"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	APIServerCAHash string `json:"apiServerCAHash"`
	// +kubebuilder:validation:MaxLength=128
	TrustUID string `json:"trustUID"`
	// +kubebuilder:validation:Minimum=1
	TrustGeneration int64 `json:"trustGeneration"`
	// +kubebuilder:validation:MaxLength=128
	ProviderID string `json:"providerID"`
	// +kubebuilder:validation:MaxLength=128
	RealmID string `json:"realmID"`
	// +kubebuilder:validation:Minimum=1
	SourceGeneration int64 `json:"sourceGeneration"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	IntentHash string `json:"intentHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	PlanHash string `json:"planHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	BindingRevision string `json:"bindingRevision"`
}

type WorkloadRuntimeMetadataStatus struct {
	// +kubebuilder:validation:MaxLength=253
	ConfigMapRef string `json:"configMapRef"`
	// +kubebuilder:validation:MaxLength=128
	ConfigMapUID string `json:"configMapUID"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	MetadataHash string `json:"metadataHash"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	BindingRevision string `json:"bindingRevision"`
}
