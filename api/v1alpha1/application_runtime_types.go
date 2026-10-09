package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ApplicationRuntimeBinding identifies pre-existing workload-owned outputs.
type ApplicationRuntimeBinding struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name           string                              `json:"name"`
	Workload       ApplicationRuntimeWorkload          `json:"workload"`
	PublicMetadata ApplicationRuntimeMetadataTarget    `json:"publicMetadata"`
	Credentials    *ApplicationRuntimeCredentialTarget `json:"credentials,omitempty"`
}

// ApplicationRuntimeWorkload is an authorization anchor, not workload federation.
type ApplicationRuntimeWorkload struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	ServiceAccountRef string `json:"serviceAccountRef"`
}

// ApplicationRuntimeMetadataTarget selects the identity.json ConfigMap.
type ApplicationRuntimeMetadataTarget struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	ConfigMapRef string `json:"configMapRef"`
}

// ApplicationRuntimeCredentialTarget selects the optional client_secret output.
type ApplicationRuntimeCredentialTarget struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	SecretRef string `json:"secretRef"`
}

// ApplicationRuntimeBindingStatus contains public delivery evidence only.
// +kubebuilder:validation:XValidation:rule="!has(self.conditions) || self.conditions.all(c, size(c.message) <= 256 && c.type == 'Ready')",message="runtime delivery conditions must be bounded Ready evidence"
type ApplicationRuntimeBindingStatus struct {
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MaxLength=253
	ServiceAccountRef string `json:"serviceAccountRef"`
	// +kubebuilder:validation:MaxLength=128
	ServiceAccountUID string `json:"serviceAccountUID,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	ConfigMapRef string `json:"configMapRef"`
	// +kubebuilder:validation:MaxLength=253
	SecretRef string `json:"secretRef,omitempty"`
	// +kubebuilder:validation:Minimum=0
	SourceGeneration int64 `json:"sourceGeneration,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SourceAppliedPlanHash string `json:"sourceAppliedPlanHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	MetadataHash string `json:"metadataHash,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	BindingRevision string `json:"bindingRevision,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=1
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
