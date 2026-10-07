package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hip,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="MFA",type=string,JSONPath=".spec.security.mfaPolicy"
// +kubebuilder:printcolumn:name="Hash",type=string,JSONPath=".status.policyHash"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoIAMProfile is a reusable realm-scoped authentication and security policy.
// Applications inherit the profile through their HankoRealm and remain unaware
// of the concrete MFA, password, session, audit and broker controls.
type HankoIAMProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoIAMProfileSpec   `json:"spec,omitempty"`
	Status HankoIAMProfileStatus `json:"status,omitempty"`
}

// HankoIAMProfileSpec defines the reusable desired IAM policy.
type HankoIAMProfileSpec struct {
	// Security is the product-neutral policy reconciled to every referencing realm.
	Security RealmSecurityProfile `json:"security"`
}

// HankoIAMProfileStatus describes validation of the reusable policy.
type HankoIAMProfileStatus struct {
	// Phase summarises whether the profile can be consumed by realms.
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase string `json:"phase,omitempty"`

	// ObservedGeneration is the profile generation represented by this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// PolicyHash is the deterministic SHA-256 of the effective security policy.
	PolicyHash string `json:"policyHash,omitempty"`

	// LastValidated is the timestamp of the last successful validation.
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoIAMProfileList contains a list of HankoIAMProfile.
type HankoIAMProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoIAMProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HankoIAMProfile{}, &HankoIAMProfileList{})
}
