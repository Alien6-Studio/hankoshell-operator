package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=his,categories=hanko
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=".spec.host"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoIssuer declares one public OIDC authority-to-realm binding trusted by
// the hankoShell facade. The operator aggregates valid declarations into the
// API deployment's exact Host/X-Forwarded-Host and realm policy.
type HankoIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoIssuerSpec   `json:"spec,omitempty"`
	Status HankoIssuerStatus `json:"status,omitempty"`
}

// HankoIssuerSpec defines one exact public issuer authority and realm pair.
type HankoIssuerSpec struct {
	// Host is an exact hostname, optionally including a port. Schemes, paths,
	// credentials, wildcards and forwarding lists are forbidden.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host"`

	// RealmRef is the HankoRealm served through this public authority.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	RealmRef string `json:"realmRef"`
}

// HankoIssuerStatus describes allowlist reconciliation state.
type HankoIssuerStatus struct {
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase string `json:"phase,omitempty"`

	// ConfiguredHost is the canonical host written to the API deployment.
	ConfiguredHost string `json:"configuredHost,omitempty"`

	// LastReconciled is the time of the latest reconciliation attempt.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoIssuerList contains a list of HankoIssuer.
type HankoIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoIssuer `json:"items"`
}
