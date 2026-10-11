package v1alpha1

// ServiceAccountAuthenticationTransition requests a reviewed method change.
// Exact approval and external authentication review use closed annotations;
// adding them cannot stale the binding generation being approved.
type ServiceAccountAuthenticationTransition struct {
	// +kubebuilder:validation:Enum=CoordinatedCutover
	Strategy string `json:"strategy"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`
	RequestID string `json:"requestID"`
	// Public workload-owner revision, never a token or credential.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`
	PreparedWorkloadRevision string `json:"preparedWorkloadRevision"`
}

// AuthenticationTransitionStatus is bounded preparation evidence. Copying it
// into status never authorizes a provider write or cleanup.
type AuthenticationTransitionStatus struct {
	RequestID       string `json:"requestID"`
	ClientUUID      string `json:"clientUUID"`
	PreviousMode    string `json:"previousMode"`
	DesiredMode     string `json:"desiredMode"`
	BindingRevision string `json:"bindingRevision"`
	NativeStateHash string `json:"nativeStateHash"`
	PlanHash        string `json:"planHash"`
	Step            string `json:"step"`
}
