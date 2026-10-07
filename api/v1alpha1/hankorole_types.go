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
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoRoleList contains a list of HankoRole.
type HankoRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoRole `json:"items"`
}
