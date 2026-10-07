package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hsa,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="NextRotation",type=string,JSONPath=".status.nextRotation"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoServiceAccount represents a machine-to-machine (M2M) Keycloak client.
type HankoServiceAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoServiceAccountSpec   `json:"spec,omitempty"`
	Status HankoServiceAccountStatus `json:"status,omitempty"`
}

// HankoServiceAccountSpec defines the desired state of an M2M client.
// Built-in Keycloak clients are never valid service-account ownership targets.
// Fleet-authority and cross-resource ownership are checked by the reconciler:
// CEL cannot query other CRDs or runtime realm/client configuration.
// +kubebuilder:validation:XValidation:rule="self.clientID.trim() != 'account' && self.clientID.trim() != 'account-console' && self.clientID.trim() != 'admin-cli' && self.clientID.trim() != 'broker' && self.clientID.trim() != 'realm-management' && self.clientID.trim() != 'security-admin-console'",message="built-in Keycloak clients cannot be managed as HankoServiceAccount"
type HankoServiceAccountSpec struct {
	// RealmRef references the HankoRealm this service account belongs to.
	// +kubebuilder:validation:Required
	RealmRef string `json:"realmRef"`

	// ClientID is the Keycloak client identifier for the M2M client.
	// +kubebuilder:validation:Required
	ClientID string `json:"clientID"`

	// Scopes lists the OAuth2 scopes granted to this service account.
	Scopes []string `json:"scopes,omitempty"`

	// SecretRotationPolicy controls automatic secret rotation.
	SecretRotationPolicy *SecretRotationPolicy `json:"secretRotationPolicy,omitempty"`

	// Attributes sets arbitrary Keycloak client attributes (single string value per
	// key) on the underlying M2M client. The full map is the desired state and
	// replaces unmanaged keys set directly in Keycloak on every reconcile.
	Attributes map[string]string `json:"attributes,omitempty"`

	// TokenClaims exposes a Keycloak user attribute or fixed value as a claim in
	// tokens issued to this service account. The same fail-closed mapper model as
	// HankoApplication is used.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	TokenClaims []ApplicationTokenClaim `json:"tokenClaims,omitempty"`
}

// SecretRotationPolicy controls how frequently a confidential client secret is rotated.
type SecretRotationPolicy struct {
	// Enabled activates automatic rotation.
	Enabled bool `json:"enabled"`

	// IntervalDays is the rotation period in days.
	// +kubebuilder:validation:Minimum=1
	IntervalDays int `json:"intervalDays,omitempty"`

	// ForceRotateAt, when set, triggers an immediate rotation on the next reconcile.
	ForceRotateAt *metav1.Time `json:"forceRotateAt,omitempty"`
}

// HankoServiceAccountStatus describes the observed state of the M2M client.
type HankoServiceAccountStatus struct {
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	// ObservedGeneration prevents consumers from trusting a Ready status left
	// behind by an unreconciled identity change.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SecretRef references the K8s Secret holding the M2M client secret.
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// LastRotated is the timestamp of the last secret rotation.
	LastRotated *metav1.Time `json:"lastRotated,omitempty"`

	// NextRotation is the scheduled timestamp for the next automatic rotation.
	NextRotation *metav1.Time `json:"nextRotation,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ManagedTokenClaims records client-scoped protocol mappers managed for this service account.
	ManagedTokenClaims []ManagedTokenClaimReference `json:"managedTokenClaims,omitempty"`
}

// +kubebuilder:object:root=true

// HankoServiceAccountList contains a list of HankoServiceAccount.
type HankoServiceAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoServiceAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HankoServiceAccount{}, &HankoServiceAccountList{})
}
