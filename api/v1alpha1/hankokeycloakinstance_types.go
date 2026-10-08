package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hkc,categories=hanko
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=".status.keycloakVersion"
// +kubebuilder:printcolumn:name="Realms",type=integer,JSONPath=".status.realmCount"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoKeycloakInstance represents a Keycloak instance managed or observed by the operator.
// Mode controls the level of ownership: managed (operator owns the Deployment),
// adopted (existing K8s Deployment), or external (Admin API only, including
// Kubernetes instances owned by the official Keycloak operator).
type HankoKeycloakInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoKeycloakInstanceSpec   `json:"spec,omitempty"`
	Status HankoKeycloakInstanceStatus `json:"status,omitempty"`
}

// HankoKeycloakInstanceSpec defines the desired state of a Keycloak instance.
type HankoKeycloakInstanceSpec struct {
	// Mode determines what the operator owns.
	// +kubebuilder:validation:Enum=managed;adopted;external
	// +kubebuilder:default=external
	Mode string `json:"mode"`

	// AdminRef points to a Secret with keys HANKO_KEYCLOAK_URL, HANKO_KC_CLIENT_ID, HANKO_KC_CLIENT_SECRET.
	// +kubebuilder:validation:Required
	AdminRef corev1.LocalObjectReference `json:"adminRef"`

	// TLSCARef is the name of a Secret containing a "ca.crt" key with the PEM-encoded
	// CA bundle used to verify the Keycloak Admin API TLS certificate.
	// HTTPS always verifies certificates; without this Secret it uses system CAs.
	TLSCARef string `json:"tlsCARef,omitempty"`

	// Managed holds the desired state for an operator-provisioned Keycloak Deployment.
	// Required when mode=managed.
	Managed *ManagedKeycloakSpec `json:"managed,omitempty"`

	// Adopted references an existing K8s Keycloak Deployment.
	// Required when mode=adopted.
	Adopted *AdoptedKeycloakSpec `json:"adopted,omitempty"`
}

// ManagedKeycloakSpec defines the desired state for an operator-provisioned Keycloak Deployment.
type ManagedKeycloakSpec struct {
	// Image is the Keycloak container image.
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// Replicas is the number of Keycloak pods. Defaults to 1.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	Replicas *int32 `json:"replicas,omitempty"`

	// Database points to a Secret with DB connection env vars
	// (KC_DB, KC_DB_URL, KC_DB_USERNAME, KC_DB_PASSWORD).
	// +kubebuilder:validation:Required
	Database corev1.LocalObjectReference `json:"database"`

	// ThemePVC is the PersistentVolumeClaim name for Keycloak theme JARs.
	ThemePVC string `json:"themePVC,omitempty"`

	// Resources sets CPU/memory requests and limits on the Keycloak container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// AdoptedKeycloakSpec references an existing Keycloak Deployment managed outside the operator.
type AdoptedKeycloakSpec struct {
	// DeploymentRef is the name of the existing Keycloak Deployment in the same namespace.
	// +kubebuilder:validation:Required
	DeploymentRef string `json:"deploymentRef"`

	// ServiceRef is the name of the existing Keycloak Service (optional, used for status).
	ServiceRef string `json:"serviceRef,omitempty"`
}

// HankoKeycloakInstanceStatus describes the observed state of the Keycloak instance.
type HankoKeycloakInstanceStatus struct {
	// Phase: Pending | Probing | Ready | Degraded | Error
	// +kubebuilder:validation:Enum=Pending;Probing;Ready;Degraded;Error
	Phase string `json:"phase,omitempty"`

	// KeycloakVersion is discovered from the Admin API when permissions allow;
	// it can be empty for a restricted administrative identity.
	KeycloakVersion string `json:"keycloakVersion,omitempty"`

	// AdminAPIURL is the base URL used to reach the Keycloak Admin API.
	AdminAPIURL string `json:"adminAPIURL,omitempty"`

	// RealmCount is the number of realms discovered in this Keycloak instance.
	RealmCount int `json:"realmCount,omitempty"`

	// LastProbed is the timestamp of the last successful Admin API probe.
	LastProbed *metav1.Time `json:"lastProbed,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// LastCredentialRotation is the last time the AdminRef service-account
	// credential was promoted after successful Keycloak verification.
	LastCredentialRotation *metav1.Time `json:"lastCredentialRotation,omitempty"`

	// NextCredentialRotation is the deadline derived from HANKO_KC_SA_MAX_AGE.
	NextCredentialRotation *metav1.Time `json:"nextCredentialRotation,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoKeycloakInstanceList contains a list of HankoKeycloakInstance.
type HankoKeycloakInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoKeycloakInstance `json:"items"`
}
