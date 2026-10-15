package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ht2,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="TenantID",type=string,JSONPath=".spec.hubTenantID"
// +kubebuilder:printcolumn:name="Bundle",type=string,JSONPath=".status.bundleVersion"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoTenant represents a registered SaaS tenant synced from hankoShell Hub.
type HankoTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoTenantSpec   `json:"spec,omitempty"`
	Status HankoTenantStatus `json:"status,omitempty"`
}

// HankoTenantSpec defines the desired state of a tenant.
type HankoTenantSpec struct {
	// HubTenantID is the tenant identifier assigned by hankoShell Hub. May be
	// left empty when HubEnrollSecretRef is set: it is then learned during
	// enrollment and stored alongside the bounded operator credential.
	HubTenantID string `json:"hubTenantID,omitempty"`

	// ClusterName is the optional human-readable cluster name sent at initial
	// enrollment. It does not rename an existing Hub identity. The cluster UID
	// is discovered from the kube-system Namespace, never supplied by a user.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=80
	ClusterName string `json:"clusterName,omitempty"`

	// HubEndpoint is the hankoShell Hub base URL. Must be an HTTPS URL.
	// +kubebuilder:default="https://hub.hanko.sh"
	// +kubebuilder:validation:Pattern=`^https://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]+)?(/[^\s]*)?$`
	HubEndpoint string `json:"hubEndpoint,omitempty"`

	// HubEnrollmentEndpoint is the public, bootstrap-only Hub base URL used to
	// exchange a single-use enrollment token. When omitted, HubEndpoint is used
	// for backward compatibility. Bundle and status traffic always use
	// HubEndpoint, which may therefore be a private Continuum address.
	// +kubebuilder:validation:Pattern=`^https://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]+)?(/[^\s]*)?$`
	HubEnrollmentEndpoint string `json:"hubEnrollmentEndpoint,omitempty"`

	// HubTransport declares the authenticated network transport used for Hub
	// bundle and status synchronization. It is reported in fleet heartbeats so
	// the public operator route is not closed before every spoke has migrated.
	// Empty is treated as direct for backward compatibility with existing CRs.
	// +kubebuilder:validation:Enum=direct;continuum
	// +kubebuilder:default=direct
	HubTransport string `json:"hubTransport,omitempty"`

	// IsolationMode defines how Keycloak resources are isolated for this tenant.
	// +kubebuilder:validation:Enum=realm;keycloak;cluster
	// +kubebuilder:default=realm
	IsolationMode string `json:"isolationMode,omitempty"`

	// RealmRef is the HankoRealm name for realm-mode isolation.
	RealmRef string `json:"realmRef,omitempty"`

	// KeycloakSecretRef points to a Secret with keys HANKO_KEYCLOAK_URL,
	// HANKO_KC_CLIENT_ID, HANKO_KC_CLIENT_SECRET for dedicated Keycloak instances.
	// Required for keycloak and cluster isolation modes.
	KeycloakSecretRef *corev1.LocalObjectReference `json:"keycloakSecretRef,omitempty"`

	// HubTokenSecretRef points to the Secret holding hub_token, tenant_id,
	// cluster_id and expires_at. The operator rotates this bounded credential
	// transactionally. When the Secret does not exist and HubEnrollSecretRef is
	// set, the operator creates it at enrollment only if status.clusterID is
	// also absent. A known identity requires credential recovery, not enrollment.
	// +kubebuilder:validation:Required
	HubTokenSecretRef corev1.LocalObjectReference `json:"hubTokenSecretRef"`

	// HubEnrollSecretRef points to a Secret with key enroll_token holding a
	// single-use hankoShell Hub enrollment token. When the hub token Secret is
	// absent and no cluster identity is known, the operator exchanges this token
	// for a bounded credential that never leaves the cluster.
	HubEnrollSecretRef *corev1.LocalObjectReference `json:"hubEnrollSecretRef,omitempty"`
}

// HankoTenantStatus describes the observed state of the tenant.
type HankoTenantStatus struct {
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Synced;Error
	Phase string `json:"phase,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// TenantID and ClusterID are non-secret Hub identities resolved from the
	// bounded operator credential. Mesh registration consumers use them instead
	// of reading the credential Secret.
	TenantID  string `json:"tenantID,omitempty"`
	ClusterID string `json:"clusterID,omitempty"`

	// ConnectedHub is the Hub endpoint this tenant is currently syncing from.
	ConnectedHub string `json:"connectedHub,omitempty"`

	// BundleVersion is the version of the last successfully applied bundle.
	BundleVersion string `json:"bundleVersion,omitempty"`

	// LastSync is the timestamp of the last successful bundle sync.
	LastSync *metav1.Time `json:"lastSync,omitempty"`

	// LastReconciled is the timestamp of the last reconciliation attempt.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// FleetPlan is the durable signed-plan high-water mark. Its presence forbids
	// legacy HMAC fallback, including after restart or trust configuration loss.
	FleetPlan *FleetPlanStatus `json:"fleetPlan,omitempty"`
	// FleetRollout is bounded delivery evidence, not provider convergence.
	FleetRollout *FleetRolloutStatus `json:"fleetRollout,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FleetPlanStatus contains only public verification/checkpoint evidence. It does
// not store plan content, keys, tokens or a provider completion attestation.
type FleetPlanStatus struct {
	// +kubebuilder:validation:Minimum=1
	Sequence int64 `json:"sequence"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Identity string `json:"identity"`
	// PreviousIdentity retains a reference for future reviewed rollback; it
	// does not authorize executing a rollback in this implementation.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	PreviousIdentity string `json:"previousIdentity,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	AppliedIdentity string `json:"appliedIdentity,omitempty"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	KeyID string `json:"keyID"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	TenantUID string      `json:"tenantUID"`
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// FleetRolloutStatus reports decisions without remote names or configuration.
// +kubebuilder:validation:XValidation:rule="self.applied + self.refused + self.pending <= 200",message="rollout evidence exceeds the plan object budget"
type FleetRolloutStatus struct {
	// +kubebuilder:validation:Minimum=1
	Sequence int64 `json:"sequence,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Identity string `json:"identity,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SelectionHash      string `json:"selectionHash,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration"`
	// +kubebuilder:validation:Enum=Pending;Applied;Partial;Refused;Paused
	State string `json:"state"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=200
	Applied int32 `json:"applied"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=200
	Refused int32 `json:"refused"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=200
	Pending int32 `json:"pending"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=index
	Findings []FleetRolloutFinding `json:"findings,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=200
	Omitted int32 `json:"omitted"`
}

type FleetRolloutFinding struct {
	// Index is the zero-based position in the fixed kind-array order.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=199
	Index int32 `json:"index"`
	// +kubebuilder:validation:Enum=FleetCapabilityUnsupported;FleetPermissionDenied;FleetDependencyRefused;FleetCapabilityInventoryUnavailable
	Reason string `json:"reason"`
}

// +kubebuilder:object:root=true

// HankoTenantList contains a list of HankoTenant.
type HankoTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoTenant `json:"items"`
}
