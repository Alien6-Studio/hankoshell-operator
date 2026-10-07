package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hms,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Workload",type=string,JSONPath=".status.workloadID"
// +kubebuilder:printcolumn:name="Audience",type=string,JSONPath=".status.audience"
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=".spec.serviceRef"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoMeshService explicitly registers one Kubernetes workload for selective
// Continuum transport. A label or selector match alone never creates a mesh
// identity; the controller resolves every mutable reference to immutable UIDs.
type HankoMeshService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoMeshServiceSpec   `json:"spec,omitempty"`
	Status HankoMeshServiceStatus `json:"status,omitempty"`
}

// HankoMeshServiceSpec binds the Hanko caller and target identities to one
// Kubernetes Service and one Kubernetes ServiceAccount in the same namespace.
type HankoMeshServiceSpec struct {
	// TenantRef references the HankoTenant whose Hub identity and cluster
	// enrollment scope this registration.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	TenantRef string `json:"tenantRef"`

	// IdentityRef references the HankoServiceAccount whose clientID identifies
	// this workload when it calls another registered service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	IdentityRef string `json:"identityRef"`

	// ResourceServerRef references the HankoResourceServer whose audience
	// identifies this workload as a destination.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	ResourceServerRef string `json:"resourceServerRef"`

	// ServiceRef names the Kubernetes Service selected for interception.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	ServiceRef string `json:"serviceRef"`

	// WorkloadServiceAccountRef names the Kubernetes ServiceAccount that every
	// selected pod must use. It is distinct from the HankoServiceAccount above.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	WorkloadServiceAccountRef string `json:"workloadServiceAccountRef"`

	// EnforcementMode makes source and destination activation independent.
	// auditOnly keeps the immutable registration visible to Hanko but omits it
	// from the signed Continuum enforcement policy. The empty value preserves
	// the original Bidirectional behavior.
	// +kubebuilder:validation:Enum=bidirectional;ingressOnly;egressOnly;auditOnly
	// +optional
	EnforcementMode string `json:"enforcementMode,omitempty"`

	// Ports is the non-empty set of exact Service ports protected by Continuum.
	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Ports []MeshServicePort `json:"ports"`

	// Egress is the bounded set of ordinary-CNI Kubernetes Services a
	// registered caller may reach. The controller resolves every name to an
	// immutable Service UID before Hub signs the policy.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	Egress []MeshServiceEgress `json:"egress,omitempty"`
}

// MeshServiceEgress identifies one reviewed unregistered Kubernetes Service.
type MeshServiceEgress struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ServiceRef string `json:"serviceRef"`

	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Ports []MeshServicePort `json:"ports"`
}

// ResolvedMeshServiceEgress is the immutable egress projection reported to Hub.
type ResolvedMeshServiceEgress struct {
	Namespace   string            `json:"namespace"`
	ServiceName string            `json:"serviceName"`
	ServiceUID  string            `json:"serviceUID"`
	Ports       []MeshServicePort `json:"ports"`
}

// MeshServicePort identifies one exact L4 Service port.
type MeshServicePort struct {
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`

	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// HankoMeshServiceStatus contains only controller-resolved identity material.
// Policy compilers must consume a Ready status for the observed generation.
type HankoMeshServiceStatus struct {
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase string `json:"phase,omitempty"`

	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	TenantID           string `json:"tenantID,omitempty"`
	ClusterID          string `json:"clusterID,omitempty"`

	WorkloadID string `json:"workloadID,omitempty"`
	Audience   string `json:"audience,omitempty"`
	// Realm is the controller-resolved Hanko realm shared by the caller
	// identity and destination resource server. It scopes otherwise reusable
	// client IDs and audiences to the authoritative Hanko link store.
	Realm string `json:"realm,omitempty"`

	ServiceUID                string `json:"serviceUID,omitempty"`
	WorkloadServiceAccountUID string `json:"workloadServiceAccountUID,omitempty"`
	SelectorSHA256            string `json:"selectorSHA256,omitempty"`
	EnforcementMode           string `json:"enforcementMode,omitempty"`

	// ReceiverNodeUIDs is the sorted immutable UID set of Kubernetes Nodes
	// currently hosting selected Running/Ready pods. Names, labels and pod IPs
	// are never receiver authority.
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	ReceiverNodeUIDs []string `json:"receiverNodeUIDs"`

	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	ResolvedPorts []MeshServicePort `json:"resolvedPorts,omitempty"`

	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=serviceName
	// +kubebuilder:validation:MaxItems=64
	ResolvedEgress []ResolvedMeshServiceEgress `json:"resolvedEgress,omitempty"`

	LastResolved *metav1.Time       `json:"lastResolved,omitempty"`
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoMeshServiceList contains HankoMeshService objects.
type HankoMeshServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoMeshService `json:"items"`
}
