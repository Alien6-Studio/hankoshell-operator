package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hsnap,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Instance",type=string,JSONPath=".spec.instanceRef"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoSnapshot is a point-in-time backup of a Keycloak instance.
// It stores the operator CRD config in a ConfigMap and optionally
// triggers a pg_dump Job for the database.
type HankoSnapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoSnapshotSpec   `json:"spec,omitempty"`
	Status HankoSnapshotStatus `json:"status,omitempty"`
}

// HankoSnapshotSpec defines the desired state of a snapshot operation.
type HankoSnapshotSpec struct {
	// InstanceRef is the name of the HankoKeycloakInstance to snapshot.
	// +kubebuilder:validation:Required
	InstanceRef string `json:"instanceRef"`

	// IncludeData triggers a pg_dump Job in addition to the config snapshot.
	// Requires the instance to be in managed mode with a Database secret,
	// and BackupPVC must be set to a PVC where the dump file will be written.
	IncludeData bool `json:"includeData,omitempty"`

	// BackupPVC is the name of the PersistentVolumeClaim where the pg_dump output
	// is written. Required when includeData is true.
	BackupPVC string `json:"backupPVC,omitempty"`
}

// HankoSnapshotStatus describes the observed state of the snapshot.
type HankoSnapshotStatus struct {
	// Phase: Pending | Running | Done | Failed
	// +kubebuilder:validation:Enum=Pending;Running;Done;Failed
	Phase string `json:"phase,omitempty"`

	// ConfigMapRef is the name of the ConfigMap holding the serialized CRD config.
	ConfigMapRef string `json:"configMapRef,omitempty"`

	// DBJobRef is the name of the pg_dump Job (set only when includeData=true).
	DBJobRef string `json:"dbJobRef,omitempty"`

	// TakenAt is when the snapshot completed successfully.
	TakenAt *metav1.Time `json:"takenAt,omitempty"`

	// LastReconciled is the timestamp of the last reconcile loop.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoSnapshotList contains a list of HankoSnapshot.
type HankoSnapshotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoSnapshot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HankoSnapshot{}, &HankoSnapshotList{})
}
