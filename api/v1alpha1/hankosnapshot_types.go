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

// HankoSnapshot records supported operator configuration for a Keycloak instance.
// It stores the operator CRD config in a ConfigMap and optionally
// triggers a pg_dump Job for the database.
// Portable backup/restore and database consistency are not qualified by 0.2.0.
type HankoSnapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoSnapshotSpec   `json:"spec,omitempty"`
	Status HankoSnapshotStatus `json:"status,omitempty"`
}

// HankoSnapshotSpec defines the desired state of a snapshot operation.
// +kubebuilder:validation:XValidation:rule="!has(self.includeData) || !self.includeData || (has(self.backupPVC) && has(self.backupImage) && has(self.backupSecretRef))",message="includeData requires backupPVC, backupImage and backupSecretRef"
type HankoSnapshotSpec struct {
	// InstanceRef is the name of the HankoKeycloakInstance to snapshot.
	// +kubebuilder:validation:Required
	InstanceRef string `json:"instanceRef"`

	// IncludeData triggers a pg_dump Job in addition to the config snapshot.
	// Requires managed mode, BackupPVC, an approved signed BackupImage and
	// a dedicated BackupSecretRef. No mutable or default image is used.
	IncludeData bool `json:"includeData,omitempty"`

	// BackupPVC is the name of the PersistentVolumeClaim where the pg_dump output
	// is written. Required when includeData is true.
	// +kubebuilder:validation:MinLength=1
	BackupPVC string `json:"backupPVC,omitempty"`

	// BackupImage is an immutable pg_dump image approved for database-backup
	// in the administrator-owned image policy. Its publisher signature and signed
	// source revision are verified before Job submission. It must run as UID/GID 70
	// with a read-only root filesystem. This separate image is not scanned as part
	// of the operator release; administrators must review its own security evidence.
	// +kubebuilder:validation:Pattern=`^[^@\s]+@sha256:[a-f0-9]{64}$`
	BackupImage string `json:"backupImage,omitempty"`

	// BackupSecretRef is a dedicated same-namespace Secret with PGHOST,
	// PGDATABASE, PGUSER and PGPASSWORD; PGPORT and PGSSLMODE are optional.
	// Only these keys enter the Job. It must differ from the instance's
	// administrative, managed database and serving TLS Secrets.
	// +kubebuilder:validation:MinLength=1
	BackupSecretRef string `json:"backupSecretRef,omitempty"`
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
