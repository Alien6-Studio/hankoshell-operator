package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hop,categories=hanko
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Instance",type=string,JSONPath=".spec.instanceRef"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoOperation is a one-shot lifecycle operation on a Keycloak instance.
type HankoOperation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoOperationSpec   `json:"spec,omitempty"`
	Status HankoOperationStatus `json:"status,omitempty"`
}

// HankoOperationType enumerates the supported lifecycle operations.
type HankoOperationType string

const (
	// OperationUpgrade upgrades the Keycloak container image.
	OperationUpgrade HankoOperationType = "Upgrade"
	// OperationClone creates an external instance alias using the source connection
	// and imports supported configuration; it does not copy a database.
	OperationClone HankoOperationType = "Clone"
	// OperationDBSwitch changes the database Secret reference without data migration.
	OperationDBSwitch HankoOperationType = "DBSwitch"
)

// HankoOperationSpec defines the desired lifecycle operation.
type HankoOperationSpec struct {
	// Type is the operation to perform.
	// +kubebuilder:validation:Enum=Upgrade;Clone;DBSwitch
	// +kubebuilder:validation:Required
	Type HankoOperationType `json:"type"`

	// InstanceRef is the name of the HankoKeycloakInstance to operate on.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	InstanceRef string `json:"instanceRef"`

	// SnapshotBefore controls whether a HankoSnapshot is created before the operation.
	// This is configuration-only, not a database backup. Defaults to true.
	// +kubebuilder:default=true
	SnapshotBefore *bool `json:"snapshotBefore,omitempty"`

	// Upgrade holds parameters for the Upgrade operation.
	Upgrade *UpgradeSpec `json:"upgrade,omitempty"`

	// Clone holds parameters for the Clone operation.
	Clone *CloneSpec `json:"clone,omitempty"`

	// DBSwitch holds parameters for the DBSwitch operation.
	DBSwitch *DBSwitchSpec `json:"dbSwitch,omitempty"`

	// DryRun skips planned steps without applying them; it does not validate
	// provider compatibility, database migration or recoverability.
	DryRun bool `json:"dryRun,omitempty"`
}

// UpgradeSpec holds parameters for upgrading the Keycloak image.
type UpgradeSpec struct {
	// ToImage is the target Keycloak container image.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[^\x00-\x20\x7F]+$`
	ToImage string `json:"toImage"`
}

// CloneSpec holds parameters for cloning a Keycloak instance.
type CloneSpec struct {
	// TargetName is the name for the new HankoKeycloakInstance.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	TargetName string `json:"targetName"`

	// TargetNamespace defaults to the source namespace. Cross-namespace cloning
	// is refused because administrative and TLS Secret references are local.
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// IncludeData is retained for API compatibility; true is refused because
	// this operation does not copy a database.
	IncludeData bool `json:"includeData,omitempty"`
}

// DBSwitchSpec holds parameters for switching the Keycloak database.
type DBSwitchSpec struct {
	// NewDatabaseSecretRef is the name of a Secret containing the new DB credentials
	// (KC_DB, KC_DB_URL, KC_DB_USERNAME, KC_DB_PASSWORD).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	NewDatabaseSecretRef string `json:"newDatabaseSecretRef"`
}

// OperationStep tracks the status of a single step within the operation.
type OperationStep struct {
	// Name is the step identifier.
	Name string `json:"name"`

	// Status: Pending | Running | Done | Failed | Skipped
	Status string `json:"status"`

	// Message holds a human-readable description or error.
	Message string `json:"message,omitempty"`

	// ChildUID binds the exact child accepted by this step.
	ChildUID string `json:"childUID,omitempty"`
	// ChildGeneration refuses child specification changes during recovery.
	// +kubebuilder:validation:Minimum=1
	ChildGeneration int64 `json:"childGeneration,omitempty"`

	// StartedAt is when this step began.
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CompletedAt is when this step finished.
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
}

// HankoOperationStatus describes the observed state of the operation.
type HankoOperationStatus struct {
	// StartedGeneration binds the operation generation at the first checkpoint.
	// +kubebuilder:validation:Minimum=1
	StartedGeneration int64 `json:"startedGeneration,omitempty"`
	// IntentHash binds the complete operation specification and tenant.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	IntentHash string `json:"intentHash,omitempty"`
	// InstanceUID prevents a replacement source from inheriting an operation.
	InstanceUID string `json:"instanceUID,omitempty"`
	// Phase: Pending | Snapshotting | Running | Validating | Done | Failed | RolledBack
	// +kubebuilder:validation:Enum=Pending;Snapshotting;Running;Validating;Done;Failed;RolledBack
	Phase string `json:"phase,omitempty"`

	// SnapshotRef is the name of the HankoSnapshot created before this operation.
	SnapshotRef string `json:"snapshotRef,omitempty"`

	// Steps is the ordered list of operation steps with their current status.
	Steps []OperationStep `json:"steps,omitempty"`

	// StartedAt is when the operation began.
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CompletedAt is when the operation finished (Done or Failed).
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// LastReconciled is the timestamp of the last reconcile loop.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoOperationList contains a list of HankoOperation.
type HankoOperationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoOperation `json:"items"`
}
