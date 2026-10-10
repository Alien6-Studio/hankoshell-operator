package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hi,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=".spec.sourceRef"
// +kubebuilder:printcolumn:name="Applied",type=integer,JSONPath=".status.applied.total"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoImport is a one-shot operation that scans an existing Keycloak instance
// and generates HankoRealm, HankoApplication and HankoServiceAccount CRDs.
type HankoImport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoImportSpec   `json:"spec,omitempty"`
	Status HankoImportStatus `json:"status,omitempty"`
}

// HankoImportSpec defines the desired state of an import operation.
type HankoImportSpec struct {
	// SourceRef is the name of the HankoKeycloakInstance to import from.
	// +kubebuilder:validation:Required
	SourceRef string `json:"sourceRef"`

	// Realms is the list of realm names to import. Empty means all realms.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=255
	Realms []string `json:"realms,omitempty"`

	// IncludeClients controls whether qualified OIDC and SAML clients are imported as HankoApplication objects.
	// +kubebuilder:default=true
	IncludeClients *bool `json:"includeClients,omitempty"`

	// IncludeServiceAccounts controls whether M2M clients are imported as HankoServiceAccount objects.
	// +kubebuilder:default=true
	IncludeServiceAccounts *bool `json:"includeServiceAccounts,omitempty"`

	// IncludeIdentityProviders controls whether realm brokers and their mappers
	// are captured in generated HankoRealm objects. Sensitive config is omitted.
	// +kubebuilder:default=true
	IncludeIdentityProviders *bool `json:"includeIdentityProviders,omitempty"`

	// DryRun generates the import report without applying any CRDs.
	DryRun bool `json:"dryRun,omitempty"`
}

// HankoImportStatus describes the observed state of the import operation.
type HankoImportStatus struct {
	// Coverage measures discovery; terminal Done does not imply complete inventory.
	Coverage ImportCoverage `json:"coverage,omitempty"`
	// Inventory holds bounded summaries; full diffs live on Observe targets.
	// +kubebuilder:validation:MaxItems=128
	Inventory []ImportInventoryReference `json:"inventory,omitempty"`

	// Findings reports protocol inventory that cannot be imported safely.
	// No incompatible OIDC manifest is generated for a SAML/unknown client.
	// +listType=map
	// +listMapKey=classification
	// +listMapKey=objectKind
	// +listMapKey=objectName
	// +listMapKey=code
	// +kubebuilder:validation:MaxItems=32
	Findings []AuthorizationFinding `json:"findings,omitempty"`
	// Phase: Pending | Scanning | Applying | Done | Failed
	// +kubebuilder:validation:Enum=Pending;Scanning;Applying;Done;Failed
	Phase string `json:"phase,omitempty"`

	// Discovered holds counts of resources found in the source Keycloak instance.
	Discovered ImportCounts `json:"discovered,omitempty"`

	// Applied holds counts of CRDs successfully created or updated.
	Applied ImportCounts `json:"applied,omitempty"`

	// Skipped holds counts of resources that were not imported (dry-run or already exist).
	Skipped ImportCounts `json:"skipped,omitempty"`

	// CompletedAt is the timestamp when the import finished.
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// LastReconciled is the timestamp of the last reconcile loop.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ImportCounts tracks resource counts across a single import phase.
type ImportCounts struct {
	Roles                int `json:"roles,omitempty"`
	Groups               int `json:"groups,omitempty"`
	Organizations        int `json:"organizations,omitempty"`
	ResourceServers      int `json:"resourceServers,omitempty"`
	AuthorizationObjects int `json:"authorizationObjects,omitempty"`

	// Realms is the count of Keycloak realms.
	Realms int `json:"realms,omitempty"`

	// Applications is the count of OIDC client applications.
	Applications int `json:"applications,omitempty"`

	// ServiceAccounts is the count of M2M service account clients.
	ServiceAccounts int `json:"serviceAccounts,omitempty"`

	// IdentityProviders is the count of realm-scoped upstream brokers.
	IdentityProviders int `json:"identityProviders,omitempty"`

	// IdentityProviderMappers is the count of mappers attached to imported brokers.
	IdentityProviderMappers int `json:"identityProviderMappers,omitempty"`

	// Total is the sum of every discovered or applied resource and nested broker object.
	Total int `json:"total,omitempty"`
}

// +kubebuilder:object:root=true

// HankoImportList contains a list of HankoImport.
type HankoImportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoImport `json:"items"`
}
