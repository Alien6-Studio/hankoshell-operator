package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=horg,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Org",type=string,JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Parent",type=string,JSONPath=".spec.parentRef"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoOrganization represents one hierarchical organization node, reconciled
// into Keycloak as a realm group whose realm-role mappings become the members'
// effective roles. It is the authoritative source Trunx consumes via claims
// (HKX-09): the organization is declared here, not in Trunx's database.
type HankoOrganization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoOrganizationSpec   `json:"spec,omitempty"`
	Status HankoOrganizationStatus `json:"status,omitempty"`
}

// HankoOrganizationSpec defines the desired state of an organization node.
// +kubebuilder:validation:XValidation:rule="!has(self.roles) || self.roles.all(r, r != 'HANKO_PLATFORM' && !r.startsWith('HANKO_PLATFORM_') && !r.startsWith('HANKO_FLEET_') && !r.startsWith('HANKO_CLUSTER_'))",message="reserved platform, fleet and cluster roles cannot be assigned through an organization"
type HankoOrganizationSpec struct {
	// RealmRef references the HankoRealm this organization belongs to.
	// +kubebuilder:validation:Required
	RealmRef string `json:"realmRef"`

	// Name is the organization's display name and Keycloak group name.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Slug is the stable, URL-safe identifier surfaced to Trunx. When empty it
	// is derived from Name by the consumer.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
	Slug string `json:"slug,omitempty"`

	// ParentRef is the name of the parent HankoOrganization in the same
	// namespace, empty for a top-level (tenant-root) organization. It expresses
	// the multi-level hierarchy as nested Keycloak groups.
	ParentRef string `json:"parentRef,omitempty"`

	// Roles lists the realm roles mapped onto this organization's group. Every
	// member of the group inherits these roles in issued tokens. Referenced
	// roles must already exist (typically declared by a HankoRealm or HankoRole).
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=255
	Roles []string `json:"roles,omitempty"`

	// ClientRoles maps client-scoped roles onto this organization's group, one
	// entry per client. This is the per-application half of the node model
	// (HKX-09): members of the node inherit each client's listed roles in
	// tokens issued for that client. Referenced clients and roles must already
	// exist (typically declared by a HankoApplication).
	ClientRoles []OrganizationClientRoles `json:"clientRoles,omitempty"`

	// Domains lists the internet domains owned by this tenant, e.g.
	// "alien6.com". Only valid on a root organization (empty parentRef): the
	// root is reconciled into a Keycloak Organization carrying the alias and
	// domains, which is the tenancy isolation boundary. Internal nodes inherit
	// the root's isolation and must leave this empty.
	Domains []string `json:"domains,omitempty"`

	// IdentityProvider is the alias of an existing realm identity broker to
	// link to this tenant root's Keycloak Organization, making it the tenant's
	// managed IdP. Only valid on a root organization (empty parentRef). When
	// empty, organization IdP links are left unmanaged: the operator never
	// unlinks a broker it was not told about, so a live login path cannot be
	// broken by omission.
	IdentityProvider string `json:"identityProvider,omitempty"`
}

// OrganizationClientRoles lists the client-scoped roles granted to an
// organization node for a single Keycloak client.
type OrganizationClientRoles struct {
	// Client is the Keycloak clientID owning the roles, e.g. "trunx-dashboard".
	// +kubebuilder:validation:Required
	Client string `json:"client"`

	// Roles lists the client role names mapped onto the node's group.
	// +kubebuilder:validation:MinItems=1
	Roles []string `json:"roles"`
}

// HankoOrganizationStatus describes the observed state of the organization.
type HankoOrganizationStatus struct {
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	// GroupID is the Keycloak UUID of the reconciled group.
	GroupID string `json:"groupID,omitempty"`

	// GroupPath is the full Keycloak group path, e.g. "/alien6/demo".
	GroupPath string `json:"groupPath,omitempty"`

	// PositionID is the hankoShell API position projected for hankoShell and ADK
	// consumers. A Ready organization always has both GroupID and PositionID.
	PositionID string `json:"positionID,omitempty"`

	// OrgID is the Keycloak Organization UUID reconciled for a tenant root.
	// Empty on internal nodes, which are groups only.
	OrgID string `json:"orgID,omitempty"`

	// ObservedGeneration is the spec generation last reconciled.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoOrganizationList contains a list of HankoOrganization.
type HankoOrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoOrganization `json:"items"`
}
