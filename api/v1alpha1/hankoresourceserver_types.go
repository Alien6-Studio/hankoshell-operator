package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hrs,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Audience",type=string,JSONPath=".spec.audience"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoResourceServer is the provider-neutral aggregate for one protected API.
type HankoResourceServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoResourceServerSpec   `json:"spec,omitempty"`
	Status HankoResourceServerStatus `json:"status,omitempty"`
}

// HankoResourceServerSpec defines the portable desired authorization model.
// Internal scope and resource references are checked at admission time. Realm,
// role, application, and service-account existence is checked fail-closed by
// the reconciler because structural CRD validation cannot dereference objects.
// +kubebuilder:validation:XValidation:rule="!has(self.resources) || self.resources.all(r, !has(r.scopes) || (has(self.scopes) && r.scopes.all(scopeName, self.scopes.exists(s, s.name == scopeName))))",message="every resource scope must reference a declared scope"
// +kubebuilder:validation:XValidation:rule="!has(self.permissions) || self.permissions.all(p, has(self.scopes) && p.scopes.all(scopeName, self.scopes.exists(s, s.name == scopeName)))",message="every permission scope must reference a declared scope"
// +kubebuilder:validation:XValidation:rule="!has(self.permissions) || self.permissions.all(p, !has(p.resources) || (has(self.resources) && p.resources.all(resourceName, self.resources.exists(r, r.name == resourceName))))",message="every permission resource must reference a declared resource"
type HankoResourceServerSpec struct {
	// RealmRef references the HankoRealm containing every referenced principal.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	RealmRef string `json:"realmRef"`

	// Audience is the immutable identifier of the protected API.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="!oldSelf.hasValue() || self == oldSelf.value()",message="audience is immutable",optionalOldSelf=true
	Audience string `json:"audience"`

	// DisplayName is the human-readable protected API name.
	// +kubebuilder:validation:MaxLength=255
	DisplayName string `json:"displayName,omitempty"`

	// ApplicationRef names the HankoApplication backing this resource server.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	ApplicationRef string `json:"applicationRef"`

	// Mode controls provider write authority.
	// +kubebuilder:validation:Enum=Manage;Observe
	// +kubebuilder:default=Manage
	Mode string `json:"mode,omitempty"`

	// Scopes is a name-keyed set of portable authorization scopes.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Scopes []AuthorizationScope `json:"scopes,omitempty"`

	// Resources is a name-keyed set of protected resource objects.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Resources []AuthorizationResource `json:"resources,omitempty"`

	// Permissions is a name-keyed set of allow-only grants.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=128
	Permissions []AuthorizationPermission `json:"permissions,omitempty"`
}

// AuthorizationScope is a scope owned by one resource server.
type AuthorizationScope struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9:._/-]*$`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// +kubebuilder:validation:MaxLength=1024
	Description string `json:"description,omitempty"`
}

// AuthorizationResource is a protected resource and its scope bindings.
type AuthorizationResource struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9:._/-]*$`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// +kubebuilder:validation:MaxLength=255
	DisplayName string `json:"displayName,omitempty"`

	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=2048
	URIs []string `json:"uris,omitempty"`

	// +kubebuilder:validation:MaxLength=255
	Type string `json:"type,omitempty"`

	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=255
	Scopes []string `json:"scopes,omitempty"`
}

// AuthorizationPermission grants scopes over optional resources to principals.
type AuthorizationPermission struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9:._/-]*$`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=255
	Resources []string `json:"resources,omitempty"`

	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=255
	Scopes []string `json:"scopes"`

	// +listType=map
	// +listMapKey=kind
	// +listMapKey=ref
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	Principals []AuthorizationPrincipal `json:"principals"`
}

// AuthorizationPrincipal is a portable role or workload principal. Ref is a
// namespaced Hanko object name; provider IDs are never accepted in desired state.
type AuthorizationPrincipal struct {
	// +kubebuilder:validation:Enum=realm_role;application;service_account
	Kind string `json:"kind"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Ref string `json:"ref"`
}

// HankoResourceServerStatus describes provider observations only.
type HankoResourceServerStatus struct {
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AppliedPlanHash is copied from the API-owned plan annotation only after
	// the corresponding generation has reconciled successfully.
	AppliedPlanHash string `json:"appliedPlanHash,omitempty"`

	BackendKind string `json:"backendKind,omitempty"`

	ProviderResourceServerID string `json:"providerResourceServerID,omitempty"`

	Capabilities AuthorizationCapabilitySnapshot `json:"capabilities,omitempty"`

	ManagedObjects AuthorizationManagedObjects `json:"managedObjects,omitempty"`

	// +listType=map
	// +listMapKey=classification
	// +listMapKey=objectKind
	// +listMapKey=objectName
	// +listMapKey=code
	Findings []AuthorizationFinding `json:"findings,omitempty"`

	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AuthorizationCapabilitySnapshot records the provider contract used during reconciliation.
type AuthorizationCapabilitySnapshot struct {
	ScopeGrants              bool `json:"scopeGrants"`
	RolePrincipals           bool `json:"rolePrincipals"`
	ApplicationPrincipals    bool `json:"applicationPrincipals"`
	ServiceAccountPrincipals bool `json:"serviceAccountPrincipals"`
	ResourceObjects          bool `json:"resourceObjects"`
	ResourceURIMatching      bool `json:"resourceURIMatching"`
	UMARPT                   bool `json:"umaRPT"`
	NativePermissionClaim    bool `json:"nativePermissionClaim"`
}

// AuthorizationManagedObjects stores only provider IDs proven to be owned by this CR.
type AuthorizationManagedObjects struct {
	// +listType=map
	// +listMapKey=name
	Scopes []AuthorizationManagedReference `json:"scopes,omitempty"`
	// +listType=map
	// +listMapKey=name
	Resources []AuthorizationManagedReference `json:"resources,omitempty"`
	// +listType=map
	// +listMapKey=name
	Policies []AuthorizationManagedReference `json:"policies,omitempty"`
	// +listType=map
	// +listMapKey=name
	Permissions []AuthorizationManagedReference `json:"permissions,omitempty"`
}

// AuthorizationManagedReference binds a portable name to one provider-generated ID.
type AuthorizationManagedReference struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// AuthorizationFinding is a machine-readable portability or provider-native gap.
type AuthorizationFinding struct {
	// +kubebuilder:validation:Enum=lossless;lossy;unsupported
	Classification string `json:"classification"`
	ObjectKind     string `json:"objectKind"`
	ObjectName     string `json:"objectName"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	ReadOnly       bool   `json:"readOnly,omitempty"`
}

// +kubebuilder:object:root=true

// HankoResourceServerList contains HankoResourceServer objects.
type HankoResourceServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoResourceServer `json:"items"`
}
