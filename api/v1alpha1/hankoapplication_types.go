package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=happ,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="ClientID",type=string,JSONPath=".spec.clientID"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoApplication represents an OIDC or qualified SAML application in a realm.
type HankoApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoApplicationSpec   `json:"spec,omitempty"`
	Status HankoApplicationStatus `json:"status,omitempty"`
}

// HankoApplicationSpec defines the desired application identity.
// +kubebuilder:validation:XValidation:rule="!has(self.runtimeBindings) || size(self.runtimeBindings) == 0 || !has(self.mode) || self.mode == 'Manage'",message="runtimeBindings require Manage mode"
// +kubebuilder:validation:XValidation:rule="!has(self.runtimeBindings) || self.runtimeBindings.all(b, !has(b.credentials) || ((!has(self.protocol) || self.protocol == 'oidc') && (!has(self.type) || self.type == 'web' || self.type == 'm2m')))",message="runtime credentials require confidential OIDC web or m2m clients"
// +kubebuilder:validation:XValidation:rule="!has(self.clientSecretProjections) || size(self.clientSecretProjections) == 0 || (has(self.type) && (self.type == 'web' || self.type == 'm2m'))",message="clientSecretProjections require a confidential web or m2m client"
// +kubebuilder:validation:XValidation:rule="!has(self.clientSecretProjections) || !has(self.mode) || self.mode != 'Observe'",message="clientSecretProjections require Manage mode"
// +kubebuilder:validation:XValidation:rule="self.clientID.trim() != 'account' && self.clientID.trim() != 'account-console' && self.clientID.trim() != 'admin-cli' && self.clientID.trim() != 'broker' && self.clientID.trim() != 'realm-management' && self.clientID.trim() != 'security-admin-console'",message="built-in Keycloak clients cannot be managed as HankoApplication"
// +kubebuilder:validation:XValidation:rule="(!has(self.protocol) || self.protocol == 'oidc') ? !has(self.saml) : has(self.saml)",message="saml configuration is required only for protocol saml"
// +kubebuilder:validation:XValidation:rule="!has(self.protocol) || self.protocol != 'saml' || (!has(self.type) && (!has(self.redirectURIs) || size(self.redirectURIs) == 0) && (!has(self.postLogoutRedirectURIs) || size(self.postLogoutRedirectURIs) == 0) && (!has(self.tokenClaims) || size(self.tokenClaims) == 0) && (!has(self.identityMappings) || size(self.identityMappings) == 0) && !has(self.realmRoleScopes) && !has(self.secretRotationPolicy) && (!has(self.clientSecretProjections) || size(self.clientSecretProjections) == 0))",message="SAML rejects OIDC types, callbacks, claims, mappings, scopes, rotation and secret projections"
// +kubebuilder:validation:XValidation:rule="!has(self.attributes) || self.attributes.all(k, !k.matches('(?i)^(saml|hanko[.]).*') && !k.matches('(?i)^(protocol|login_theme|post[.]logout[.]redirect[.]uris)$') && !k.matches('(?i).*(private|password|secret|credential|access_token|bearer).*'))",message="native attributes cannot override protocol, SAML, ownership or managed theme/logout settings"
type HankoApplicationSpec struct {
	// RealmRef references the HankoRealm this application belongs to.
	// +kubebuilder:validation:Required
	RealmRef string `json:"realmRef"`

	// ClientID is the Keycloak client identifier.
	// +kubebuilder:validation:Required
	ClientID string `json:"clientID"`

	// Protocol defaults to OIDC for existing manifests. An owned client cannot
	// change protocol without administrator-reviewed deletion and recreation.
	// +kubebuilder:validation:Enum=oidc;saml
	// +kubebuilder:default=oidc
	Protocol string `json:"protocol,omitempty"`

	// SAML is the bounded SP-initiated contract. ClientID is the SP entity ID.
	SAML *ApplicationSAML `json:"saml,omitempty"`

	// Type is the application type.
	// +kubebuilder:validation:Enum=spa;web;m2m
	Type string `json:"type,omitempty"`

	// RedirectURIs is the list of allowed redirect URIs after authentication.
	RedirectURIs []string `json:"redirectURIs,omitempty"`

	// PostLogoutRedirectURIs is the list of allowed URIs after logout.
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectURIs,omitempty"`

	// Theme references a HankoTheme to apply to this application's login page.
	Theme string `json:"theme,omitempty"`

	// Roles lists client roles to create in Keycloak alongside this application.
	// Roles are scoped to this client and deleted automatically when the client is deleted.
	Roles []ApplicationRole `json:"roles,omitempty"`

	// RealmRoleScopes is the exact set of realm roles allowed into tokens issued
	// to this client while Keycloak fullScopeAllowed remains disabled. When the
	// field is omitted, existing realm-role scope mappings remain unmanaged.
	// +listType=set
	RealmRoleScopes []string `json:"realmRoleScopes,omitempty"`

	// IdentityMappings maps claims received from an upstream OIDC identity provider
	// to Keycloak realm roles, roles owned by this client, or user attributes.
	// The mapper itself is realm-scoped in Keycloak but is lifecycle-owned by this application.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	IdentityMappings []ApplicationIdentityMapping `json:"identityMappings,omitempty"`

	// TokenClaims exposes a Keycloak user attribute or a fixed value as a claim only
	// in tokens issued to this application. These are client-scoped protocol mappers.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	TokenClaims []ApplicationTokenClaim `json:"tokenClaims,omitempty"`

	// Attributes sets arbitrary Keycloak client attributes (single string value per
	// key). The full map is the desired state and replaces unmanaged keys set
	// directly in Keycloak on every reconcile. Keys reserved by the operator for
	// other spec fields (login_theme, post.logout.redirect.uris) are rejected.
	// +kubebuilder:validation:MaxProperties=64
	Attributes map[string]string `json:"attributes,omitempty"`

	// Mode controls the operator's write authority over the underlying Keycloak client.
	//
	// Manage: the operator creates, updates and deletes the client, and owns its
	// lifecycle (client secret, roles, finalizer-gated deletion).
	//
	// Observe: the operator only reads the client to report status. It never creates,
	// updates, or deletes the client in Keycloak, and never reads or stores its secret.
	// Objects carrying the hanko.sh/imported-by label are always treated as Observe,
	// regardless of this field, for backward compatibility with pre-existing imports.
	// +kubebuilder:validation:Enum=Manage;Observe
	// +kubebuilder:default=Manage
	Mode string `json:"mode,omitempty"`

	// SecretRotationPolicy controls rotation for confidential web and m2m
	// clients. It is ignored for public SPA clients and Observe-mode objects.
	SecretRotationPolicy *SecretRotationPolicy `json:"secretRotationPolicy,omitempty"`

	// ClientSecretProjections copies the operator-managed client secret into
	// dedicated, pre-provisioned Secrets in workload namespaces. Projections are
	// reconciled on every rotation and cleared with this application. Existing
	// Secrets not explicitly pre-authorized for this application are never
	// adopted or overwritten.
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	ClientSecretProjections []ApplicationSecretProjection `json:"clientSecretProjections,omitempty"`

	// RuntimeBindings delivers proven application metadata and optional OIDC
	// credentials to preauthorized, pre-existing workload targets. Manage only.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=32
	RuntimeBindings []ApplicationRuntimeBinding `json:"runtimeBindings,omitempty"`
}

// ApplicationSecretProjection selects a dedicated workload Secret that receives
// the confidential OIDC client secret under the client_secret key.
type ApplicationSecretProjection struct {
	// Namespace is the workload namespace that receives the projected Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`

	// Name is the dedicated Secret name in the target namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
}

// ApplicationRole describes a Keycloak client role managed by the operator.
type ApplicationRole struct {
	// Name is the Keycloak client role name.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Description is an optional human-readable description.
	Description string `json:"description,omitempty"`
}

// ApplicationIdentityMapping describes an inbound OIDC broker mapper owned by
// a HankoApplication.
type ApplicationIdentityMapping struct {
	// Name is unique within this application and is used to derive a stable
	// operator-owned Keycloak mapper name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// KeycloakName explicitly adopts an existing mapper by name. When omitted,
	// the operator derives an application-namespaced mapper name. Use this only
	// for deliberate migration of a pre-existing mapper.
	KeycloakName string `json:"keycloakName,omitempty"`

	// IdentityProvider is the Keycloak identity-provider alias, for example "entra".
	// +kubebuilder:validation:Required
	IdentityProvider string `json:"identityProvider"`

	// Claim is the upstream OIDC claim to inspect or import, for example "groups".
	// +kubebuilder:validation:Required
	Claim string `json:"claim"`

	// MatchValue is required for role targets and is the exact claim value that
	// grants the role. For array claims, Keycloak matches when the array contains it.
	// It is omitted for userAttribute targets, which import the complete claim value.
	MatchValue string `json:"matchValue,omitempty"`

	// SyncMode controls updates when an already-linked user logs in again.
	// +kubebuilder:validation:Enum=IMPORT;FORCE;LEGACY;INHERIT
	// +kubebuilder:default=FORCE
	SyncMode string `json:"syncMode,omitempty"`

	// Target selects exactly one Keycloak destination.
	// +kubebuilder:validation:Required
	Target ApplicationIdentityMappingTarget `json:"target"`
}

// ApplicationIdentityMappingTarget selects the destination of an inbound claim.
// Exactly one field must be set.
// +kubebuilder:validation:XValidation:rule="(has(self.realmRole) ? 1 : 0) + (has(self.clientRole) ? 1 : 0) + (has(self.userAttribute) ? 1 : 0) == 1",message="exactly one of realmRole, clientRole or userAttribute must be set"
// +kubebuilder:validation:XValidation:rule="!has(self.realmRole) || (self.realmRole != 'HANKO_PLATFORM' && !self.realmRole.startsWith('HANKO_PLATFORM_') && !self.realmRole.startsWith('HANKO_FLEET_') && !self.realmRole.startsWith('HANKO_CLUSTER_'))",message="reserved platform, fleet and cluster roles cannot be granted by an application identity mapping"
type ApplicationIdentityMappingTarget struct {
	// RealmRole grants an existing realm role when the claim matches.
	// +kubebuilder:validation:MaxLength=255
	RealmRole string `json:"realmRole,omitempty"`

	// ClientRole grants a role owned by this HankoApplication. The role should
	// also be declared in spec.roles.
	ClientRole string `json:"clientRole,omitempty"`

	// UserAttribute imports the upstream claim into this Keycloak user attribute.
	// Because Keycloak users are realm-scoped, the persisted attribute is global;
	// spec.tokenClaims controls which applications receive it in tokens.
	UserAttribute string `json:"userAttribute,omitempty"`
}

// ApplicationTokenClaim describes a client-scoped OIDC protocol mapper. Only
// the typed mapper forms below are supported; arbitrary Keycloak mapper
// implementations and reserved identity/authorization claims fail closed.
// +kubebuilder:validation:XValidation:rule="[has(self.userAttribute), has(self.value), has(self.realmRoles)].exists_one(x, x)",message="exactly one of userAttribute, value or realmRoles must be set"
// +kubebuilder:validation:XValidation:rule="self.claim != 'sub' && self.claim != 'iss' && self.claim != 'exp' && self.claim != 'iat' && self.claim != 'nbf' && self.claim != 'jti' && self.claim != 'azp' && self.claim != 'typ' && self.claim != 'sid' && self.claim != 'scope' && self.claim != 'session_state' && self.claim != 'nonce' && self.claim != 'auth_time' && self.claim != 'acr' && self.claim != 'amr' && self.claim != 'at_hash' && self.claim != 'c_hash' && self.claim != 's_hash' && self.claim != 'client_id' && self.claim != 'hanko_token_use' && self.claim != 'realm_access' && !self.claim.startsWith('realm_access.') && self.claim != 'resource_access' && !self.claim.startsWith('resource_access.') && self.claim != 'authorization' && !self.claim.startsWith('authorization.') && self.claim != 'permissions' && !self.claim.startsWith('permissions.') && self.claim != 'https://hanko.sh/authorization' && !self.claim.startsWith('https://hanko.sh/authorization.') && self.claim != 'cnf' && !self.claim.startsWith('cnf.') && self.claim != 'act' && !self.claim.startsWith('act.') && self.claim != 'may_act' && !self.claim.startsWith('may_act.') && self.claim != 'authorization_details' && !self.claim.startsWith('authorization_details.')",message="reserved identity and authorization claims cannot be overridden"
type ApplicationTokenClaim struct {
	// Name is unique within this application.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// KeycloakName explicitly adopts an existing client protocol mapper by name.
	// When omitted, the operator derives a stable application-scoped name.
	KeycloakName string `json:"keycloakName,omitempty"`

	// Claim is the claim name emitted in tokens. Dot notation creates nested claims.
	// The reserved value "aud" with a fixed Value uses Keycloak's native Audience
	// mapper so existing access-token audiences are preserved.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Claim string `json:"claim"`

	// UserAttribute reads the value from a Keycloak user attribute.
	// Exactly one of userAttribute and value must be set.
	UserAttribute string `json:"userAttribute,omitempty"`

	// Value emits a fixed application-specific claim value. A pointer allows an
	// explicitly configured empty string to remain distinguishable from omission.
	Value *string `json:"value,omitempty"`

	// RealmRoles projects the caller's realm roles into this claim as a
	// multivalued array (Keycloak's realm-role user-model mapper). It is the
	// substrate for hierarchical-org role projection (HKX-09): a member inherits
	// realm roles from their organization group, and this claim carries them to
	// the consuming application (e.g. Trunx reads "trunx_roles"). Exactly one of
	// userAttribute, value or realmRoles must be set.
	RealmRoles bool `json:"realmRoles,omitempty"`

	// RealmRolePrefix, when set, restricts and strips a prefix from the projected
	// realm-role names. Only meaningful together with realmRoles.
	RealmRolePrefix string `json:"realmRolePrefix,omitempty"`

	// JSONType controls conversion of the emitted value.
	// +kubebuilder:validation:Enum=String;long;int;boolean;JSON
	// +kubebuilder:default=String
	JSONType string `json:"jsonType,omitempty"`

	// Multivalued emits all values of a user attribute as an array.
	Multivalued bool `json:"multivalued,omitempty"`

	// Token destinations default to true when omitted. Introspection defaults to
	// the access-token setting.
	AddToIDToken       *bool `json:"addToIDToken,omitempty"`
	AddToAccessToken   *bool `json:"addToAccessToken,omitempty"`
	AddToUserInfo      *bool `json:"addToUserInfo,omitempty"`
	AddToIntrospection *bool `json:"addToIntrospection,omitempty"`
}

// HankoApplicationStatus describes the observed state of the application.
type HankoApplicationStatus struct {
	// AdoptionCandidate is bounded review evidence, never execution authority.
	AdoptionCandidate *AdoptionCandidateStatus `json:"adoptionCandidate,omitempty"`

	// RuntimeBindings records bounded delivery evidence, never write authority.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=32
	RuntimeBindings []ApplicationRuntimeBindingStatus `json:"runtimeBindings,omitempty"`
	// Protocol is the actual protocol detected by a successful provider read.
	// A mismatch is reported; this field never authorizes protocol conversion.
	// +kubebuilder:validation:Enum=oidc;saml;unsupported
	Protocol string `json:"protocol,omitempty"`

	// EvaluatedGeneration is the latest generation whose execution semantics
	// were fully evaluated or definitively refused. It does not prove application.
	// +kubebuilder:validation:Minimum=0
	EvaluatedGeneration int64 `json:"evaluatedGeneration,omitempty"`

	// AppliedGeneration is the latest Manage generation proven by matching
	// provider read-back. Observe clears applied evidence and cannot advance it.
	// +kubebuilder:validation:Minimum=0
	AppliedGeneration int64 `json:"appliedGeneration,omitempty"`

	// ContractVersion identifies canonical evidence semantics, not an executable API.
	// +kubebuilder:validation:MaxLength=64
	ContractVersion string `json:"contractVersion,omitempty"`

	// IntentHash identifies normalized portable semantics of EvaluatedGeneration.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	IntentHash string `json:"intentHash,omitempty"`

	// EvaluatedPlanHash identifies the locally compiled provider-bound plan.
	// It is absent for rejected evaluation and is never execution authority.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	EvaluatedPlanHash string `json:"evaluatedPlanHash,omitempty"`

	// ObservedStateHash identifies safe normalized provider semantics, including
	// observation coverage. It is neither an intent/plan identity nor a provider ID.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservedStateHash string `json:"observedStateHash,omitempty"`

	// ObservationGeneration and ObservationPlanHash bind the latest successful
	// bounded read to its evaluated input. They remain unchanged on read failure.
	// +kubebuilder:validation:Minimum=0
	ObservationGeneration int64 `json:"observationGeneration,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservationPlanHash string `json:"observationPlanHash,omitempty"`

	// ObservationComplete distinguishes full supported-contract read-back from
	// partial coverage. A partial observation can prove drift but never equality.
	ObservationComplete bool `json:"observationComplete,omitempty"`

	// DriftState is the comparison for ObservationPlanHash. Failure conditions
	// describe the current attempt; an older observation is historical evidence.
	// +kubebuilder:validation:Enum=Unknown;InSync;Drifted
	DriftState string `json:"driftState,omitempty"`

	// CapabilityEvidence names static adapter qualification, not runtime discovery.
	CapabilityEvidence IAMCapabilityEvidence `json:"capabilityEvidence,omitempty"`

	// AppliedPlanHash identifies the latest Manage plan proven by matching read-back.
	// Observe clears applied evidence and cannot claim provider application.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	AppliedPlanHash string `json:"appliedPlanHash,omitempty"`
	// +kubebuilder:validation:MaxLength=32
	BackendKind  string                        `json:"backendKind,omitempty"`
	Capabilities ApplicationCapabilitySnapshot `json:"capabilities,omitempty"`
	// +listType=map
	// +listMapKey=classification
	// +listMapKey=objectKind
	// +listMapKey=objectName
	// +listMapKey=code
	// +kubebuilder:validation:MaxItems=32
	Findings []AuthorizationFinding `json:"findings,omitempty"`

	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error;Conflict
	Phase string `json:"phase,omitempty"`

	// ObservedGeneration is the latest metadata.generation processed into status.
	// AppliedGeneration separately proves successful execution and read-back.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClientSecret references the K8s Secret holding the OIDC client secret.
	// Only set for confidential clients (web, m2m).
	ClientSecret *SecretReference `json:"clientSecret,omitempty"`

	// OIDCEndpoints holds the Keycloak OIDC endpoint URLs for this application.
	OIDCEndpoints *OIDCEndpoints `json:"oidcEndpoints,omitempty"`

	// SAMLEndpoints is absent for OIDC applications. No full XML is stored.
	SAMLEndpoints *SAMLEndpoints `json:"samlEndpoints,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// LastRotated is the timestamp of the last confidential client secret rotation.
	LastRotated *metav1.Time `json:"lastRotated,omitempty"`

	// NextRotation is the next scheduled secret rotation, when configured.
	NextRotation *metav1.Time `json:"nextRotation,omitempty"`

	// ManagedClientSecretProjections records the exact workload Secrets whose
	// client_secret value is lifecycle-managed by this application.
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	ManagedClientSecretProjections []ApplicationSecretProjection `json:"managedClientSecretProjections,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ManagedIdentityMappings records realm-scoped identity-provider mappers
	// lifecycle-owned by this application.
	ManagedIdentityMappings []ManagedIdentityMappingReference `json:"managedIdentityMappings,omitempty"`

	// ManagedTokenClaims records client-scoped protocol mappers managed for this application.
	ManagedTokenClaims []ManagedTokenClaimReference `json:"managedTokenClaims,omitempty"`
}

// ManagedIdentityMappingReference reports the desired identity-provider mapper's
// reconciliation state. KeycloakID is set once the operator owns an external mapper.
type ManagedIdentityMappingReference struct {
	Name             string `json:"name"`
	IdentityProvider string `json:"identityProvider"`
	KeycloakID       string `json:"keycloakID"`
	// Conditions reports this mapper's individual reconciliation state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ManagedTokenClaimReference reports the desired client protocol mapper's
// reconciliation state. KeycloakID is set once the operator owns an external mapper.
type ManagedTokenClaimReference struct {
	Name       string `json:"name"`
	KeycloakID string `json:"keycloakID"`
	// Conditions reports this mapper's individual reconciliation state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SecretReference points to a K8s Secret key holding a sensitive value.
type SecretReference struct {
	SecretRef corev1.SecretKeySelector `json:"secretRef"`
}

// OIDCEndpoints holds the standard OIDC discovery URLs for an application.
type OIDCEndpoints struct {
	Issuer        string `json:"issuer,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	Token         string `json:"token,omitempty"`
	JWKS          string `json:"jwks,omitempty"`
	UserInfo      string `json:"userInfo,omitempty"`
}

// +kubebuilder:object:root=true

// HankoApplicationList contains a list of HankoApplication.
type HankoApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoApplication `json:"items"`
}
