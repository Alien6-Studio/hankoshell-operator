package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hr,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".status.keycloakRealmID"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoRealm represents a Keycloak realm managed by hanko-operator.
type HankoRealm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoRealmSpec   `json:"spec,omitempty"`
	Status HankoRealmStatus `json:"status,omitempty"`
}

// HankoRealmSpec defines the desired state of a Keycloak realm.
// +kubebuilder:validation:XValidation:rule="!(has(self.iamProfileRef) && has(self.securityProfile))",message="iamProfileRef and securityProfile are mutually exclusive"
type HankoRealmSpec struct {
	// DisplayName is the human-readable realm name shown on the login page.
	DisplayName string `json:"displayName,omitempty"`

	// FrontendURL is the canonical public URL Keycloak uses for browser-facing
	// endpoints in this realm. When omitted, the operator leaves the existing
	// Keycloak realm frontend URL unmanaged.
	// +kubebuilder:validation:Pattern=`^https?://.+$`
	FrontendURL string `json:"frontendURL,omitempty"`

	// LoginTheme is the Keycloak theme applied to the realm login page.
	LoginTheme string `json:"loginTheme,omitempty"`

	// Roles lists realm-scoped roles managed additively by the operator.
	// Existing roles not declared here are preserved.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Roles []RealmRole `json:"roles,omitempty"`

	// IdentityProviders declares upstream identity brokers and their realm-scoped
	// mappers. Providers omitted from this list are left untouched unless they
	// were previously recorded as managed by this HankoRealm.
	// +listType=map
	// +listMapKey=alias
	// +kubebuilder:validation:MaxItems=32
	IdentityProviders []RealmIdentityProvider `json:"identityProviders,omitempty"`

	// OTPRequired forces TOTP for all realm users when true.
	OTPRequired bool `json:"otpRequired,omitempty"`

	// IAMProfileRef references a reusable HankoIAMProfile in the same namespace.
	// Every application in this realm inherits the resolved authentication policy.
	// It is mutually exclusive with the legacy inline SecurityProfile.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	IAMProfileRef string `json:"iamProfileRef,omitempty"`

	// SecurityProfile is the legacy inline authentication and security policy.
	// New managed realms should reference a reusable HankoIAMProfile instead.
	SecurityProfile *RealmSecurityProfile `json:"securityProfile,omitempty"`

	// Email retains platform messaging preferences for API compatibility.
	// Provider credentials, tests and sending belong to the platform API.
	// The operator does not route messages or change Keycloak SMTP with this field.
	Email *RealmEmailRouteSpec `json:"email,omitempty"`
}

// RealmEmailRouteSpec retains API messaging preferences without managing Keycloak SMTP.
type RealmEmailRouteSpec struct {
	// ProviderRef selects the singleton Graph provider. Empty or omitted
	// delegates Hanko UI delivery to the realm's SMTP path.
	// +kubebuilder:validation:Enum=platform-email
	ProviderRef string `json:"providerRef,omitempty"`

	// FromName is the sender display name for Hanko-owned messages.
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[^\r\n]*$`
	FromName string `json:"fromName,omitempty"`

	// ReplyTo optionally routes replies to a different mailbox.
	// +kubebuilder:validation:Format=email
	// +kubebuilder:validation:MaxLength=254
	ReplyTo string `json:"replyTo,omitempty"`

	// ReplyToName is the display name associated with ReplyTo.
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[^\r\n]*$`
	ReplyToName string `json:"replyToName,omitempty"`
}

// RealmRole describes a Keycloak realm role and the realm roles it includes.
// Composite membership is reconciled additively so adopting an existing role
// does not remove composites managed outside hankoShell.
// +kubebuilder:validation:XValidation:rule="!has(self.composites) || self.composites.all(r, r != 'HANKO_PLATFORM' && !r.startsWith('HANKO_PLATFORM_') && !r.startsWith('HANKO_FLEET_') && !r.startsWith('HANKO_CLUSTER_'))",message="reserved platform, fleet and cluster roles cannot be inherited through composites"
type RealmRole struct {
	// Name is the Keycloak realm role name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// Description is an optional human-readable explanation of the role.
	Description string `json:"description,omitempty"`

	// Composites lists realm roles included by this role.
	// Every referenced role must already exist or be declared in this spec.
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=255
	Composites []string `json:"composites,omitempty"`
}

// RealmIdentityProvider describes an upstream Keycloak identity broker.
// Non-sensitive provider options live in Config; client credentials must be
// supplied through ClientSecretRef so they never appear in the CRD or imports.
// +kubebuilder:validation:XValidation:rule="!has(self.config) || !('clientSecret' in self.config)",message="clientSecret must be supplied through clientSecretRef"
type RealmIdentityProvider struct {
	// Alias is the stable URL-addressable Keycloak provider name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=255
	Alias string `json:"alias"`

	// ProviderID is the Keycloak provider implementation, for example "oidc".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=255
	ProviderID string `json:"providerID"`

	DisplayName string `json:"displayName,omitempty"`

	// Boolean settings use pointers so imported providers preserve explicit
	// false values. Enabled defaults to true; the other flags default to false.
	Enabled                  *bool `json:"enabled,omitempty"`
	TrustEmail               *bool `json:"trustEmail,omitempty"`
	StoreToken               *bool `json:"storeToken,omitempty"`
	AddReadTokenRoleOnCreate *bool `json:"addReadTokenRoleOnCreate,omitempty"`
	LinkOnly                 *bool `json:"linkOnly,omitempty"`

	FirstBrokerLoginFlowAlias string `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias  string `json:"postBrokerLoginFlowAlias,omitempty"`

	// Config contains non-sensitive provider-specific Keycloak options. Only
	// declared keys are reconciled; provider defaults and opaque keys survive.
	// +kubebuilder:validation:MaxProperties=64
	Config map[string]string `json:"config,omitempty"`

	// ClientSecretRef points to the Kubernetes Secret key injected into
	// config.clientSecret at reconcile time. Imports never populate this field.
	ClientSecretRef *corev1.SecretKeySelector `json:"clientSecretRef,omitempty"`

	// Mappers are realm-scoped Keycloak identity-provider mappers owned by this
	// HankoRealm. Mapper names must be unique within the provider.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=32
	Mappers []RealmIdentityProviderMapper `json:"mappers,omitempty"`
}

// RealmIdentityProviderMapper is a provider-native mapper attached to a realm broker.
// Reserved authority markers in mapper config keys and values are checked
// exhaustively by the reconciler before any provider mutation. Admission CEL
// deliberately does not iterate this provider-native map because OpenAPI cannot
// bound JSON object-key length and Kubernetes therefore rejects the CRD's
// worst-case CEL cost estimate.
type RealmIdentityProviderMapper struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._ -]+$`
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// IdentityProviderMapper is the Keycloak mapper implementation identifier.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=255
	IdentityProviderMapper string `json:"identityProviderMapper"`

	// +kubebuilder:validation:MaxProperties=32
	Config map[string]string `json:"config,omitempty"`
}

// RealmSecurityProfile mirrors the hankoShell security policy structure.
type RealmSecurityProfile struct {
	// MFAPolicy controls multi-factor authentication enforcement.
	// +kubebuilder:validation:Enum=none;optional;required
	MFAPolicy string `json:"mfaPolicy,omitempty"`

	// PasswordMinLength is the minimum password length enforced by Keycloak.
	// +kubebuilder:validation:Minimum=8
	PasswordMinLength int `json:"passwordMinLength,omitempty"`

	// PasswordExpiryDays forces password renewal after this many days. 0 disables expiry.
	// +kubebuilder:validation:Minimum=0
	PasswordExpiryDays int `json:"passwordExpiryDays,omitempty"`

	// PasswordHistory prevents reuse of this many previous passwords.
	// +kubebuilder:validation:Minimum=0
	PasswordHistory *int `json:"passwordHistory,omitempty"`

	// PasswordRequireUppercase requires at least one uppercase character.
	PasswordRequireUppercase *bool `json:"passwordRequireUppercase,omitempty"`

	// PasswordRequireLowercase requires at least one lowercase character.
	PasswordRequireLowercase *bool `json:"passwordRequireLowercase,omitempty"`

	// PasswordRequireDigit requires at least one numeric character.
	PasswordRequireDigit *bool `json:"passwordRequireDigit,omitempty"`

	// PasswordRequireSpecial requires at least one special character.
	PasswordRequireSpecial *bool `json:"passwordRequireSpecial,omitempty"`

	// PasswordDisallowUsername prevents a user name from being used as the password.
	PasswordDisallowUsername *bool `json:"passwordDisallowUsername,omitempty"`

	// PasswordDisallowEmail prevents an email address from being used as the password.
	PasswordDisallowEmail *bool `json:"passwordDisallowEmail,omitempty"`

	// BruteForce holds brute-force protection settings.
	BruteForce *BruteForcePolicy `json:"bruteForce,omitempty"`

	// SessionLifetime is the maximum SSO session duration (Go duration string, e.g. "8h").
	SessionLifetime string `json:"sessionLifetime,omitempty"`

	// SessionIdleTimeout is the maximum inactive SSO session duration.
	SessionIdleTimeout string `json:"sessionIdleTimeout,omitempty"`

	// SSLRequired controls TLS enforcement on the Keycloak realm.
	// "external" (default) uses Keycloak's external-client TLS requirement,
	// including its local/private-address exceptions. This does not configure
	// the operator's administrative transport.
	// +kubebuilder:validation:Enum=none;external;all
	// +kubebuilder:default=external
	SSLRequired string `json:"sslRequired,omitempty"`

	// RevokeRefreshToken invalidates refresh tokens after a single use to prevent replay attacks.
	RevokeRefreshToken bool `json:"revokeRefreshToken,omitempty"`

	// RefreshTokenMaxReuse is the number of times a refresh token may be reused.
	// 0 means single use when RevokeRefreshToken is true.
	// +kubebuilder:validation:Minimum=0
	RefreshTokenMaxReuse int `json:"refreshTokenMaxReuse,omitempty"`

	// OTPAlgorithm is the TOTP hash algorithm applied when MFA is required or optional.
	// HmacSHA256 is recommended for new deployments; HmacSHA1 for legacy authenticator compat.
	// +kubebuilder:validation:Enum=HmacSHA1;HmacSHA256;HmacSHA512
	// +kubebuilder:default=HmacSHA1
	OTPAlgorithm string `json:"otpAlgorithm,omitempty"`

	// OTPDigits is the number of digits in generated TOTP codes.
	// +kubebuilder:validation:Enum=6;8
	OTPDigits int `json:"otpDigits,omitempty"`

	// OTPPeriodSeconds is the TOTP validity period.
	// +kubebuilder:validation:Minimum=15
	// +kubebuilder:validation:Maximum=120
	OTPPeriodSeconds int `json:"otpPeriodSeconds,omitempty"`

	// EmailVerificationRequired requires proof of email ownership.
	EmailVerificationRequired *bool `json:"emailVerificationRequired,omitempty"`

	// RememberMeEnabled allows persistent browser sessions.
	RememberMeEnabled *bool `json:"rememberMeEnabled,omitempty"`

	// UserRegistrationEnabled allows public realm self-registration.
	UserRegistrationEnabled *bool `json:"userRegistrationEnabled,omitempty"`

	// UserEventsEnabled records authentication and account events.
	UserEventsEnabled *bool `json:"userEventsEnabled,omitempty"`

	// AdminEventsEnabled records administrative realm changes.
	AdminEventsEnabled *bool `json:"adminEventsEnabled,omitempty"`

	// AuditRetentionDays controls Keycloak user-event retention for this realm.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3650
	AuditRetentionDays *int `json:"auditRetentionDays,omitempty"`

	// AuditExportEnabled sends realm events to Keycloak's external logging listener.
	AuditExportEnabled *bool `json:"auditExportEnabled,omitempty"`

	// ClientSecretRotationDays is the default cadence for managed confidential
	// applications and service accounts that do not declare their own policy.
	// Zero disables the realm default.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3650
	ClientSecretRotationDays *int `json:"clientSecretRotationDays,omitempty"`

	// AdminConsoleExposure controls the browser-based realm administration console.
	// Restricted expects the platform ingress allow-list; disabled also disables
	// the realm's security-admin-console client in Keycloak.
	// +kubebuilder:validation:Enum=public;restricted;disabled
	AdminConsoleExposure string `json:"adminConsoleExposure,omitempty"`

	// IDPBrokerRequireSignature requires configured identity providers to validate
	// upstream token or assertion signatures.
	IDPBrokerRequireSignature *bool `json:"idpBrokerRequireSignature,omitempty"`

	// IDPBrokerTrustEmail controls whether brokered identities may assert that an
	// upstream email address is already verified.
	IDPBrokerTrustEmail *bool `json:"idpBrokerTrustEmail,omitempty"`
}

// BruteForcePolicy configures Keycloak's built-in brute-force protection.
type BruteForcePolicy struct {
	// Enabled activates brute-force protection.
	Enabled bool `json:"enabled"`

	// MaxFailures is the number of failures before lockout.
	// +kubebuilder:validation:Minimum=1
	MaxFailures int `json:"maxFailures,omitempty"`

	// WaitIncrements is the lockout duration (Go duration string, e.g. "30s").
	WaitIncrements string `json:"waitIncrements,omitempty"`
}

// HankoRealmStatus describes the observed state of the realm.
type HankoRealmStatus struct {
	// Phase summarises the reconciliation state.
	// +kubebuilder:validation:Enum=Pending;Reconciling;Ready;Error
	Phase string `json:"phase,omitempty"`

	// ObservedGeneration is the HankoRealm generation represented by this status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// KeycloakRealmID is the realm ID as registered in Keycloak.
	KeycloakRealmID string `json:"keycloakRealmID,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// EffectiveIAMProfile is the resolved profile name, or "inline" for a legacy
	// inline security profile. Empty means that no explicit IAM profile is active.
	EffectiveIAMProfile string `json:"effectiveIAMProfile,omitempty"`

	// EffectivePolicyHash identifies the exact security policy applied to Keycloak.
	EffectivePolicyHash string `json:"effectivePolicyHash,omitempty"`

	// PolicyRevision increases whenever a different effective IAM policy is
	// successfully applied. Applications do not interpret this value.
	PolicyRevision int64 `json:"policyRevision,omitempty"`

	// AppliedMFAPolicy records the MFA level represented by EffectivePolicyHash.
	// It lets the operator detect a later strengthening and revoke older sessions.
	AppliedMFAPolicy string `json:"appliedMFAPolicy,omitempty"`

	// ManagedIdentityProviders records only provider objects whose lifecycle was
	// explicitly adopted by this HankoRealm. Cleanup never touches other brokers.
	// +listType=map
	// +listMapKey=alias
	ManagedIdentityProviders []ManagedRealmIdentityProviderReference `json:"managedIdentityProviders,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ManagedRealmIdentityProviderReference checkpoints provider ownership and its
// child mapper IDs so interrupted reconciliations remain safely recoverable.
type ManagedRealmIdentityProviderReference struct {
	Alias string `json:"alias"`

	// +listType=map
	// +listMapKey=name
	Mappers []ManagedRealmIdentityProviderMapperReference `json:"mappers,omitempty"`
}

// ManagedRealmIdentityProviderMapperReference identifies an owned Keycloak mapper.
type ManagedRealmIdentityProviderMapperReference struct {
	Name       string `json:"name"`
	KeycloakID string `json:"keycloakID"`
}

// +kubebuilder:object:root=true

// HankoRealmList contains a list of HankoRealm.
type HankoRealmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoRealm `json:"items"`
}
