package v1alpha1

// ApplicationSAML requires signed assertions and responses. Requests are unsigned;
// request signatures, encryption, SLO and SAML attribute mappers are unsupported.
// The realm owns IdP signing keys; the operator never reads their private keys.
type ApplicationSAML struct {
	// AssertionConsumerServices is the exact set of HTTP-POST ACS destinations.
	// HTTPS is required. Wildcards, userinfo, query and fragments are forbidden.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=2048
	// +kubebuilder:validation:items:Pattern=`^https://([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:[0-9]{1,5})?(/[^\s?#@\\*]*)?$`
	AssertionConsumerServices []string `json:"assertionConsumerServices"`

	// RequireSignedAssertions must be true. Response signing is also enforced.
	// This field does not require SP-signed authentication requests.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Enum=true
	RequireSignedAssertions *bool `json:"requireSignedAssertions,omitempty"`

	// NameIDFormat is forced by the IdP independently of request preferences.
	// +kubebuilder:validation:Enum=persistent;transient;email;unspecified
	// +kubebuilder:default=persistent
	NameIDFormat string `json:"nameIDFormat,omitempty"`
}

// SAMLEndpoints references realm IdP metadata, not a runtime workload binding.
// The metadata document supplies public signing certificates and rollover keys.
type SAMLEndpoints struct {
	// +kubebuilder:validation:MaxLength=2048
	Issuer string `json:"issuer"`
	// +kubebuilder:validation:MaxLength=2048
	SSO string `json:"sso"`
	// +kubebuilder:validation:MaxLength=2048
	Metadata string `json:"metadata"`
	// +kubebuilder:validation:Enum="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	ResponseBinding string `json:"responseBinding"`
}

// ApplicationCapabilitySnapshot names qualified application semantics only.
type ApplicationCapabilitySnapshot struct {
	OIDC                 bool `json:"oidc"`
	PublicClient         bool `json:"publicClient"`
	ConfidentialClient   bool `json:"confidentialClient"`
	SAML                 bool `json:"saml"`
	SAMLACS              bool `json:"samlACS"`
	SAMLAssertionSigning bool `json:"samlAssertionSigning"`
	SAMLResponseSigning  bool `json:"samlResponseSigning"`
	SAMLMetadata         bool `json:"samlMetadata"`
	ClientRoles          bool `json:"clientRoles"`
	ProtocolMappers      bool `json:"protocolMappers"`
}
