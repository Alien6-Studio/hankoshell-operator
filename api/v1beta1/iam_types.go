package v1beta1

import (
	alpha "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Reusing the exact hub field types prevents version-specific pruning, defaults
// or authority semantics. The generated schemas are compared independently.
type HankoApplicationSpec = alpha.HankoApplicationSpec
type HankoApplicationStatus = alpha.HankoApplicationStatus
type HankoRoleSpec = alpha.HankoRoleSpec
type HankoRoleStatus = alpha.HankoRoleStatus
type HankoResourceServerSpec = alpha.HankoResourceServerSpec
type HankoResourceServerStatus = alpha.HankoResourceServerStatus

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=".spec.realmRef"
// +kubebuilder:resource:scope=Namespaced,shortName=happ,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="ClientID",type=string,JSONPath=".spec.clientID"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// HankoApplication represents an OIDC or qualified SAML application in a realm.
type HankoApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HankoApplicationSpec   `json:"spec,omitempty"`
	Status            HankoApplicationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HankoApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoApplication `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hrole,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Realm",type=string,JSONPath=".spec.realmRef"
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// HankoRole represents one realm-scoped role in Keycloak.
type HankoRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HankoRoleSpec   `json:"spec,omitempty"`
	Status            HankoRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HankoRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoRole `json:"items"`
}

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
	Spec              HankoResourceServerSpec   `json:"spec,omitempty"`
	Status            HankoResourceServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HankoResourceServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoResourceServer `json:"items"`
}
