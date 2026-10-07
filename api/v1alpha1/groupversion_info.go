// Package v1alpha1 contains the v1alpha1 API group for hanko.sh.
//
// +kubebuilder:object:generate=true
// +groupName=hanko.sh
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version for the hanko.sh API.
	GroupVersion = schema.GroupVersion{Group: "hanko.sh", Version: "v1alpha1"}

	// SchemeBuilder registers types in the scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&HankoApplication{},
		&HankoApplicationList{},
		&HankoEmailProvider{},
		&HankoEmailProviderList{},
		&HankoIAMProfile{},
		&HankoIAMProfileList{},
		&HankoImport{},
		&HankoImportList{},
		&HankoIssuer{},
		&HankoIssuerList{},
		&HankoKeycloakInstance{},
		&HankoKeycloakInstanceList{},
		&HankoMeshService{},
		&HankoMeshServiceList{},
		&HankoOperation{},
		&HankoOperationList{},
		&HankoOrganization{},
		&HankoOrganizationList{},
		&HankoRealm{},
		&HankoRealmList{},
		&HankoResourceServer{},
		&HankoResourceServerList{},
		&HankoRole{},
		&HankoRoleList{},
		&HankoServiceAccount{},
		&HankoServiceAccountList{},
		&HankoSnapshot{},
		&HankoSnapshotList{},
		&HankoTenant{},
		&HankoTenantList{},
		&HankoTheme{},
		&HankoThemeList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
