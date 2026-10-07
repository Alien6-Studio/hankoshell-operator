// Package v1alpha1 contains the v1alpha1 API group for hanko.sh.
//
// +kubebuilder:object:generate=true
// +groupName=hanko.sh
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version for the hanko.sh API.
	GroupVersion = schema.GroupVersion{Group: "hanko.sh", Version: "v1alpha1"}

	// SchemeBuilder registers types in the scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
