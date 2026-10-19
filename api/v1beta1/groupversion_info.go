// Package v1beta1 serves the structurally equivalent candidate IAM API.
// API maturity is recorded separately from its wire version.
//
// +kubebuilder:object:generate=true
// +groupName=hanko.sh
package v1beta1

import (
	"errors"
	alpha "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "hanko.sh", Version: "v1beta1"}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &HankoApplication{}, &HankoApplicationList{}, &HankoRole{}, &HankoRoleList{}, &HankoResourceServer{}, &HankoResourceServerList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	for _, pair := range []struct {
		from, to any
		convert  conversion.ConversionFunc
	}{
		{&alpha.HankoApplicationList{}, &HankoApplicationList{}, structuralConversion(ApplicationListFromHub)},
		{&HankoApplicationList{}, &alpha.HankoApplicationList{}, structuralConversion((*HankoApplicationList).ToHub)},
		{&alpha.HankoApplication{}, &HankoApplication{}, structuralConversion(ApplicationFromHub)},
		{&HankoApplication{}, &alpha.HankoApplication{}, structuralConversion((*HankoApplication).ToHub)},
		{&alpha.HankoRoleList{}, &HankoRoleList{}, structuralConversion(RoleListFromHub)},
		{&HankoRoleList{}, &alpha.HankoRoleList{}, structuralConversion((*HankoRoleList).ToHub)},
		{&alpha.HankoRole{}, &HankoRole{}, structuralConversion(RoleFromHub)},
		{&HankoRole{}, &alpha.HankoRole{}, structuralConversion((*HankoRole).ToHub)},
		{&alpha.HankoResourceServerList{}, &HankoResourceServerList{}, structuralConversion(ResourceServerListFromHub)},
		{&HankoResourceServerList{}, &alpha.HankoResourceServerList{}, structuralConversion((*HankoResourceServerList).ToHub)},
		{&alpha.HankoResourceServer{}, &HankoResourceServer{}, structuralConversion(ResourceServerFromHub)},
		{&HankoResourceServer{}, &alpha.HankoResourceServer{}, structuralConversion((*HankoResourceServer).ToHub)},
	} {
		if err := scheme.AddConversionFunc(pair.from, pair.to, pair.convert); err != nil {
			return err
		}
	}
	return nil
}

// The scheme controls registration, while checked assertions also make an
// accidentally misregistered converter return an error rather than panic.
func structuralConversion[A, B any](translate func(*A) *B) conversion.ConversionFunc {
	return func(a, b any, _ conversion.Scope) error {
		source, sourceOK := a.(*A)
		destination, destinationOK := b.(*B)
		if !sourceOK || !destinationOK || source == nil || destination == nil {
			return errors.New("invalid structural conversion types")
		}
		*destination = *translate(source)
		return nil
	}
}
