package v1beta1

import (
	alpha "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ToHub returns an independent object for the existing reconciliation/storage
// hub. Only the root wire version changes; journals, references and authority
// identities, including ownerReference API versions, remain untouched.
func (in *HankoApplication) ToHub() *alpha.HankoApplication {
	if in == nil {
		return nil
	}
	return &alpha.HankoApplication{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoApplication"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}

func ApplicationFromHub(in *alpha.HankoApplication) *HankoApplication {
	if in == nil {
		return nil
	}
	return &HankoApplication{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoApplication"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}

func (in *HankoRole) ToHub() *alpha.HankoRole {
	if in == nil {
		return nil
	}
	return &alpha.HankoRole{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoRole"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}

func RoleFromHub(in *alpha.HankoRole) *HankoRole {
	if in == nil {
		return nil
	}
	return &HankoRole{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoRole"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}

func (in *HankoResourceServer) ToHub() *alpha.HankoResourceServer {
	if in == nil {
		return nil
	}
	return &alpha.HankoResourceServer{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoResourceServer"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}

func ResourceServerFromHub(in *alpha.HankoResourceServer) *HankoResourceServer {
	if in == nil {
		return nil
	}
	return &HankoResourceServer{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoResourceServer"}, ObjectMeta: *in.ObjectMeta.DeepCopy(), Spec: *in.Spec.DeepCopy(), Status: *in.Status.DeepCopy()}
}
