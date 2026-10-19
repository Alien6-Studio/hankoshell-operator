package v1beta1

import (
	alpha "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (in *HankoApplicationList) ToHub() *alpha.HankoApplicationList {
	if in == nil {
		return nil
	}
	out := &alpha.HankoApplicationList{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoApplicationList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]alpha.HankoApplication, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].ToHub()
		}
	}
	return out
}

func ApplicationListFromHub(in *alpha.HankoApplicationList) *HankoApplicationList {
	if in == nil {
		return nil
	}
	out := &HankoApplicationList{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoApplicationList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]HankoApplication, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *ApplicationFromHub(&in.Items[i])
		}
	}
	return out
}

func (in *HankoRoleList) ToHub() *alpha.HankoRoleList {
	if in == nil {
		return nil
	}
	out := &alpha.HankoRoleList{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoRoleList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]alpha.HankoRole, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].ToHub()
		}
	}
	return out
}

func RoleListFromHub(in *alpha.HankoRoleList) *HankoRoleList {
	if in == nil {
		return nil
	}
	out := &HankoRoleList{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoRoleList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]HankoRole, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *RoleFromHub(&in.Items[i])
		}
	}
	return out
}

func (in *HankoResourceServerList) ToHub() *alpha.HankoResourceServerList {
	if in == nil {
		return nil
	}
	out := &alpha.HankoResourceServerList{TypeMeta: metav1.TypeMeta{APIVersion: alpha.GroupVersion.String(), Kind: "HankoResourceServerList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]alpha.HankoResourceServer, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].ToHub()
		}
	}
	return out
}

func ResourceServerListFromHub(in *alpha.HankoResourceServerList) *HankoResourceServerList {
	if in == nil {
		return nil
	}
	out := &HankoResourceServerList{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "HankoResourceServerList"}, ListMeta: *in.ListMeta.DeepCopy()}
	if in.Items != nil {
		out.Items = make([]HankoResourceServer, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *ResourceServerFromHub(&in.Items[i])
		}
	}
	return out
}
