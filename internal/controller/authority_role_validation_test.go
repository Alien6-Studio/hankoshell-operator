package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func TestValidateRealmAuthorityRolesAllowsOnlyCanonicalNonCompositeDefinitions(t *testing.T) {
	realm := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{Name: "alien6"},
		Spec: hankoshv1alpha1.HankoRealmSpec{Roles: []hankoshv1alpha1.RealmRole{
			{Name: "HANKO_PLATFORM"},
			{Name: "HANKO_FLEET_ADMIN"},
			{Name: "HANKO_FLEET_OPERATOR"},
			{Name: "HANKO_CLUSTER_ADMIN"},
			{Name: "HANKO_CLUSTER_OPERATOR"},
			{Name: "HANKO_REALM_ADMIN"},
		}},
	}
	if err := validateRealmAuthorityRoles(realm, "alien6"); err != nil {
		t.Fatalf("canonical authority role definitions rejected: %v", err)
	}
}

func TestValidateRealmAuthorityRolesRejectsDirectPrivilegePaths(t *testing.T) {
	tests := []struct {
		name  string
		realm *hankoshv1alpha1.HankoRealm
	}{
		{
			name: "authority role homonym outside authority realm",
			realm: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}, Spec: hankoshv1alpha1.HankoRealmSpec{
				Roles: []hankoshv1alpha1.RealmRole{{Name: "HANKO_FLEET_ADMIN"}},
			}},
		},
		{
			name: "future reserved prefix in authority realm",
			realm: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6"}, Spec: hankoshv1alpha1.HankoRealmSpec{
				Roles: []hankoshv1alpha1.RealmRole{{Name: "HANKO_FLEET_OWNER"}},
			}},
		},
		{
			name: "canonical authority role made composite",
			realm: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6"}, Spec: hankoshv1alpha1.HankoRealmSpec{
				Roles: []hankoshv1alpha1.RealmRole{{Name: "HANKO_CLUSTER_ADMIN", Composites: []string{"editor"}}},
			}},
		},
		{
			name: "ordinary wrapper inherits authority role",
			realm: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6"}, Spec: hankoshv1alpha1.HankoRealmSpec{
				Roles: []hankoshv1alpha1.RealmRole{{Name: "innocent", Composites: []string{"HANKO_PLATFORM"}}},
			}},
		},
		{
			name: "provider-native mapper config grants authority role",
			realm: &hankoshv1alpha1.HankoRealm{ObjectMeta: metav1.ObjectMeta{Name: "alien6"}, Spec: hankoshv1alpha1.HankoRealmSpec{
				IdentityProviders: []hankoshv1alpha1.RealmIdentityProvider{{
					Alias: "entra", ProviderID: "oidc", Mappers: []hankoshv1alpha1.RealmIdentityProviderMapper{{
						Name: "fleet", IdentityProviderMapper: "oidc-hardcoded-role-idp-mapper",
						Config: map[string]string{"role": "/HANKO_FLEET_ADMIN"},
					}},
				}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRealmAuthorityRoles(tt.realm, "alien6"); err == nil || !strings.Contains(err.Error(), "reserved authority role") {
				t.Fatalf("validation error = %v, want reserved authority role rejection", err)
			}
		})
	}
}

func TestValidateDirectAuthorityRoleGrantSurfaces(t *testing.T) {
	app := &hankoshv1alpha1.HankoApplication{Spec: hankoshv1alpha1.HankoApplicationSpec{
		RealmRef: "alien6", IdentityMappings: []hankoshv1alpha1.ApplicationIdentityMapping{{
			Name: "fleet", Target: hankoshv1alpha1.ApplicationIdentityMappingTarget{RealmRole: "HANKO_FLEET_ADMIN"},
		}},
	}}
	if err := validateApplicationAuthorityRoles(app, "alien6"); err == nil {
		t.Fatal("application identity mapping granted a Fleet role")
	}

	org := &hankoshv1alpha1.HankoOrganization{
		ObjectMeta: metav1.ObjectMeta{Name: "admins"},
		Spec:       hankoshv1alpha1.HankoOrganizationSpec{RealmRef: "alien6", Roles: []string{"HANKO_CLUSTER_ADMIN"}},
	}
	if err := validateOrganizationAuthorityRoles(org, "alien6"); err == nil {
		t.Fatal("organization assigned a Cluster role")
	}

	role := &hankoshv1alpha1.HankoRole{
		ObjectMeta: metav1.ObjectMeta{Name: "wrapper"},
		Spec:       hankoshv1alpha1.HankoRoleSpec{RealmRef: "alien6", Name: "wrapper", Composites: []string{"HANKO_PLATFORM"}},
	}
	if err := validateStandaloneAuthorityRole(role, "alien6"); err == nil {
		t.Fatal("HankoRole inherited a platform authority role")
	}
}
