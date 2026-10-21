package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

var errReservedAuthorityRole = errors.New("reserved authority role")

var canonicalAuthorityRoles = map[string]struct{}{
	"HANKO_PLATFORM":         {},
	"HANKO_FLEET_ADMIN":      {},
	"HANKO_FLEET_OPERATOR":   {},
	"HANKO_CLUSTER_ADMIN":    {},
	"HANKO_CLUSTER_OPERATOR": {},
}

// isReservedAuthorityRole reserves every current and future Fleet/Cluster
// role name, plus the global platform administrator. Keeping this prefix based
// prevents a direct CR from minting a lookalike that a newer API version might
// later interpret as authoritative.
func isReservedAuthorityRole(role string) bool {
	role = strings.TrimSpace(role)
	return role == "HANKO_PLATFORM" || strings.HasPrefix(role, "HANKO_PLATFORM_") ||
		strings.HasPrefix(role, "HANKO_FLEET_") || strings.HasPrefix(role, "HANKO_CLUSTER_")
}

func validateApplicationAuthorityRoles(app *hankoshv1alpha1.HankoApplication, protectedRealm string) error {
	for _, mapping := range app.Spec.IdentityMappings {
		if isReservedAuthorityRole(mapping.Target.RealmRole) {
			return reservedAuthorityRoleError(protectedRealm, app.Spec.RealmRef,
				fmt.Sprintf("identity mapping %q", mapping.Name), mapping.Target.RealmRole)
		}
	}
	return nil
}

type authorityRoleReference struct {
	clientID          string
	role              string
	allowReservedRoot bool
	allowMissing      bool
}

func realmAuthorityRoleReference(role string) authorityRoleReference {
	return authorityRoleReference{role: strings.TrimSpace(role)}
}

func clientAuthorityRoleReference(clientID, role string) authorityRoleReference {
	return authorityRoleReference{clientID: strings.TrimSpace(clientID), role: strings.TrimSpace(role)}
}

// validateEffectiveAuthorityRoleReferences expands every referenced role from
// Keycloak. Literal validation is insufficient because an innocently named,
// pre-existing realm or client role may transitively contain a reserved role.
// Any lookup failure aborts reconciliation before a provider mutation.
func validateEffectiveAuthorityRoleReferences(ctx context.Context, kc *keycloak.Client, protectedRealm, targetRealm, surface string, references []authorityRoleReference) error {
	if strings.TrimSpace(protectedRealm) == "" || strings.TrimSpace(targetRealm) != strings.TrimSpace(protectedRealm) {
		return nil
	}
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if reference.role == "" {
			continue
		}
		key := reference.clientID + "\x00" + reference.role
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}

		var (
			closure []keycloak.RealmRole
			err     error
		)
		if reference.clientID == "" {
			closure, err = kc.GetRealmRoleClosure(ctx, targetRealm, reference.role)
		} else {
			closure, err = kc.GetClientRoleClosure(ctx, targetRealm, reference.clientID, reference.role)
		}
		if err != nil && reference.allowMissing && keycloak.IsNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("verify effective role %q for %s: %w", reference.role, surface, err)
		}
		if reference.allowReservedRoot && len(closure) != 1 {
			return fmt.Errorf("%w: %s references reserved authority role %q with provider composites; reserved roles must be non-composite", errReservedAuthorityRole, surface, reference.role)
		}
		for index, role := range closure {
			if !isReservedAuthorityRole(role.Name) || (index == 0 && reference.allowReservedRoot) {
				continue
			}
			return reservedAuthorityRoleError(protectedRealm, targetRealm, surface, role.Name)
		}
	}
	return nil
}

func validateApplicationEffectiveAuthorityRoles(ctx context.Context, app *hankoshv1alpha1.HankoApplication, protectedRealm string, protectedClientIDs []string, kc *keycloak.Client) error {
	if strings.TrimSpace(app.Spec.RealmRef) != strings.TrimSpace(protectedRealm) || strings.TrimSpace(protectedRealm) == "" {
		return nil
	}
	references := make([]authorityRoleReference, 0, len(app.Spec.IdentityMappings)+len(app.Spec.RealmRoleScopes)+len(app.Spec.Roles))
	declaredClientRoles := make(map[string]struct{}, len(app.Spec.Roles))
	for _, role := range app.Spec.Roles {
		declaredClientRoles[role.Name] = struct{}{}
	}
	for _, mapping := range app.Spec.IdentityMappings {
		if mapping.Target.RealmRole != "" {
			references = append(references, realmAuthorityRoleReference(mapping.Target.RealmRole))
		}
		if mapping.Target.ClientRole != "" {
			if _, declared := declaredClientRoles[mapping.Target.ClientRole]; !declared {
				return fmt.Errorf("identity mapping %q targets undeclared client role %q", mapping.Name, mapping.Target.ClientRole)
			}
		}
	}

	protectedClient := isProtectedControlPlaneClient(protectedRealm, protectedClientIDs, app.Spec.RealmRef, app.Spec.ClientID)
	for _, role := range app.Spec.RealmRoleScopes {
		reference := realmAuthorityRoleReference(role)
		if isReservedAuthorityRole(reference.role) {
			if !protectedClient {
				return reservedAuthorityRoleError(protectedRealm, app.Spec.RealmRef,
					fmt.Sprintf("application %q realm-role scope", app.Name), reference.role)
			}
			reference.allowReservedRoot = true
		}
		references = append(references, reference)
	}
	if err := validateEffectiveAuthorityRoleReferences(ctx, kc, protectedRealm, app.Spec.RealmRef,
		fmt.Sprintf("HankoApplication %q", app.Name), references); err != nil {
		return err
	}

	needsClientRoleLookup := len(app.Spec.Roles) != 0
	for _, mapping := range app.Spec.IdentityMappings {
		needsClientRoleLookup = needsClientRoleLookup || mapping.Target.ClientRole != ""
	}
	if !needsClientRoleLookup {
		return nil
	}
	exists, err := kc.ClientExists(ctx, app.Spec.RealmRef, app.Spec.ClientID)
	if err != nil {
		return fmt.Errorf("verify client-role authority for application %q: %w", app.Name, err)
	}
	if !exists {
		return nil
	}
	clientReferences := make([]authorityRoleReference, 0, len(app.Spec.Roles))
	for _, role := range app.Spec.Roles {
		reference := clientAuthorityRoleReference(app.Spec.ClientID, role.Name)
		reference.allowMissing = true
		clientReferences = append(clientReferences, reference)
	}
	return validateEffectiveAuthorityRoleReferences(ctx, kc, protectedRealm, app.Spec.RealmRef,
		fmt.Sprintf("HankoApplication %q client role", app.Name), clientReferences)
}

func validateOrganizationEffectiveAuthorityRoles(ctx context.Context, org *hankoshv1alpha1.HankoOrganization, protectedRealm string, kc *keycloak.Client) error {
	references := make([]authorityRoleReference, 0, len(org.Spec.Roles)+len(org.Spec.ClientRoles))
	for _, role := range org.Spec.Roles {
		references = append(references, realmAuthorityRoleReference(role))
	}
	for _, clientRoles := range org.Spec.ClientRoles {
		for _, role := range clientRoles.Roles {
			references = append(references, clientAuthorityRoleReference(clientRoles.Client, role))
		}
	}
	return validateEffectiveAuthorityRoleReferences(ctx, kc, protectedRealm, org.Spec.RealmRef,
		fmt.Sprintf("HankoOrganization %q", org.Name), references)
}

func validateRealmEffectiveAuthorityRoles(ctx context.Context, realm *hankoshv1alpha1.HankoRealm, protectedRealm string, kc *keycloak.Client) error {
	if strings.TrimSpace(realm.Name) != strings.TrimSpace(protectedRealm) || strings.TrimSpace(protectedRealm) == "" {
		return nil
	}
	declared := make(map[string]struct{}, len(realm.Spec.Roles))
	for _, role := range realm.Spec.Roles {
		declared[role.Name] = struct{}{}
		closure, err := kc.GetRealmRoleClosure(ctx, realm.Name, role.Name)
		if err != nil {
			if keycloak.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("verify existing realm role %q: %w", role.Name, err)
		}
		if isReservedAuthorityRole(role.Name) && len(closure) != 1 {
			return fmt.Errorf("%w: reserved authority role %q in fleet authority realm %q has provider composites and must be non-composite", errReservedAuthorityRole, role.Name, realm.Name)
		}
		for index, effective := range closure {
			if index > 0 && isReservedAuthorityRole(effective.Name) {
				return reservedAuthorityRoleError(protectedRealm, realm.Name,
					fmt.Sprintf("existing HankoRealm role %q composite", role.Name), effective.Name)
			}
		}
	}

	references := make([]authorityRoleReference, 0)
	for _, role := range realm.Spec.Roles {
		for _, composite := range role.Composites {
			if _, inManifest := declared[composite]; !inManifest {
				references = append(references, realmAuthorityRoleReference(composite))
			}
		}
	}
	for _, provider := range realm.Spec.IdentityProviders {
		for _, mapper := range provider.Mappers {
			for _, reference := range authorityRoleReferencesFromMapper(mapper.IdentityProviderMapper, mapper.Config) {
				if reference.clientID == "" {
					if _, inManifest := declared[reference.role]; inManifest {
						continue
					}
				}
				references = append(references, reference)
			}
		}
	}
	return validateEffectiveAuthorityRoleReferences(ctx, kc, protectedRealm, realm.Name,
		fmt.Sprintf("HankoRealm %q", realm.Name), references)
}

func authorityRoleReferencesFromMapper(_ string, config map[string]string) []authorityRoleReference {
	value := ""
	for key, candidate := range config {
		if strings.EqualFold(strings.TrimSpace(key), "role") {
			value = strings.TrimSpace(strings.TrimPrefix(candidate, "/"))
			break
		}
	}
	if value == "" {
		return nil
	}
	if clientID, role, found := strings.Cut(value, "."); found && clientID != "" && role != "" {
		return []authorityRoleReference{clientAuthorityRoleReference(clientID, role)}
	}
	return []authorityRoleReference{realmAuthorityRoleReference(value)}
}

func isReservedAuthorityRoleViolation(err error) bool {
	return errors.Is(err, errReservedAuthorityRole)
}

func validateOrganizationAuthorityRoles(org *hankoshv1alpha1.HankoOrganization, protectedRealm string) error {
	for _, role := range org.Spec.Roles {
		if isReservedAuthorityRole(role) {
			return reservedAuthorityRoleError(protectedRealm, org.Spec.RealmRef,
				fmt.Sprintf("organization %q", org.Name), role)
		}
	}
	return nil
}

func validateStandaloneAuthorityRole(role *hankoshv1alpha1.HankoRole, protectedRealm string) error {
	if isReservedAuthorityRole(role.Spec.Name) {
		return reservedAuthorityRoleError(protectedRealm, role.Spec.RealmRef,
			fmt.Sprintf("HankoRole %q", role.Name), role.Spec.Name)
	}
	for _, composite := range role.Spec.Composites {
		if isReservedAuthorityRole(composite) {
			return reservedAuthorityRoleError(protectedRealm, role.Spec.RealmRef,
				fmt.Sprintf("HankoRole %q composite", role.Name), composite)
		}
	}
	return nil
}

func validateRealmAuthorityRoles(realm *hankoshv1alpha1.HankoRealm, protectedRealm string) error {
	protectedRealm = strings.TrimSpace(protectedRealm)
	for _, role := range realm.Spec.Roles {
		roleName := strings.TrimSpace(role.Name)
		if isReservedAuthorityRole(roleName) {
			_, canonical := canonicalAuthorityRoles[roleName]
			if protectedRealm == "" || realm.Name != protectedRealm || !canonical {
				return reservedAuthorityRoleError(protectedRealm, realm.Name,
					fmt.Sprintf("HankoRealm %q role definition", realm.Name), roleName)
			}
			if len(role.Composites) != 0 {
				return fmt.Errorf("%w: reserved authority role %q in fleet authority realm %q must be non-composite", errReservedAuthorityRole, roleName, realm.Name)
			}
		}
		for _, composite := range role.Composites {
			if isReservedAuthorityRole(composite) {
				return reservedAuthorityRoleError(protectedRealm, realm.Name,
					fmt.Sprintf("HankoRealm %q composite role %q", realm.Name, role.Name), composite)
			}
		}
	}

	for _, provider := range realm.Spec.IdentityProviders {
		for _, mapper := range provider.Mappers {
			if strings.TrimSpace(realm.Name) == strings.TrimSpace(protectedRealm) && authorityMapperMayAssignGroup(mapper.IdentityProviderMapper, mapper.Config) {
				return fmt.Errorf("%w: identity-provider group mapper %q is forbidden in fleet authority realm %q because group role inheritance cannot be bounded safely", errReservedAuthorityRole, mapper.Name, realm.Name)
			}
			for key, value := range mapper.Config {
				if reference, found := reservedAuthorityRoleReference(key); found {
					return reservedAuthorityRoleError(protectedRealm, realm.Name,
						fmt.Sprintf("identity-provider mapper %q config key", mapper.Name), reference)
				}
				if reference, found := reservedAuthorityRoleReference(value); found {
					return reservedAuthorityRoleError(protectedRealm, realm.Name,
						fmt.Sprintf("identity-provider mapper %q config value", mapper.Name), reference)
				}
			}
		}
	}
	return nil
}

func authorityMapperMayAssignGroup(implementation string, config map[string]string) bool {
	if strings.Contains(strings.ToLower(strings.TrimSpace(implementation)), "group") {
		return true
	}
	for key := range config {
		var normalized strings.Builder
		for _, char := range strings.ToLower(strings.TrimSpace(key)) {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
				normalized.WriteRune(char)
			}
		}
		if strings.HasPrefix(normalized.String(), "group") {
			return true
		}
	}
	return false
}

func reservedAuthorityRoleReference(value string) (string, bool) {
	for _, marker := range []string{"HANKO_PLATFORM", "HANKO_FLEET_", "HANKO_CLUSTER_"} {
		if strings.Contains(value, marker) {
			return marker, true
		}
	}
	return "", false
}

func reservedAuthorityRoleError(protectedRealm, targetRealm, surface, role string) error {
	protectedRealm = strings.TrimSpace(protectedRealm)
	if protectedRealm == "" {
		return fmt.Errorf("%w: %s references reserved authority role %q while HANKO_FLEET_AUTHORITY_REALM is unset", errReservedAuthorityRole, surface, strings.TrimSpace(role))
	}
	if targetRealm != protectedRealm {
		return fmt.Errorf("%w: %s cannot define or grant reserved authority role %q outside fleet authority realm %q", errReservedAuthorityRole, surface, strings.TrimSpace(role), protectedRealm)
	}
	return fmt.Errorf("%w: %s cannot grant or compose reserved authority role %q; bootstrap assignments require the primary Keycloak administrative service account", errReservedAuthorityRole, surface, strings.TrimSpace(role))
}
