/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.identity.UserModelIdentity;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;

final class NativeAuthority {
    private NativeAuthority() {}

    static Authority fromToken(AccessToken token) {
        Set<String> roles = token.getRealmAccess() == null || token.getRealmAccess().getRoles() == null
                ? Set.of() : token.getRealmAccess().getRoles();
        Map<String, Set<String>> clientRoles = new HashMap<>();
        token.getResourceAccess().forEach((key, value) -> {
            if (value.getRoles() != null) clientRoles.put(key, value.getRoles());
        });
        return new Authority(scopes(token.getScope()), roles, clientRoles,
                permissions(token.getAuthorization() == null ? List.of() : token.getAuthorization().getPermissions()));
    }

    static Authority current(KeycloakSession session, RealmModel realm, ClientModel target, ClientModel identityClient,
                             UserModel user, AccessToken token, Authority grant) {
        Authority claims = fromToken(token);
        Set<String> realmRoles = claims.realmRoles().stream().filter(name -> {
            RoleModel role = realm.getRole(name);
            return role != null && user.hasRole(role);
        }).collect(Collectors.toSet());
        Map<String, Set<String>> clientRoles = new HashMap<>();
        claims.clientRoles().forEach((clientID, names) -> {
            ClientModel client = session.clients().getClientByClientId(realm, clientID);
            if (client != null && client.isEnabled()) clientRoles.put(clientID, names.stream().filter(name -> {
                RoleModel role = client.getRole(name);
                return role != null && user.hasRole(role);
            }).collect(Collectors.toSet()));
        });
        AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
        ResourceServer server = authorization.getStoreFactory().getResourceServerStore().findByClient(target);
        if (server == null || server.getPolicyEnforcementMode() != PolicyEnforcementMode.ENFORCING) {
            throw new Bounds.Rejected("resource_server_unavailable");
        }
        List<ResourcePermission> requested = new ArrayList<>();
        grant.permissions().forEach((id, names) -> {
            Resource resource = authorization.getStoreFactory().getResourceStore().findById(server, id);
            if (resource == null || resource.isOwnerManagedAccess()) throw new Bounds.Rejected("resource_unavailable");
            var selected = resource.getScopes().stream().filter(scope -> names.contains(scope.getName())).toList();
            if (selected.size() != names.size()) throw new Bounds.Rejected("resource_scope_unavailable");
            requested.add(new ResourcePermission(resource, selected, server));
        });
        // Read current native memberships/composites, never a saved user or group list.
        // Each evaluation uses the original software client, not the HTTP requester's client.
        var evaluation = new DefaultEvaluationContext(new UserModelIdentity(realm, user),
                Map.of("kc.client.id", List.of(identityClient.getClientId())), session);
        var result = authorization.evaluators().from(requested, evaluation).evaluate(server, new AuthorizationRequest());
        return new Authority(claims.scopes(), realmRoles, clientRoles, permissions(result));
    }

    static void apply(AccessToken token, Authority authority) {
        token.setScope(String.join(" ", authority.scopes().stream().sorted().toList()));
        token.setRealmAccess(new AccessToken.Access().roles(authority.realmRoles()));
        Map<String, AccessToken.Access> clientRoles = new HashMap<>();
        authority.clientRoles().forEach((key, value) -> clientRoles.put(key, new AccessToken.Access().roles(value)));
        token.setResourceAccess(clientRoles);
        AccessToken.Authorization authorization = new AccessToken.Authorization();
        authorization.setPermissions(authority.permissions().entrySet().stream()
                .map(entry -> new Permission(entry.getKey(), entry.getValue())).toList());
        token.setAuthorization(authorization);
        token.setAuthorizationDetails(null);
        // Identity/profile and arbitrary mapper claims do not become delegated authorization.
        token.getOtherClaims().clear();
        token.setAllowedOrigins(null);
        token.setTrustedCertificates(null);
    }

    static Set<String> scopes(String scope) {
        if (scope == null || scope.isBlank()) return Set.of();
        if (scope.length() > 8192) throw new Bounds.Rejected("scope_limit");
        return Set.of(scope.strip().split(" +"));
    }

    private static Map<String, Set<String>> permissions(java.util.Collection<Permission> values) {
        Map<String, Set<String>> result = new HashMap<>();
        if (values == null) return result;
        if (values.size() > 256) throw new Bounds.Rejected("permission_limit");
        for (Permission permission : values) {
            if (permission.getResourceId() == null || permission.getScopes() == null || permission.getScopes().isEmpty()) continue;
            Set<String> merged = result.computeIfAbsent(permission.getResourceId(), ignored -> new HashSet<>());
            merged.addAll(permission.getScopes());
            if (merged.size() > 1024) throw new Bounds.Rejected("scope_limit");
        }
        return result;
    }
}
